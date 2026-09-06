package api

import (
	"context"
	"encoding/json"
	"github.com/coder/websocket"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/auth"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"io"
	"net/http"
	"strconv"
	"time"
)

const (
	consoleSessionBudget = 20
	consoleMaxDuration   = 30 * time.Minute
	consolePingInterval  = 25 * time.Second
	consoleReadLimit     = 64 * 1024
)

// consoleWriter forwards terminal output as binary frames. Output is not passed
// through security.Redact: escape sequences are what makes the terminal work,
// and rewriting them would corrupt the screen.
type consoleWriter struct {
	ctx  context.Context
	conn *websocket.Conn
}

func (c *consoleWriter) Write(p []byte) (int, error) {
	ctx, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	defer cancel()
	if e := c.conn.Write(ctx, websocket.MessageBinary, p); e != nil {
		return 0, e
	}
	return len(p), nil
}

func consoleDimension(raw string) int {
	v, e := strconv.Atoi(raw)
	if e != nil {
		return 0
	}
	return v
}

// console opens an interactive shell inside a container over a WebSocket.
//
// Protocol: binary frames carry keystrokes inbound and terminal output back;
// text frames carry only {"rows":n,"cols":n}.
func (s *Server) console(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	// A WebSocket handshake is a GET, and Authenticate validates neither CSRF nor
	// Origin on GET, so the handshake arrives with the session cookie and no
	// X-CSRF-Token. Comparing Origin with PUBLIC_ORIGIN here is the only defence
	// against another site opening a shell with the user's cookie. Removing it
	// reintroduces cross-site WebSocket hijacking. It runs first so a cross-site
	// caller cannot probe which resource ids exist.
	if r.Header.Get("Origin") != s.Config.Origin {
		return HTTPError{401, "origin validation failed"}
	}
	rs, h, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, rbac.Permission(rs.Provider, "exec"), h.Environment); e != nil {
		return e
	}
	cmd, target, e := adapters.ConsoleCommand(rs, r.URL.Query().Get("shell"))
	if e != nil {
		return bad(e.Error())
	}
	ok, e := s.DB.RateLimit(r.Context(), "console:"+p.User.ID, consoleSessionBudget, time.Hour)
	if e != nil {
		return e
	}
	if !ok {
		return HTTPError{429, "console session budget reached"}
	}
	if e = s.record(r, p, "resource.console", h.Environment, map[string]any{"resource_id": rs.ID, "host_id": h.ID, "container": target.Container, "shell": target.Shell}); e != nil {
		return e
	}
	// Every check above has to stay above: once the response is hijacked the only
	// thing this handler can still do is close the socket.
	//
	// The library's own origin check compares against the Host header and would
	// reject the origin that arrives through the proxy, so it is skipped in favour
	// of the explicit comparison already made above.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil
	}
	defer conn.CloseNow()
	conn.SetReadLimit(consoleReadLimit)
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), consoleMaxDuration)
	defer cancel()
	stdin, keys := io.Pipe()
	resize := make(chan [2]int, 4)
	go func() {
		defer close(resize)
		defer keys.Close()
		for {
			kind, data, e := conn.Read(ctx)
			if e != nil {
				return
			}
			if kind == websocket.MessageBinary {
				if _, e = keys.Write(data); e != nil {
					return
				}
				continue
			}
			var size struct {
				Rows int `json:"rows"`
				Cols int `json:"cols"`
			}
			if json.Unmarshal(data, &size) != nil {
				continue
			}
			select {
			case resize <- [2]int{size.Rows, size.Cols}:
			default:
			}
		}
	}()
	// An idle session is still a live session; ping so the proxy does not drop it.
	go func() {
		t := time.NewTicker(consolePingInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ping, stop := context.WithTimeout(ctx, 10*time.Second)
				e := conn.Ping(ping)
				stop()
				if e != nil {
					return
				}
			}
		}
	}()
	term := executor.Terminal{
		Stdin:       stdin,
		Stdout:      &consoleWriter{ctx: ctx, conn: conn},
		Rows:        consoleDimension(r.URL.Query().Get("rows")),
		Cols:        consoleDimension(r.URL.Query().Get("cols")),
		Resize:      resize,
		MaxDuration: consoleMaxDuration,
	}
	reason := "session ended"
	if e = s.SSH.Shell(ctx, h, cmd, term); e != nil {
		reason = e.Error()
	}
	// The session itself is not recorded: keystrokes never reach the audit trail.
	_ = s.DB.Audit(context.WithoutCancel(r.Context()), domain.Event{
		Actor: p.User.ID, ActorType: "user", SourceIP: auth.IP(r), Action: "resource.console_ended",
		ResourceID: rs.ID, Environment: h.Environment, Decision: "allow",
		Metadata: map[string]any{"resource_id": rs.ID, "container": target.Container, "duration_seconds": int(time.Since(started).Seconds()), "reason": security.Redact(reason)},
	})
	conn.Close(websocket.StatusNormalClosure, "session ended")
	return nil
}
