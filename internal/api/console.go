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
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	consoleSession = 30 * time.Minute
	consoleKeep    = 25 * time.Second
	consolePing    = 10 * time.Second
	consoleInput   = 8192
)

// consoleWriter streams shell output to the browser as binary frames. Terminal output
// is never sanitized: escape sequences are what makes it a terminal, and the client
// renders them in an emulator rather than as HTML.
type consoleWriter struct {
	ctx  context.Context
	conn *websocket.Conn
}

func (c *consoleWriter) Write(p []byte) (int, error) {
	if e := c.conn.Write(c.ctx, websocket.MessageBinary, p); e != nil {
		return 0, e
	}
	return len(p), nil
}

// console attaches an interactive shell to a container over the host's SSH connection.
// Unlike every other route this one is a long-lived socket, so all authorization runs
// before the upgrade; afterwards failures can only be reported by closing the socket.
func (s *Server) console(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rs, h, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, rbac.Permission(rs.Provider, "exec"), h.Environment); e != nil {
		return e
	}
	cmd, e := adapters.ConsoleCommand(rs, r.URL.Query().Get("shell"))
	if e != nil {
		return bad(e.Error())
	}
	// A WebSocket handshake is a GET, so it carries the session cookie without the CSRF
	// header the mutating routes require. Origin is the defense against another site
	// opening a shell with the user's cookie, and it is mandatory here.
	if r.Header.Get("Origin") != s.Config.Origin {
		return deny("origin validation failed")
	}
	ok, e := s.DB.RateLimit(r.Context(), "console:"+p.User.ID, 20, time.Hour)
	if e != nil {
		return e
	}
	if !ok {
		return HTTPError{429, "console session limit reached"}
	}
	rows, _ := strconv.Atoi(r.URL.Query().Get("rows"))
	cols, _ := strconv.Atoi(r.URL.Query().Get("cols"))
	// The origin check above is stricter than the library's Host comparison, which would
	// reject the proxied origin, so its own verification is skipped deliberately.
	conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		return nil
	}
	defer conn.CloseNow()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Time{})
	_ = rc.SetWriteDeadline(time.Time{})
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	_ = s.DB.Audit(ctx, domain.Event{Actor: p.User.ID, ActorType: "user", SourceIP: auth.IP(r), HostID: h.ID, ResourceID: rs.ID, Environment: h.Environment, Action: "resource.console", Decision: "allow", Metadata: map[string]any{"provider": rs.Provider, "shell": cmd.Args[len(cmd.Args)-1], "container": cmd.Args[len(cmd.Args)-2]}})
	stdin, writer := io.Pipe()
	resize := make(chan [2]int, 4)
	go s.consoleRead(ctx, conn, writer, resize)
	go func() {
		t := time.NewTicker(consoleKeep)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				ping, stop := context.WithTimeout(ctx, consolePing)
				e := conn.Ping(ping)
				stop()
				if e != nil {
					return
				}
			}
		}
	}()
	started := time.Now()
	e = s.SSH.Shell(ctx, h, cmd, executor.Terminal{Rows: rows, Cols: cols, Stdin: stdin, Stdout: &consoleWriter{ctx, conn}, Resize: resize, MaxDuration: consoleSession})
	_ = writer.Close()
	result := "closed"
	if e != nil {
		result = security.Redact(e.Error())
		slog.Info("console session ended", "resource", rs.ID, "actor", p.User.ID, "error", e)
	}
	_ = s.DB.Audit(context.WithoutCancel(ctx), domain.Event{Actor: p.User.ID, ActorType: "user", HostID: h.ID, ResourceID: rs.ID, Environment: h.Environment, SourceIP: auth.IP(r), Action: "resource.console_ended", Decision: "allow", Result: result, Metadata: map[string]any{"seconds": int(time.Since(started).Seconds())}})
	_ = conn.Close(websocket.StatusNormalClosure, "session ended")
	return nil
}

// consoleRead forwards keystrokes to the shell. Binary frames are raw input; text
// frames carry the resize control message and nothing else.
func (s *Server) consoleRead(ctx context.Context, conn *websocket.Conn, stdin *io.PipeWriter, resize chan<- [2]int) {
	defer stdin.Close()
	conn.SetReadLimit(consoleInput)
	for {
		typ, data, e := conn.Read(ctx)
		if e != nil {
			return
		}
		if typ == websocket.MessageBinary {
			if _, e = stdin.Write(data); e != nil {
				return
			}
			continue
		}
		var in struct {
			Rows int `json:"rows"`
			Cols int `json:"cols"`
		}
		if json.Unmarshal(data, &in) == nil && in.Rows > 0 && in.Cols > 0 {
			select {
			case resize <- [2]int{in.Rows, in.Cols}:
			default:
			}
		}
	}
}
