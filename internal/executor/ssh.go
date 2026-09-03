package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Command struct {
	Program string
	Args    []string
	Stdin   []byte
}
type Result struct {
	Output    string
	Truncated bool
}
type Executor interface {
	Run(context.Context, domain.Host, Command) (Result, error)
}

var programs = map[string]bool{"docker": true, "podman": true, "docker-compose": true, "podman-compose": true, "systemctl": true, "journalctl": true, "kubectl": true, "nomad": true, "supervisorctl": true, "pm2": true, "uname": true, "hostname": true, "cat": true, "df": true, "uptime": true, "ip": true, "getconf": true, "free": true}

func Quote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func (c Command) Render() (string, error) {
	if !programs[c.Program] {
		return "", fmt.Errorf("executable not allowed")
	}
	parts := []string{c.Program}
	for _, a := range c.Args {
		if strings.ContainsRune(a, 0) || len(a) > 8192 {
			return "", fmt.Errorf("invalid argument")
		}
		parts = append(parts, Quote(a))
	}
	return strings.Join(parts, " "), nil
}

var validRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:@/+-]{0,255}$`)

func ValidRef(s string) bool { return validRef.MatchString(s) && !strings.Contains(s, "..") }

type SSH struct {
	Inventory                      store.Inventory
	Secrets                        secrets.Provider
	Network                        *security.NetworkPolicy
	KnownHosts                     string
	ConnectTimeout, CommandTimeout time.Duration
	Slots                          chan struct{}
}
type connection struct {
	client  *ssh.Client
	closers []io.Closer
}

func (c *connection) Close() {
	if c.client != nil {
		c.client.Close()
	}
	for _, v := range c.closers {
		v.Close()
	}
}
func (s *SSH) config(ctx context.Context, h domain.Host) (*ssh.ClientConfig, []io.Closer, error) {
	var closers []io.Closer
	var methods []ssh.AuthMethod
	switch h.AuthMethod {
	case "key":
		b, e := s.Secrets.Get(ctx, h.SecretID)
		if e != nil {
			return nil, nil, e
		}
		signer, e := ssh.ParsePrivateKey(b)
		if e != nil {
			return nil, nil, fmt.Errorf("invalid SSH private key")
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(signer)}
	case "password":
		b, e := s.Secrets.Get(ctx, h.SecretID)
		if e != nil {
			return nil, nil, e
		}
		methods = []ssh.AuthMethod{ssh.Password(string(b))}
	case "agent":
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, nil, fmt.Errorf("SSH_AUTH_SOCK required")
		}
		c, e := net.DialTimeout("unix", sock, s.ConnectTimeout)
		if e != nil {
			return nil, nil, e
		}
		closers = append(closers, c)
		signers, e := agent.NewClient(c).Signers()
		if e != nil {
			c.Close()
			return nil, nil, e
		}
		methods = []ssh.AuthMethod{ssh.PublicKeys(signers...)}
	default:
		return nil, nil, fmt.Errorf("invalid SSH authentication method")
	}
	var callback ssh.HostKeyCallback
	if h.Fingerprint != "" {
		callback = func(_ string, _ net.Addr, k ssh.PublicKey) error {
			if ssh.FingerprintSHA256(k) != h.Fingerprint {
				return fmt.Errorf("SSH host fingerprint mismatch")
			}
			return nil
		}
	} else if s.KnownHosts != "" {
		var e error
		callback, e = knownhosts.New(s.KnownHosts)
		if e != nil {
			return nil, closers, e
		}
	} else {
		return nil, closers, fmt.Errorf("verified fingerprint or known_hosts required")
	}
	return &ssh.ClientConfig{User: h.Username, Auth: methods, HostKeyCallback: callback, Timeout: s.ConnectTimeout}, closers, nil
}
func (s *SSH) connect(ctx context.Context, h domain.Host) (*connection, error) {
	cfg, closers, e := s.config(ctx, h)
	c := &connection{closers: closers}
	if e != nil {
		c.Close()
		return nil, e
	}
	address := net.JoinHostPort(h.Hostname, fmt.Sprint(h.Port))
	var raw net.Conn
	if h.BastionID != "" {
		b, e := s.Inventory.Host(ctx, h.BastionID)
		if e != nil {
			c.Close()
			return nil, e
		}
		if !b.Enabled || b.BastionID != "" || b.ID == h.ID {
			c.Close()
			return nil, fmt.Errorf("invalid bastion configuration")
		}
		jump, e := s.connect(ctx, b)
		if e != nil {
			c.Close()
			return nil, e
		}
		c.closers = append(c.closers, jump)
		ips, e := s.Network.Resolve(ctx, h.Hostname)
		if e != nil {
			c.Close()
			return nil, e
		}
		raw, e = jump.client.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), fmt.Sprint(h.Port)))
		if e != nil {
			c.Close()
			return nil, e
		}
	} else {
		raw, e = s.Network.DialContext(ctx, "tcp", address)
		if e != nil {
			c.Close()
			return nil, e
		}
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(s.ConnectTimeout))
	sc, ch, req, e := ssh.NewClientConn(raw, address, cfg)
	if e != nil {
		raw.Close()
		c.Close()
		return nil, e
	}
	_ = raw.SetDeadline(time.Time{})
	c.client = ssh.NewClient(sc, ch, req)
	return c, nil
}

type capped struct {
	mu        sync.Mutex
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	remaining := c.limit - c.b.Len()
	if n > remaining {
		p = p[:remaining]
		c.truncated = true
	}
	c.b.Write(p)
	return n, nil
}
func (s *SSH) Run(ctx context.Context, h domain.Host, cmd Command) (Result, error) {
	ctx, span := otel.Tracer("executor").Start(ctx, "ssh.execute")
	defer span.End()
	var out Result
	command, e := cmd.Render()
	if e != nil {
		return out, e
	}
	if !h.Enabled {
		return out, fmt.Errorf("host disabled")
	}
	ctx, cancel := context.WithTimeout(ctx, s.CommandTimeout)
	defer cancel()
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	case <-ctx.Done():
		return out, ctx.Err()
	}
	conn, e := s.connect(ctx, h)
	if e != nil {
		return out, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, conn.Close)
	defer stop()
	session, e := conn.client.NewSession()
	if e != nil {
		return out, e
	}
	defer session.Close()
	buf := &capped{limit: 1024 * 1024}
	session.Stdout = buf
	session.Stderr = buf
	if len(cmd.Stdin) > 0 {
		session.Stdin = bytes.NewReader(cmd.Stdin)
	}
	e = session.Run(command)
	out = Result{Output: buf.b.String(), Truncated: buf.truncated}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, e
}
func (s *SSH) Probe(ctx context.Context, h domain.Host) (string, error) {
	if h.BastionID != "" {
		return "", fmt.Errorf("for private hosts obtain fingerprint through a trusted channel and register it before testing")
	}
	ctx, cancel := context.WithTimeout(ctx, s.ConnectTimeout)
	defer cancel()
	raw, e := s.Network.DialContext(ctx, "tcp", net.JoinHostPort(h.Hostname, fmt.Sprint(h.Port)))
	if e != nil {
		return "", e
	}
	defer raw.Close()
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	_ = raw.SetDeadline(time.Now().Add(s.ConnectTimeout))
	fingerprint := ""
	sentinel := errors.New("fingerprint captured; authentication intentionally aborted")
	cfg := &ssh.ClientConfig{User: h.Username, HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		fingerprint = ssh.FingerprintSHA256(k)
		return sentinel
	}, Timeout: s.ConnectTimeout}
	_, _, _, e = ssh.NewClientConn(raw, net.JoinHostPort(h.Hostname, fmt.Sprint(h.Port)), cfg)
	if fingerprint != "" {
		return fingerprint, nil
	}
	return "", e
}
