package executor

import (
	"bytes"
	"context"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// DockerAPI forwards the Engine socket over the verified SSH connection; it never exposes TCP 2375.
func (s *SSH) DockerAPI(ctx context.Context, h domain.Host, method, path string, body []byte, registryAuth string) ([]byte, error) {
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\r\n") {
		return nil, fmt.Errorf("invalid Engine path")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	select {
	case s.Slots <- struct{}{}:
		defer func() { <-s.Slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	conn, e := s.connect(ctx, h)
	if e != nil {
		return nil, e
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	transport := &http.Transport{DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return conn.client.DialContext(c, "unix", "/var/run/docker.sock")
	}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	req, e := http.NewRequestWithContext(ctx, method, "http://docker"+path, bytes.NewReader(body))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Content-Type", "application/json")
	if registryAuth != "" {
		req.Header.Set("X-Registry-Auth", registryAuth)
	}
	res, e := (&http.Client{Transport: transport}).Do(req)
	if e != nil {
		return nil, e
	}
	defer res.Body.Close()
	b, e := io.ReadAll(io.LimitReader(res.Body, 4*1024*1024+1))
	if e != nil {
		return nil, e
	}
	if len(b) > 4*1024*1024 {
		return nil, fmt.Errorf("Engine response exceeded 4 MiB; verify pull state before retry")
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("Docker Engine HTTP %d: %s", res.StatusCode, string(b))
	}
	return b, nil
}
