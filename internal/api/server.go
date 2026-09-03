package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/infra-orchestrator/internal/auth"
	"github.com/thiagomontozo/infra-orchestrator/internal/cache"
	"github.com/thiagomontozo/infra-orchestrator/internal/config"
	"github.com/thiagomontozo/infra-orchestrator/internal/discovery"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"go.opentelemetry.io/otel"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type Handler func(http.ResponseWriter, *http.Request, domain.Principal) error
type Server struct {
	Limiter   cache.Limiter
	Config    config.Config
	DB        *store.DB
	Auth      *auth.Service
	SSH       *executor.SSH
	Secrets   secrets.Provider
	Engine    *operations.Engine
	Discovery *discovery.Service
	Network   *security.NetworkPolicy
	Mux       *http.ServeMux
	Metrics   http.Handler
	AI        AIService
}
type AIService interface {
	Analyze(context.Context, domain.Principal, string, string, string) (domain.Object, error)
	TestProvider(context.Context, string) (any, error)
	Tool(context.Context, domain.Principal, string, string, string, string) (any, error)
}
type HTTPError struct {
	Status  int
	Message string
}

func (e HTTPError) Error() string { return e.Message }
func deny(msg string) error       { return HTTPError{403, msg} }
func bad(msg string) error        { return HTTPError{400, msg} }
func jsonResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		return bad("invalid JSON request: " + e.Error())
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return bad("only one JSON object allowed")
	}
	return nil
}
func require(p domain.Principal, permission, env string) error {
	if !rbac.Allowed(p, permission, env) {
		return deny("permission denied")
	}
	return nil
}
func (s *Server) route(pattern string, h Handler) {
	s.Mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, e := s.Auth.Authenticate(r)
		if e != nil {
			jsonResponse(w, 401, map[string]string{"error": "authentication or CSRF validation failed"})
			return
		}
		path := r.URL.Path
		if p.User.MFARequired && !p.MFA && !strings.HasPrefix(path, "/api/v1/auth/") {
			s.writeError(w, deny("MFA enrollment required"))
			return
		}
		if p.User.ForcePassword && !strings.HasPrefix(path, "/api/v1/auth/") {
			s.writeError(w, deny("password change required"))
			return
		}
		var ok bool
		if s.Limiter != nil {
			ok, e = s.Limiter.Allow(r.Context(), "api:"+p.User.ID, 600, time.Minute)
		} else {
			ok, e = s.DB.RateLimit(r.Context(), "api:"+p.User.ID, 600, time.Minute)
		}
		if e != nil {
			s.writeError(w, e)
			return
		}
		if !ok {
			s.writeError(w, HTTPError{429, "request limit reached"})
			return
		}
		if e = h(w, r, p); e != nil {
			s.writeError(w, e)
		}
	})
}
func (s *Server) writeError(w http.ResponseWriter, e error) {
	status, msg := 500, "request failed"
	var he HTTPError
	if errors.As(e, &he) {
		status, msg = he.Status, he.Message
	} else if operations.IsDenied(e) {
		status, msg = 403, e.Error()
	} else if errors.Is(e, pgx.ErrNoRows) {
		status, msg = 404, "not found"
	} else if errors.Is(e, context.DeadlineExceeded) {
		status, msg = 504, "request timed out"
	}
	if status == 500 {
		slog.Error("API request failed", "error", security.Redact(e.Error()))
	}
	jsonResponse(w, status, map[string]string{"error": msg})
}
func (s *Server) Handler() http.Handler {
	s.Mux = http.NewServeMux()
	s.Mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"status": "ok", "name": s.Config.Name})
	})
	s.Mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if e := s.DB.Pool.Ping(ctx); e != nil {
			jsonResponse(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		jsonResponse(w, 200, map[string]string{"status": "ready"})
	})
	if s.Metrics != nil {
		s.Mux.Handle("GET /metrics", s.Metrics)
	}
	s.Mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.Mux.HandleFunc("GET /api/v1/auth/config", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]any{"name": s.Config.Name, "oidc": s.Config.OIDCIssuer != "", "ldap": s.Config.LDAPURL != ""})
	})
	if s.Config.OIDCIssuer != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		o, e := auth.NewOIDC(ctx, s.Auth)
		cancel()
		if e == nil {
			s.Mux.HandleFunc("GET /api/v1/auth/oidc/start", o.Start)
			s.Mux.HandleFunc("GET /api/v1/auth/oidc/callback", o.Callback)
		} else {
			slog.Error("OIDC initialization failed", "error", e)
		}
	}
	s.route("GET /api/v1/auth/me", s.me)
	s.route("POST /api/v1/auth/logout", s.logout)
	s.route("POST /api/v1/auth/renew", s.renew)
	s.route("POST /api/v1/auth/password", s.password)
	s.route("POST /api/v1/auth/mfa/enroll", s.mfaEnroll)
	s.route("POST /api/v1/auth/mfa/verify", s.mfaVerify)
	s.route("GET /api/v1/users", s.users)
	s.route("POST /api/v1/users", s.createUser)
	s.route("PUT /api/v1/users/{id}", s.updateUser)
	s.route("DELETE /api/v1/users/{id}", s.deleteUser)
	s.route("POST /api/v1/users/{id}/reset-password", s.resetPassword)
	s.route("GET /api/v1/sessions", s.sessions)
	s.route("DELETE /api/v1/sessions/{id}", s.revokeSession)
	s.route("DELETE /api/v1/users/{id}/sessions", s.revokeUserSessions)
	s.route("GET /api/v1/roles", s.roles)
	s.route("GET /api/v1/tokens", s.tokens)
	s.route("POST /api/v1/tokens", s.createToken)
	s.route("DELETE /api/v1/tokens/{id}", s.revokeToken)
	s.route("GET /api/v1/hosts", s.hosts)
	s.route("POST /api/v1/kubernetes/clusters", s.createCluster)
	s.route("POST /api/v1/hosts", s.saveHost)
	s.route("PUT /api/v1/hosts/{id}", s.saveHost)
	s.route("DELETE /api/v1/hosts/{id}", s.deleteHost)
	s.route("POST /api/v1/hosts/probe", s.probeHost)
	s.route("POST /api/v1/hosts/{id}/test", s.testHost)
	s.route("POST /api/v1/hosts/{id}/discover", s.discoverHost)
	s.route("GET /api/v1/resources", s.resources)
	s.route("GET /api/v1/resources/{id}", s.resource)
	s.route("GET /api/v1/resources/{id}/logs", s.logs)
	s.route("GET /api/v1/resources/{id}/read", s.readResource)
	s.route("GET /api/v1/operations", s.listOperations)
	s.route("POST /api/v1/operations", s.submitOperation)
	s.route("GET /api/v1/operations/{id}", s.getOperation)
	s.route("POST /api/v1/operations/{id}/approve", s.approveOperation)
	s.route("POST /api/v1/operations/{id}/cancel", s.cancelOperation)
	s.route("POST /api/v1/operations/batch", s.batchOperation)
	s.route("POST /api/v1/resources/{id}/reconcile", s.reconcile)
	s.route("POST /api/v1/provisioning/containers", s.provisionContainer)
	s.route("GET /api/v1/dashboard", s.dashboard)
	s.route("GET /api/v1/events", s.events)
	s.route("GET /api/v1/audit", s.audit)
	s.route("GET /api/v1/{kind}", s.listObjects)
	s.route("POST /api/v1/{kind}", s.saveObject)
	s.route("PUT /api/v1/{kind}/{id}", s.saveObject)
	s.route("DELETE /api/v1/{kind}/{id}", s.deleteObject)
	s.route("GET /api/v1/llm/providers", s.providers)
	s.route("POST /api/v1/llm/providers", s.saveProvider)
	s.route("PUT /api/v1/llm/providers/{id}", s.saveProvider)
	s.route("POST /api/v1/llm/providers/{id}/test", s.testProvider)
	s.route("POST /api/v1/agents/analyze", s.analyze)
	s.route("POST /api/v1/agents/tools", s.agentTool)
	s.route("POST /api/v1/deployments/execute", s.deploy)
	s.route("POST /api/v1/deployments/{id}/rollback", s.rollback)
	s.route("POST /api/v1/gitops/{id}/diff", s.gitopsDiff)
	s.Mux.HandleFunc("GET /api/v1/openapi", func(w http.ResponseWriter, r *http.Request) { http.ServeFile(w, r, "docs/openapi.yaml") })
	s.Mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 404, map[string]string{"error": "not found"})
	})
	s.Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.Contains(path, "..") || strings.HasPrefix(path, "/.") {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(path, ".") {
			http.ServeFile(w, r, "web/dist"+path)
		} else {
			http.ServeFile(w, r, "web/dist/index.html")
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		id := domain.ID()
		w.Header().Set("X-Request-ID", id)
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if s.Config.SecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		ctx, span := otel.Tracer("api").Start(r.Context(), r.Method+" "+routeClass(r.URL.Path))
		defer span.End()
		defer func() {
			if v := recover(); v != nil {
				slog.Error("request panic", "request_id", id)
				jsonResponse(w, 500, map[string]string{"error": "internal error"})
			}
			slog.Info("request", "method", r.Method, "path", r.URL.Path, "request_id", id, "duration_ms", time.Since(start).Milliseconds())
		}()
		s.Mux.ServeHTTP(w, r.WithContext(ctx))
	})
}
func routeClass(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) > 4 {
		return strings.Join(parts[:4], "/") + "/{id}"
	}
	return path
}
func (s *Server) record(r *http.Request, p domain.Principal, action, env string, metadata map[string]any) error {
	return s.DB.Audit(r.Context(), domain.Event{Actor: p.User.ID, SourceIP: auth.IP(r), RequestID: r.Header.Get("X-Request-ID"), Action: action, Environment: env, Decision: "allow", Metadata: metadata})
}

var _ = fmt.Sprint
