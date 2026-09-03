package api

import (
	"encoding/json"
	"github.com/robfig/cron/v3"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/policy"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type objectAccess struct{ Read, Write string }

var objectKinds = map[string]objectAccess{"host-groups": {"host.read", "hostgroup.manage"}, "environments": {"host.read", "hostgroup.manage"}, "policies": {"host.read", "policy.manage"}, "maintenance-windows": {"operation.read", "policy.manage"}, "schedules": {"operation.read", "schedule.manage"}, "deployments": {"deployment.read", "deployment.execute"}, "alerts": {"alert.read", "incident.manage"}, "incidents": {"incident.read", "incident.manage"}, "providers": {"llm.use", "llm.manage"}, "agents": {"llm.use", "llm.manage"}, "recommendations": {"llm.use", "llm.manage"}, "registries": {"resource.read", "registry.manage"}, "notifications": {"alert.read", "notification.manage"}, "gitops": {"deployment.read", "deployment.execute"}, "settings": {"host.read", "settings.manage"}, "monitoring": {"llm.use", "llm.manage"}}

func publicObject(o domain.Object) domain.Object {
	copy := map[string]any{}
	for k, v := range o.Data {
		if strings.HasSuffix(k, "secret_id") || k == "api_key" || k == "password" || k == "credential" {
			continue
		}
		copy[k] = v
	}
	o.Data = sanitizedMap(copy)
	return o
}
func (s *Server) listObjects(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	kind := r.PathValue("kind")
	access, ok := objectKinds[kind]
	if !ok {
		return HTTPError{404, "unknown collection"}
	}
	if kind == "environments" {
		out := []map[string]string{}
		for _, env := range []string{"development", "testing", "homologation", "staging", "production"} {
			if rbac.Allowed(p, "host.read", env) {
				out = append(out, map[string]string{"id": env, "name": env})
			}
		}
		jsonResponse(w, 200, out)
		return nil
	}
	all, e := s.DB.Objects(r.Context(), kind)
	if e != nil {
		return e
	}
	out := []domain.Object{}
	for _, o := range all {
		if rbac.Allowed(p, access.Read, o.Environment) {
			out = append(out, publicObject(o))
		}
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) validateObject(r *http.Request, p domain.Principal, o *domain.Object) error {
	if o.Name == "" || len(o.Name) > 128 {
		return bad("name must contain 1..128 characters")
	}
	if o.Environment != "" && !validEnv(o.Environment) {
		return bad("invalid environment")
	}
	if o.Data == nil {
		o.Data = map[string]any{}
	}
	switch o.Kind {
	case "policies":
		b, _ := json.Marshal(o.Data)
		var rule policy.Rule
		if e := json.Unmarshal(b, &rule); e != nil {
			return bad(e.Error())
		}
		if e := policy.Validate(rule); e != nil {
			return bad(e.Error())
		}
	case "maintenance-windows":
		b, _ := json.Marshal(o.Data)
		var window policy.Window
		if e := json.Unmarshal(b, &window); e != nil {
			return bad(e.Error())
		}
		if e := policy.Validate(policy.Rule{Window: &window}); e != nil {
			return bad(e.Error())
		}
	case "schedules":
		action := domain.String(o.Data, "action")
		if !domain.Contains([]string{"start", "stop", "restart", "reload", "scale"}, action) {
			return bad("schedule action is not allowed")
		}
		res, h, e := s.visibleResource(r.Context(), p, domain.String(o.Data, "resource_id"))
		if e != nil {
			return e
		}
		params, _ := o.Data["parameters"].(map[string]any)
		if _, e = s.Engine.Authorize(r.Context(), p, res, h, operations.Request{Action: action, Parameters: params}); e != nil {
			return e
		}
		o.Environment = h.Environment
		o.Data["requester"] = p.User.ID
		o.Data["auth_mfa"] = p.MFA
		if expr := domain.String(o.Data, "cron"); expr != "" {
			zone := domain.String(o.Data, "timezone")
			if _, e = time.LoadLocation(zone); e != nil {
				return bad("valid IANA timezone required")
			}
			if _, e = cron.ParseStandard("CRON_TZ=" + zone + " " + expr); e != nil {
				return bad("invalid cron expression")
			}
		} else {
			at, e := time.Parse(time.RFC3339, domain.String(o.Data, "at"))
			if e != nil || !at.After(time.Now()) {
				return bad("future RFC3339 execution time required")
			}
		}
	case "incidents":
		if !domain.Contains([]string{"open", "investigating", "mitigated", "resolved", "closed"}, domain.String(o.Data, "status")) {
			return bad("invalid incident status")
		}
		if !domain.Contains([]string{"critical", "high", "medium", "low"}, domain.String(o.Data, "severity")) {
			return bad("invalid severity")
		}
		o.Data["updated_by"] = p.User.ID
	case "providers":
		raw := domain.String(o.Data, "base_url")
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		if e := s.Network.ValidateURL(raw); e != nil {
			return bad(e.Error())
		}
		o.Data["base_url"] = strings.TrimRight(raw, "/")
		if domain.String(o.Data, "model") == "" {
			return bad("model is required")
		}
		if domain.Number(o.Data, "max_context") == 0 {
			o.Data["max_context"] = 8192.0
		}
		if domain.Number(o.Data, "timeout") == 0 {
			o.Data["timeout"] = 60.0
		}
	case "registries":
		server := domain.String(o.Data, "server")
		u, e := url.Parse("https://" + server)
		if e != nil || u.Hostname() == "" || u.Path != "" || u.User != nil {
			return bad("registry must be a host[:port]")
		}
	case "agents", "monitoring":
		if !domain.Contains([]string{"DISABLED", "ADVISORY", "ASSISTED", "AUTOMATED_POLICY_CONTROLLED"}, domain.String(o.Data, "mode")) {
			return bad("invalid agent mode")
		}
		interval := domain.Number(o.Data, "interval")
		if interval < 60 || interval > 86400 {
			return bad("agent interval must be 60..86400 seconds")
		}
		if domain.String(o.Data, "mode") == "AUTOMATED_POLICY_CONTROLLED" {
			u, e := s.DB.User(r.Context(), domain.String(o.Data, "service_account_id"))
			if e != nil || !u.Service {
				return bad("automation requires a service account")
			}
		}
	case "notifications":
		typ := domain.String(o.Data, "type")
		if !domain.Contains([]string{"webhook", "slack", "teams", "email"}, typ) {
			return bad("invalid notification type")
		}
		if typ != "email" {
			if e := s.Network.ValidateURL(domain.String(o.Data, "url")); e != nil {
				return bad(e.Error())
			}
		}
	case "gitops":
		raw := domain.String(o.Data, "manifest_url")
		if e := s.Network.ValidateURL(raw); e != nil {
			return bad(e.Error())
		}
		if !strings.HasPrefix(raw, "https://") {
			return bad("GitOps requires HTTPS manifest URL")
		}
		if domain.String(o.Data, "resource_id") == "" {
			return bad("target resource required")
		}
	case "deployments", "recommendations", "alerts":
		return bad("this collection is created through its operational workflow")
	}
	return nil
}
func (s *Server) saveObject(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	kind := r.PathValue("kind")
	access, ok := objectKinds[kind]
	if !ok {
		return HTTPError{404, "unknown collection"}
	}
	var in struct {
		Name        string         `json:"name"`
		Environment string         `json:"environment"`
		Data        map[string]any `json:"data"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := require(p, access.Write, in.Environment); e != nil {
		return e
	}
	id := r.PathValue("id")
	var old domain.Object
	if id != "" {
		var e error
		old, e = s.DB.Object(r.Context(), kind, id)
		if e != nil {
			return e
		}
		if e = require(p, access.Write, old.Environment); e != nil {
			return e
		}
	} else {
		id = domain.ID()
	}
	o := domain.Object{ID: id, Kind: kind, Name: in.Name, Environment: in.Environment, Data: in.Data}
	if e := s.validateObject(r, p, &o); e != nil {
		return e
	}
	for k := range o.Data {
		if strings.HasSuffix(k, "secret_id") {
			delete(o.Data, k)
		}
	}
	secretInput := ""
	for _, k := range []string{"api_key", "password", "credential"} {
		if v := domain.String(o.Data, k); v != "" {
			secretInput = v
		}
		delete(o.Data, k)
	}
	if secretInput != "" {
		sid := domain.ID()
		if e := s.Secrets.Put(r.Context(), sid, []byte(secretInput)); e != nil {
			return e
		}
		o.Data["secret_id"] = sid
	} else if old.Data != nil {
		o.Data["secret_id"] = old.Data["secret_id"]
	}
	if e := s.DB.SaveObject(r.Context(), o); e != nil {
		return e
	}
	if e := s.record(r, p, kind+".saved", o.Environment, map[string]any{"id": o.ID, "name": o.Name}); e != nil {
		return e
	}
	jsonResponse(w, 200, publicObject(o))
	return nil
}
func (s *Server) deleteObject(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	kind := r.PathValue("kind")
	access, ok := objectKinds[kind]
	if !ok {
		return HTTPError{404, "unknown collection"}
	}
	o, e := s.DB.Object(r.Context(), kind, r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, access.Write, o.Environment); e != nil {
		return e
	}
	if _, e = s.DB.Pool.Exec(r.Context(), "DELETE FROM objects WHERE id=$1 AND kind=$2", o.ID, kind); e != nil {
		return e
	}
	if sid := domain.String(o.Data, "secret_id"); sid != "" {
		_ = s.Secrets.Delete(r.Context(), sid)
	}
	if e = s.record(r, p, kind+".deleted", o.Environment, map[string]any{"id": o.ID}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) providers(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	r.SetPathValue("kind", "providers")
	return s.listObjects(w, r, p)
}
func (s *Server) saveProvider(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	r.SetPathValue("kind", "providers")
	return s.saveObject(w, r, p)
}
func (s *Server) testProvider(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "llm.manage", ""); e != nil {
		return e
	}
	if s.AI == nil {
		return HTTPError{503, "AI not configured"}
	}
	v, e := s.AI.TestProvider(r.Context(), r.PathValue("id"))
	if e != nil {
		return bad(e.Error())
	}
	jsonResponse(w, 200, v)
	return nil
}
func (s *Server) analyze(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		ResourceID string `json:"resource_id"`
		ProviderID string `json:"provider_id"`
		Question   string `json:"question"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if s.AI == nil {
		return HTTPError{503, "AI not configured"}
	}
	out, e := s.AI.Analyze(r.Context(), p, in.ResourceID, in.ProviderID, in.Question)
	if e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 200, publicObject(out))
	return nil
}
func (s *Server) agentTool(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		Tool             string `json:"tool"`
		ResourceID       string `json:"resource_id"`
		Reason           string `json:"reason"`
		RecommendationID string `json:"recommendation_id"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if s.AI == nil {
		return HTTPError{503, "AI not configured"}
	}
	out, e := s.AI.Tool(r.Context(), p, in.Tool, in.ResourceID, in.Reason, in.RecommendationID)
	if e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 202, out)
	return nil
}
