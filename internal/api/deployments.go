package api

import (
	"encoding/json"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"io"
	"net/http"
	"strings"
)

func (s *Server) deploy(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		ResourceID string `json:"resource_id"`
		Version    string `json:"version"`
		Artifact   string `json:"artifact"`
		Commit     string `json:"commit"`
		Manifest   string `json:"manifest"`
		Reason     string `json:"reason"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	rs, h, e := s.visibleResource(r.Context(), p, in.ResourceID)
	if e != nil {
		return e
	}
	if e = require(p, "deployment.execute", h.Environment); e != nil {
		return e
	}
	action := ""
	switch rs.Provider {
	case "kubernetes", "kubernetes-api":
		action = "deploy"
	case "nomad":
		action = "run"
	case "dockercompose", "podmancompose":
		action = "up"
	case "swarm":
		if rs.Type != "docker_swarm_stack" {
			return bad("select an existing Swarm stack for deployment")
		}
		action = "deploy"
	default:
		return bad("resource does not support deployment")
	}
	params := map[string]any{"version": in.Version, "artifact": in.Artifact, "commit": in.Commit}
	if rs.Provider == "kubernetes" || rs.Provider == "kubernetes-api" || rs.Provider == "nomad" || rs.Provider == "swarm" {
		provider := rs.Provider
		if provider == "kubernetes-api" {
			provider = "kubernetes"
		}
		if e = adapters.ValidateManifest(provider, rs, in.Manifest); e != nil {
			return bad(e.Error())
		}
		sid := domain.ID()
		if e = s.Secrets.Put(r.Context(), sid, []byte(in.Manifest)); e != nil {
			return e
		}
		params["manifest_secret_id"] = sid
		params["manifest_hash"] = security.HashToken(in.Manifest)
	}
	op, e := s.Engine.Submit(r.Context(), p, operations.Request{ResourceID: rs.ID, Action: action, Parameters: params, Reason: in.Reason, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: domain.ID()})
	if e != nil {
		return badOrDenied(e)
	}
	id := "deployment-" + op.ID
	o := domain.Object{ID: id, Kind: "deployments", Name: rs.Name + " @ " + in.Version, Environment: h.Environment, Data: map[string]any{"resource_id": rs.ID, "operation_id": op.ID, "version": in.Version, "artifact": in.Artifact, "commit": in.Commit, "operator": p.User.ID, "status": op.State, "rollback_supported": domain.Contains(s.Engine.Adapters[rs.Provider].Capabilities(rs), "rollback")}}
	if e = s.DB.SaveObject(r.Context(), o); e != nil {
		return e
	}
	jsonResponse(w, 202, publicObject(o))
	return nil
}
func (s *Server) rollback(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	dep, e := s.DB.Object(r.Context(), "deployments", r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "deployment.rollback", dep.Environment); e != nil {
		return e
	}
	var in struct {
		Reason   string `json:"reason"`
		Revision int    `json:"revision"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	rs, h, e := s.visibleResource(r.Context(), p, domain.String(dep.Data, "resource_id"))
	if e != nil {
		return e
	}
	if !domain.Contains(s.Engine.Adapters[rs.Provider].Capabilities(rs), "rollback") {
		return bad("this adapter has no verified rollback mechanism")
	}
	if rs.Provider != "kubernetes-api" {
		history, err := s.Engine.Adapters[rs.Provider].Execute(r.Context(), h, rs, domain.Operation{Action: "rollout_history"})
		if err != nil || strings.TrimSpace(history.Output) == "" {
			return bad("rollback history unavailable")
		}
	}
	op, e := s.Engine.Submit(r.Context(), p, operations.Request{ResourceID: rs.ID, Action: "rollback", Parameters: map[string]any{"revision": float64(in.Revision)}, Reason: in.Reason, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: domain.ID()})
	if e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 202, op)
	return nil
}
func (s *Server) gitopsDiff(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	o, e := s.DB.Object(r.Context(), "gitops", r.PathValue("id"))
	if e != nil {
		return e
	}
	rs, h, e := s.visibleResource(r.Context(), p, domain.String(o.Data, "resource_id"))
	if e != nil {
		return e
	}
	if e = require(p, "deployment.read", h.Environment); e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(r.Context(), "GET", domain.String(o.Data, "manifest_url"), nil)
	if e != nil {
		return bad("invalid manifest URL")
	}
	if sid := domain.String(o.Data, "secret_id"); sid != "" {
		secret, e := s.Secrets.Get(r.Context(), sid)
		if e != nil {
			return e
		}
		req.Header.Set("Authorization", "Bearer "+string(secret))
	}
	res, e := s.Network.Client(30e9).Do(req)
	if e != nil {
		return bad(e.Error())
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return bad("repository manifest retrieval failed")
	}
	body, e := io.ReadAll(io.LimitReader(res.Body, 256*1024+1))
	if e != nil || len(body) > 256*1024 {
		return bad("manifest exceeds 256 KiB")
	}
	if e = adapters.ValidateManifest(rs.Provider, rs, string(body)); e != nil {
		return bad(e.Error())
	}
	var manifest map[string]any
	if e = json.Unmarshal(body, &manifest); e != nil {
		return bad("JSON manifest required")
	} // The reviewed desired state can be submitted through deployments; no auto-apply.
	jsonResponse(w, 200, map[string]any{"resource_id": rs.ID, "desired": sanitizedMap(manifest), "observed": sanitizedMap(rs.Metadata), "desired_sha256": security.HashToken(string(body)), "execution_requires_deployment": true, "comparison": "desired manifest versus last collected metadata; not a server-side apply diff"})
	return s.record(r, p, "gitops.diff", h.Environment, map[string]any{"gitops_id": o.ID, "sha256": security.HashToken(string(body))})
}
