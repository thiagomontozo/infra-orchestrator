package api

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/executor"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/policy"
	"github.com/thiagomontozo/infra-orchestrator/internal/provisioning"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func validEnv(s string) bool {
	return domain.Contains([]string{"development", "testing", "homologation", "staging", "production"}, s)
}

type hostInput struct {
	ID                   string   `json:"id"`
	Name                 string   `json:"name"`
	Description          string   `json:"description"`
	Hostname             string   `json:"hostname"`
	Port                 int      `json:"port"`
	Username             string   `json:"username"`
	AuthMethod           string   `json:"auth_method"`
	Credential           string   `json:"credential"`
	Fingerprint          string   `json:"fingerprint"`
	FingerprintConfirmed bool     `json:"fingerprint_confirmed"`
	Environment          string   `json:"environment"`
	Groups               []string `json:"groups"`
	Tags                 []string `json:"tags"`
	Enabled              bool     `json:"enabled"`
	BastionID            string   `json:"bastion_id"`
}

func (s *Server) hosts(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	all, e := s.DB.Hosts(r.Context())
	if e != nil {
		return e
	}
	out := []domain.Host{}
	for _, h := range all {
		if rbac.Allowed(p, "host.read", h.Environment) {
			out = append(out, h)
		}
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) saveHost(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	permission := "host.create"
	if r.PathValue("id") != "" {
		permission = "host.update"
	}
	if e := require(p, permission, ""); e != nil {
		return e
	}
	var in hostInput
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if len(in.Name) < 1 || len(in.Name) > 128 || len(in.Description) > 2000 || in.Port < 1 || in.Port > 65535 || !regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,253}$`).MatchString(in.Hostname) || !executor.ValidRef(in.Username) || !validEnv(in.Environment) {
		return bad("invalid host fields")
	}
	if !domain.Contains([]string{"key", "agent", "password"}, in.AuthMethod) {
		return bad("invalid SSH authentication method")
	}
	if !regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(in.Fingerprint) || !in.FingerprintConfirmed {
		return bad("verify the SHA256 fingerprint using a trusted channel and explicitly confirm it")
	}
	id := r.PathValue("id")
	secretID := ""
	if id != "" {
		old, e := s.DB.Host(r.Context(), id)
		if e != nil {
			return e
		}
		secretID = old.SecretID
		if e = require(p, permission, old.Environment); e != nil {
			return e
		}
	} else {
		id = domain.ID()
	}
	if in.BastionID != "" {
		b, e := s.DB.Host(r.Context(), in.BastionID)
		if e != nil {
			return bad("bastion not found")
		}
		if b.ID == id || b.BastionID != "" || !b.Enabled {
			return bad("bastion must be enabled and cannot itself use a bastion")
		}
	}
	if in.Credential != "" {
		if len(in.Credential) > 65536 {
			return bad("credential too large")
		}
		secretID = domain.ID()
		if e := s.Secrets.Put(r.Context(), secretID, []byte(in.Credential)); e != nil {
			return e
		}
	}
	if in.AuthMethod != "agent" && secretID == "" {
		return bad("SSH credential required")
	}
	h := domain.Host{ID: id, Name: in.Name, Description: in.Description, Hostname: in.Hostname, Port: in.Port, Username: in.Username, AuthMethod: in.AuthMethod, SecretID: secretID, Fingerprint: in.Fingerprint, Environment: in.Environment, Groups: in.Groups, Tags: in.Tags, Enabled: in.Enabled, BastionID: in.BastionID, State: "unknown", Facts: map[string]any{}}
	if e := s.DB.SaveHost(r.Context(), h); e != nil {
		return e
	}
	if e := s.record(r, p, "host.saved", h.Environment, map[string]any{"host_id": id, "fingerprint": h.Fingerprint}); e != nil {
		return e
	}
	jsonResponse(w, 200, h)
	return nil
}
func (s *Server) deleteHost(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	h, e := s.DB.Host(r.Context(), r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "host.delete", h.Environment); e != nil {
		return e
	}
	h.Enabled = false
	h.State = "disabled"
	if e = s.DB.SaveHost(r.Context(), h); e != nil {
		return e
	}
	if e = s.record(r, p, "host.disabled", h.Environment, map[string]any{"host_id": h.ID}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) probeHost(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := require(p, "host.create", ""); e != nil {
		return e
	}
	var in struct {
		Hostname string `json:"hostname"`
		Port     int    `json:"port"`
		Username string `json:"username"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if in.Port < 1 || in.Port > 65535 {
		return bad("invalid port")
	}
	fingerprint, e := s.SSH.Probe(r.Context(), domain.Host{Hostname: in.Hostname, Port: in.Port, Username: in.Username})
	if e != nil {
		return bad("SSH fingerprint probe failed: " + e.Error())
	}
	jsonResponse(w, 200, map[string]any{"fingerprint": fingerprint, "verified": false, "instruction": "Compare this fingerprint through a trusted channel before confirming."})
	return nil
}
func (s *Server) testHost(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	h, e := s.DB.Host(r.Context(), r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "host.update", h.Environment); e != nil {
		return e
	}
	out, e := s.SSH.Run(r.Context(), h, executor.Command{Program: "hostname", Args: []string{"-f"}})
	if e != nil {
		return bad("SSH connection failed: " + e.Error())
	}
	if e = s.record(r, p, "ssh.test", h.Environment, map[string]any{"host_id": h.ID}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]any{"ok": true, "hostname": security.Redact(out.Output)})
	return nil
}
func (s *Server) discoverHost(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	h, e := s.DB.Host(r.Context(), r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "host.update", h.Environment); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	facts, e := s.Discovery.Discover(ctx, h)
	if e != nil {
		return bad("discovery failed: " + e.Error())
	}
	if runtimes, ok := facts["runtimes"].([]string); ok && domain.Contains(runtimes, "docker") {
		rs, e := s.Engine.Adapters["provisioning"].Discover(ctx, h)
		if e != nil {
			return e
		}
		if e = s.DB.UpsertResources(ctx, h.ID, "provisioning", rs); e != nil {
			return e
		}
	}
	jsonResponse(w, 200, facts)
	return nil
}
func (s *Server) visibleResource(ctx context.Context, p domain.Principal, id string) (domain.Resource, domain.Host, error) {
	rs, e := s.DB.Resource(ctx, id)
	if e != nil {
		return rs, domain.Host{}, e
	}
	h, e := s.DB.Host(ctx, rs.HostID)
	if e != nil {
		return rs, h, e
	}
	if e = require(p, "resource.read", h.Environment); e != nil {
		return rs, h, e
	}
	rs.Environment = h.Environment
	return rs, h, nil
}
func (s *Server) filterCapabilities(p domain.Principal, r domain.Resource) domain.Resource {
	caps := []string{}
	if a, ok := s.Engine.Adapters[r.Provider]; ok && r.State != "missing" {
		for _, c := range a.Capabilities(r) {
			if rbac.Allowed(p, rbac.Permission(r.Provider, c), r.Environment) {
				caps = append(caps, c)
			}
		}
	}
	r.Capabilities = caps
	r.Metadata = sanitizedMap(r.Metadata)
	r.Labels = redactedLabels(r.Labels)
	return r
}
func sanitizedMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return security.SanitizeValue(m).(map[string]any)
}
func redactedLabels(m map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		if strings.Contains(strings.ToLower(k), "secret") || strings.Contains(strings.ToLower(k), "password") || strings.Contains(strings.ToLower(k), "token") {
			out[k] = "[REDACTED]"
		} else {
			out[k] = security.Redact(v)
		}
	}
	return out
}
func (s *Server) resources(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	all, e := s.DB.Resources(r.Context())
	if e != nil {
		return e
	}
	hosts, e := s.DB.Hosts(r.Context())
	if e != nil {
		return e
	}
	hm := map[string]domain.Host{}
	for _, h := range hosts {
		hm[h.ID] = h
	}
	out := []domain.Resource{}
	for _, rs := range all {
		h, ok := hm[rs.HostID]
		if !ok || !rbac.Allowed(p, "resource.read", h.Environment) {
			continue
		}
		if host := r.URL.Query().Get("host_id"); host != "" && host != rs.HostID {
			continue
		}
		if provider := r.URL.Query().Get("provider"); provider != "" && provider != rs.Provider {
			continue
		}
		rs.Environment = h.Environment
		out = append(out, s.filterCapabilities(p, rs))
	}
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) resource(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rs, _, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	jsonResponse(w, 200, s.filterCapabilities(p, rs))
	return nil
}
func (s *Server) readResource(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rs, h, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	action := r.URL.Query().Get("action")
	if !policy.ReadOnly(action) {
		return bad("read-only action required")
	}
	if _, e = s.Engine.Authorize(r.Context(), p, rs, h, operations.Request{Action: action}); e != nil {
		return e
	}
	out, e := s.Engine.Adapters[rs.Provider].Execute(r.Context(), h, rs, domain.Operation{Action: action})
	if e != nil {
		return bad("adapter read failed: " + e.Error())
	}
	out.Output = security.SanitizeText(out.Output)
	jsonResponse(w, 200, out)
	return nil
}
func (s *Server) logs(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rs, h, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	if _, e = s.Engine.Authorize(r.Context(), p, rs, h, operations.Request{Action: "logs"}); e != nil {
		return e
	}
	tail := 200
	if str := r.URL.Query().Get("tail"); str != "" {
		tail, e = strconv.Atoi(str)
		if e != nil || tail < 1 || tail > 2000 {
			return bad("tail must be 1..2000")
		}
	}
	req := adapters.LogRequest{Host: h, Resource: rs, Tail: tail, Since: r.URL.Query().Get("since")}
	out, e := s.Engine.Adapters[rs.Provider].Logs(r.Context(), req)
	if e != nil {
		return bad("logs failed: " + e.Error())
	}
	if e = s.record(r, p, "resource.logs", h.Environment, map[string]any{"resource_id": rs.ID, "tail": tail}); e != nil {
		return e
	}
	if r.URL.Query().Get("download") == "true" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=resource.log")
		_, _ = w.Write([]byte(out.Output))
		return nil
	}
	jsonResponse(w, 200, map[string]any{"output": out.Output, "truncated": out.Truncated})
	return nil
}
func (s *Server) listOperations(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	ops, e := s.Engine.List(r.Context())
	if e != nil {
		return e
	}
	out := []domain.Operation{}
	for _, op := range ops {
		if rbac.Allowed(p, "operation.read", op.Environment) {
			op.Parameters = sanitizedOperationParams(op.Parameters)
			out = append(out, op)
		}
	}
	jsonResponse(w, 200, out)
	return nil
}
func sanitizedOperationParams(p map[string]any) map[string]any {
	copy := map[string]any{}
	for k, v := range p {
		if k == "manifest" || k == "spec_secret_id" {
			copy[k] = "[STORED SECURELY]"
		} else {
			copy[k] = v
		}
	}
	return sanitizedMap(copy)
}
func (s *Server) submitOperation(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var req operations.Request
	if e := decode(w, r, &req); e != nil {
		return e
	}
	if req.Parameters["spec_secret_id"] != nil {
		return bad("use provisioning endpoint")
	}
	if req.Action == "deploy" || req.Action == "run" {
		return bad("use deployments endpoint")
	}
	req.IdempotencyKey = r.Header.Get("Idempotency-Key")
	req.RequestID = domain.ID()
	op, e := s.Engine.Submit(r.Context(), p, req)
	if e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 202, op)
	return nil
}
func badOrDenied(e error) error {
	if operations.IsDenied(e) {
		return e
	}
	return bad(e.Error())
}
func (s *Server) getOperation(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	op, e := s.Engine.Get(r.Context(), r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "operation.read", op.Environment); e != nil {
		return e
	}
	op.Parameters = sanitizedOperationParams(op.Parameters)
	jsonResponse(w, 200, op)
	return nil
}
func (s *Server) approveOperation(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		Approve bool   `json:"approve"`
		Reason  string `json:"reason"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if e := s.Engine.Approve(r.Context(), p, r.PathValue("id"), in.Approve, in.Reason); e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) cancelOperation(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	if e := s.Engine.Cancel(r.Context(), p, r.PathValue("id")); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]bool{"ok": true})
	return nil
}
func (s *Server) batchOperation(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		ResourceIDs      []string       `json:"resource_ids"`
		Action           string         `json:"action"`
		Parameters       map[string]any `json:"parameters"`
		Reason           string         `json:"reason"`
		BatchSize        int            `json:"batch_size"`
		FailureThreshold int            `json:"failure_threshold"`
		ContinueOnError  bool           `json:"continue_on_error"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	if !domain.Contains([]string{"start", "stop", "restart", "reload", "scale"}, in.Action) {
		return bad("unsupported batch action")
	}
	req := operations.Request{Action: in.Action, Parameters: in.Parameters, Reason: in.Reason, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: domain.ID()}
	if req.IdempotencyKey == "" {
		return bad("Idempotency-Key required")
	}
	id, ops, e := s.Engine.Batch(r.Context(), p, req, in.ResourceIDs, in.BatchSize, in.FailureThreshold, in.ContinueOnError)
	if e != nil {
		return badOrDenied(e)
	}
	jsonResponse(w, 202, map[string]any{"id": id, "operations": ops})
	return nil
}
func (s *Server) reconcile(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	rs, h, e := s.visibleResource(r.Context(), p, r.PathValue("id"))
	if e != nil {
		return e
	}
	if e = require(p, "host.update", h.Environment); e != nil {
		return e
	}
	var in struct {
		Reason    string `json:"reason"`
		Confirmed bool   `json:"confirmed"`
	}
	if e = decode(w, r, &in); e != nil {
		return e
	}
	if !in.Confirmed || len(in.Reason) < 10 {
		return bad("confirm remote state was checked and provide reconciliation evidence")
	}
	tag, e := s.DB.Pool.Exec(r.Context(), "DELETE FROM resource_leases WHERE resource_id=$1 AND expires_at<now() AND NOT EXISTS(SELECT 1 FROM operations WHERE id=resource_leases.operation_id AND state='running')", rs.ID)
	if e != nil {
		return e
	}
	if e = s.record(r, p, "resource.reconciled", h.Environment, map[string]any{"resource_id": rs.ID, "reason": in.Reason, "released": tag.RowsAffected()}); e != nil {
		return e
	}
	jsonResponse(w, 200, map[string]any{"released": tag.RowsAffected()})
	return nil
}
func (s *Server) provisionContainer(w http.ResponseWriter, r *http.Request, p domain.Principal) error {
	var in struct {
		HostID string            `json:"host_id"`
		Reason string            `json:"reason"`
		Spec   provisioning.Spec `json:"spec"`
	}
	if e := decode(w, r, &in); e != nil {
		return e
	}
	h, e := s.DB.Host(r.Context(), in.HostID)
	if e != nil {
		return e
	}
	if e = require(p, "container.create", h.Environment); e != nil {
		return e
	}
	if e = provisioning.Validate(in.Spec); e != nil {
		return bad(e.Error())
	}
	if r.Header.Get("Idempotency-Key") == "" {
		return bad("Idempotency-Key required")
	}
	resourceID := security.HashToken(h.ID + "/provisioning/docker-engine")[:32]
	if _, e = s.DB.Resource(r.Context(), resourceID); e != nil {
		return bad("discover Docker on the host before creating containers")
	}
	specID := domain.ID()
	body, _ := json.Marshal(in.Spec)
	if e = s.Secrets.Put(r.Context(), specID, body); e != nil {
		return e
	}
	op, e := s.Engine.Submit(r.Context(), p, operations.Request{ResourceID: resourceID, Action: "create", Parameters: map[string]any{"spec_secret_id": specID, "spec_hash": security.HashToken(string(body)), "name": in.Spec.Name, "image": in.Spec.Image}, Reason: in.Reason, IdempotencyKey: r.Header.Get("Idempotency-Key"), RequestID: domain.ID()})
	if e != nil {
		_ = s.Secrets.Delete(r.Context(), specID)
		return badOrDenied(e)
	}
	op.Parameters = sanitizedOperationParams(op.Parameters)
	jsonResponse(w, 202, op)
	return nil
}

var _ = fmt.Sprint
