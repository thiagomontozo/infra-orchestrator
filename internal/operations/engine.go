package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/policy"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"strings"
	"time"
)

type Engine struct {
	DB       *store.DB
	Adapters adapters.Registry
	Secrets  secrets.Provider
}

func (e *Engine) Parameters(ctx context.Context, params map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range params {
		if k != "manifest_secret_id" && k != "manifest_hash" {
			out[k] = v
		}
	}
	if sid := domain.String(params, "manifest_secret_id"); sid != "" {
		if e.Secrets == nil {
			return nil, fmt.Errorf("secret provider unavailable")
		}
		b, err := e.Secrets.Get(ctx, sid)
		if err != nil {
			return nil, err
		}
		if security.HashToken(string(b)) != domain.String(params, "manifest_hash") {
			return nil, fmt.Errorf("manifest integrity mismatch")
		}
		out["manifest"] = string(b)
	}
	return out, nil
}

type Request struct {
	ResourceID     string         `json:"resource_id"`
	Action         string         `json:"action"`
	Parameters     map[string]any `json:"parameters"`
	Reason         string         `json:"reason"`
	IdempotencyKey string         `json:"-"`
	RequestID      string         `json:"-"`
	Agent          bool           `json:"-"`
	AgentMode      string         `json:"-"`
	BatchID        string         `json:"-"`
	BatchIndex     int            `json:"-"`
}
type Denied struct{ Reason string }

func (e Denied) Error() string { return e.Reason }
func (e *Engine) Rules(ctx context.Context) ([]policy.Rule, error) {
	objects, err := e.DB.Objects(ctx, "policies")
	if err != nil {
		return nil, err
	}
	rules := []policy.Rule{}
	for _, o := range objects {
		b, _ := json.Marshal(o.Data)
		var r policy.Rule
		if err = json.Unmarshal(b, &r); err != nil {
			return nil, err
		}
		r.ID = o.ID
		if o.Environment != "" {
			r.Environment = o.Environment
		}
		rules = append(rules, r)
	}
	return rules, nil
}
func (e *Engine) Authorize(ctx context.Context, p domain.Principal, r domain.Resource, h domain.Host, req Request) (policy.Decision, error) {
	if r.State == "missing" {
		return policy.Decision{}, Denied{"resource is no longer present; run discovery"}
	}
	rules, err := e.Rules(ctx)
	if err != nil {
		return policy.Decision{}, err
	}
	a, ok := e.Adapters[r.Provider]
	if !ok {
		return policy.Decision{}, fmt.Errorf("adapter unavailable")
	}
	if !domain.Contains(a.Capabilities(r), req.Action) {
		return policy.Decision{}, Denied{"unsupported action"}
	}
	if cli, ok := a.(*adapters.CLI); ok {
		params, resolveErr := e.Parameters(ctx, req.Parameters)
		if resolveErr != nil {
			return policy.Decision{}, resolveErr
		}
		if _, err = cli.Build(r, req.Action, params); err != nil {
			return policy.Decision{}, Denied{err.Error()}
		}
	}
	d := policy.Evaluate(policy.Input{Principal: p, Resource: r, Host: h, Action: req.Action, Agent: req.Agent, Mode: req.AgentMode, Now: time.Now()}, rules)
	if !d.Allowed {
		return d, Denied{d.Reason}
	}
	return d, nil
}
func (e *Engine) Submit(ctx context.Context, p domain.Principal, req Request) (domain.Operation, error) {
	var op domain.Operation
	if req.IdempotencyKey == "" || len(req.IdempotencyKey) > 128 {
		return op, fmt.Errorf("Idempotency-Key required (1..128 characters)")
	}
	if len(req.Reason) < 3 || len(req.Reason) > 2000 {
		return op, fmt.Errorf("reason must contain 3..2000 characters")
	}
	if policy.ReadOnly(req.Action) {
		return op, fmt.Errorf("use resource read endpoint for read actions")
	}
	r, err := e.DB.Resource(ctx, req.ResourceID)
	if err != nil {
		return op, err
	}
	h, err := e.DB.Host(ctx, r.HostID)
	if err != nil {
		return op, err
	}
	d, err := e.Authorize(ctx, p, r, h, req)
	if err != nil {
		_ = e.DB.Audit(ctx, domain.Event{Actor: p.User.ID, ResourceID: r.ID, HostID: h.ID, Environment: h.Environment, Action: "policy.denied", Decision: "deny", Result: err.Error()})
		return op, err
	}
	if req.Parameters == nil {
		req.Parameters = map[string]any{}
	}
	hashParams := map[string]any{}
	for k, v := range req.Parameters {
		if k != "spec_secret_id" && k != "manifest_secret_id" {
			hashParams[k] = v
		}
	}
	body, _ := json.Marshal(struct {
		R, A  string
		P     map[string]any
		Agent bool
		Mode  string
	}{req.ResourceID, req.Action, hashParams, req.Agent, req.AgentMode})
	hash := security.HashToken(string(body))
	op = domain.Operation{ID: domain.ID(), Requester: p.User.ID, ResourceID: r.ID, HostID: h.ID, Action: req.Action, Parameters: req.Parameters, Environment: h.Environment, Risk: d.Risk, State: "queued", RequestID: req.RequestID, Reason: req.Reason, Agent: req.Agent, AgentMode: req.AgentMode, CreatedAt: time.Now().UTC(), BatchID: req.BatchID, BatchIndex: req.BatchIndex}
	if d.Approval {
		op.State = "waiting_approval"
	}
	params, _ := json.Marshal(req.Parameters)
	targetHash, err := e.TargetHash(ctx, h, r)
	if err != nil {
		return op, err
	}
	tx, err := e.DB.Pool.Begin(ctx)
	if err != nil {
		return op, err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "INSERT INTO operations(id,requester,resource_id,host_id,action,parameters,environment,risk,state,request_id,reason,agent,agent_mode,auth_mfa,idempotency_key,request_hash,batch_id,batch_index,auth_token_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19) ON CONFLICT(requester,idempotency_key) DO NOTHING", op.ID, p.User.ID, r.ID, h.ID, req.Action, params, h.Environment, d.Risk, op.State, req.RequestID, req.Reason, req.Agent, req.AgentMode, p.MFA, req.IdempotencyKey, hash, req.BatchID, req.BatchIndex, p.TokenID)
	if err != nil {
		return op, err
	}
	if tag.RowsAffected() == 0 {
		var b []byte
		var existing string
		err = tx.QueryRow(ctx, "SELECT to_jsonb(o),request_hash FROM operations o WHERE requester=$1 AND idempotency_key=$2", p.User.ID, req.IdempotencyKey).Scan(&b, &existing)
		if err != nil {
			return op, err
		}
		if existing != hash {
			return op, Denied{"idempotency key reused with different request"}
		}
		err = json.Unmarshal(b, &op)
		return op, err
	}
	if _, err = tx.Exec(ctx, "UPDATE operations SET target_hash=$2 WHERE id=$1", op.ID, targetHash); err != nil {
		return op, err
	}
	action := "operation.created"
	if d.Approval {
		action = "approval.requested"
	}
	if err = store.AuditTx(ctx, tx, domain.Event{Actor: p.User.ID, ActorType: actorType(req.Agent), ResourceID: r.ID, HostID: h.ID, Environment: h.Environment, RequestID: req.RequestID, Action: action, Decision: "allow", Metadata: map[string]any{"operation_id": op.ID, "action": op.Action, "state": op.State, "policy": d}}); err != nil {
		return op, err
	}
	err = tx.Commit(ctx)
	return op, err
}
func actorType(agent bool) string {
	if agent {
		return "agent"
	}
	return "user"
}
func (e *Engine) Get(ctx context.Context, id string) (op domain.Operation, err error) {
	var b []byte
	err = e.DB.Pool.QueryRow(ctx, "SELECT to_jsonb(o) FROM operations o WHERE id=$1", id).Scan(&b)
	if err == nil {
		err = json.Unmarshal(b, &op)
	}
	return
}
func (e *Engine) List(ctx context.Context) ([]domain.Operation, error) {
	rows, err := e.DB.Pool.Query(ctx, "SELECT to_jsonb(o) FROM operations o ORDER BY created_at DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []domain.Operation{}
	for rows.Next() {
		var b []byte
		var op domain.Operation
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(b, &op); err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}
func (e *Engine) Approve(ctx context.Context, p domain.Principal, id string, approve bool, reason string) error {
	op, err := e.Get(ctx, id)
	if err != nil {
		return err
	}
	if !rbac.Allowed(p, "operation.approve", op.Environment) {
		return Denied{"approval permission required"}
	}
	if p.User.ID == op.Requester {
		return Denied{"self approval forbidden"}
	}
	if p.User.MFARequired && !p.MFA {
		return Denied{"MFA required"}
	}
	if len(reason) < 3 {
		return fmt.Errorf("approval reason required")
	}
	state := "queued"
	event := "approval.approved"
	if !approve {
		state = "rejected"
		event = "approval.rejected"
	}
	tx, err := e.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE operations SET state=$2,approval_by=$3,error=$4,finished_at=CASE WHEN $2='rejected' THEN now() ELSE NULL END WHERE id=$1 AND state='waiting_approval'", id, state, p.User.ID, security.Bounded(reason, 2000, 20))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return Denied{"operation is not waiting for approval"}
	}
	if err = store.AuditTx(ctx, tx, domain.Event{Actor: p.User.ID, Action: event, Decision: state, ResourceID: op.ResourceID, Environment: op.Environment, Metadata: map[string]any{"operation_id": id, "reason": reason}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (e *Engine) Cancel(ctx context.Context, p domain.Principal, id string) error {
	op, err := e.Get(ctx, id)
	if err != nil {
		return err
	}
	if p.User.ID != op.Requester && p.User.Role != "ADMIN" {
		return Denied{"only requester or admin may cancel"}
	}
	if !rbac.Allowed(p, "operation.read", op.Environment) {
		return Denied{"environment denied"}
	}
	tx, err := e.DB.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE operations SET state='cancelled',finished_at=now(),error='cancelled; if already running, remote effects require reconciliation' WHERE id=$1 AND state IN ('waiting_approval','queued','running')", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return Denied{"operation is terminal"}
	}
	if err = store.AuditTx(ctx, tx, domain.Event{Actor: p.User.ID, Action: "operation.cancelled", Environment: op.Environment, ResourceID: op.ResourceID, Metadata: map[string]any{"operation_id": id}}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (e *Engine) Batch(ctx context.Context, p domain.Principal, req Request, ids []string, batchSize, threshold int, continueOnError bool) (string, []domain.Operation, error) {
	if len(ids) == 0 || len(ids) > 500 || batchSize < 1 || batchSize > 20 || threshold < 0 || threshold > 500 {
		return "", nil, fmt.Errorf("invalid batch bounds")
	}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			return "", nil, fmt.Errorf("duplicate resource")
		}
		seen[id] = true
		r, err := e.DB.Resource(ctx, id)
		if err != nil {
			return "", nil, err
		}
		h, err := e.DB.Host(ctx, r.HostID)
		if err != nil {
			return "", nil, err
		}
		if _, err = e.Authorize(ctx, p, r, h, req); err != nil {
			return "", nil, err
		}
	}
	if req.IdempotencyKey == "" || len(req.IdempotencyKey) > 80 {
		return "", nil, fmt.Errorf("batch Idempotency-Key must contain 1..80 characters")
	}
	batch := security.HashToken(p.User.ID + ":batch:" + req.IdempotencyKey)[:32]
	conn, err := e.DB.Pool.Acquire(ctx)
	if err != nil {
		return "", nil, err
	}
	defer conn.Release()
	if _, err = conn.Exec(ctx, "SELECT pg_advisory_lock(hashtextextended($1,0))", batch); err != nil {
		return "", nil, err
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(hashtextextended($1,0))", batch)
	requestBytes, _ := json.Marshal(map[string]any{"ids": ids, "action": req.Action, "parameters": req.Parameters, "batch_size": batchSize, "threshold": threshold, "continue": continueOnError})
	requestHash := security.HashToken(string(requestBytes))
	_, err = e.DB.Pool.Exec(ctx, "INSERT INTO batches(id,requester,batch_size,failure_threshold,continue_on_error,request_hash) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING", batch, p.User.ID, batchSize, threshold, continueOnError, requestHash)
	if err != nil {
		return "", nil, err
	}
	var storedHash string
	if err = e.DB.Pool.QueryRow(ctx, "SELECT request_hash FROM batches WHERE id=$1", batch).Scan(&storedHash); err != nil {
		return "", nil, err
	}
	if storedHash != requestHash {
		return "", nil, Denied{"batch idempotency collision"}
	}
	ops := []domain.Operation{}
	for i, id := range ids {
		r := req
		r.ResourceID = id
		r.IdempotencyKey = req.IdempotencyKey + ":" + id
		r.BatchID = batch
		r.BatchIndex = i
		op, err := e.Submit(ctx, p, r)
		if err != nil {
			_, _ = e.DB.Pool.Exec(ctx, "UPDATE operations SET state='cancelled',error='batch creation failed',finished_at=now() WHERE batch_id=$1 AND state IN ('queued','waiting_approval')", batch)
			return batch, ops, err
		}
		ops = append(ops, op)
	}
	if _, err = e.DB.Pool.Exec(ctx, "UPDATE batches SET ready=true WHERE id=$1", batch); err != nil {
		return batch, ops, err
	}
	return batch, ops, nil
}
func IsDenied(err error) bool {
	var d Denied
	return errors.As(err, &d) || strings.Contains(fmt.Sprint(err), "permission")
}

var _ = pgx.ErrNoRows
