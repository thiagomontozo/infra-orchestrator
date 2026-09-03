package operations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/rbac"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"go.opentelemetry.io/otel"
	"log/slog"
	"sync"
	"time"
)

type Queue interface {
	Claim(context.Context, string) (domain.Operation, error)
	Renew(context.Context, domain.Operation, string) error
	Finish(context.Context, domain.Operation, string, string, string) error
}
type PGQueue struct{ DB *store.DB }

func (q *PGQueue) Claim(ctx context.Context, worker string) (op domain.Operation, err error) {
	tx, err := q.DB.Pool.Begin(ctx)
	if err != nil {
		return op, err
	}
	defer tx.Rollback(ctx)
	var b []byte
	err = tx.QueryRow(ctx, `SELECT to_jsonb(o) FROM operations o WHERE state='queued'
 AND NOT EXISTS(SELECT 1 FROM resource_leases l WHERE l.resource_id=o.resource_id)
 AND (o.batch_id='' OR EXISTS(SELECT 1 FROM batches b WHERE b.id=o.batch_id AND b.ready
 AND NOT EXISTS(SELECT 1 FROM operations x WHERE x.batch_id=o.batch_id AND x.batch_index/b.batch_size<o.batch_index/b.batch_size AND x.state NOT IN ('succeeded','failed','timeout','rejected','cancelled'))
 AND (b.continue_on_error OR NOT EXISTS(SELECT 1 FROM operations x WHERE x.batch_id=o.batch_id AND x.state IN ('failed','timeout','rejected')))
 AND (SELECT count(*) FROM operations x WHERE x.batch_id=o.batch_id AND x.state IN ('failed','timeout','rejected'))<=b.failure_threshold))
 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&b)
	if err != nil {
		return op, err
	}
	if err = json.Unmarshal(b, &op); err != nil {
		return op, err
	}
	tag, err := tx.Exec(ctx, "INSERT INTO resource_leases(resource_id,operation_id,worker_id,expires_at) VALUES($1,$2,$3,now()+interval '45 seconds') ON CONFLICT DO NOTHING", op.ResourceID, op.ID, worker)
	if err != nil {
		return op, err
	}
	if tag.RowsAffected() == 0 {
		return op, pgx.ErrNoRows
	}
	_, err = tx.Exec(ctx, "UPDATE operations SET state='running',worker_id=$2,lease_until=now()+interval '45 seconds',started_at=now() WHERE id=$1", op.ID, worker)
	if err != nil {
		return op, err
	}
	op.State = "running"
	op.WorkerID = worker
	if err = store.AuditTx(ctx, tx, domain.Event{Actor: worker, ActorType: "worker", Action: "operation.started", Environment: op.Environment, ResourceID: op.ResourceID, Metadata: map[string]any{"operation_id": op.ID}}); err != nil {
		return op, err
	}
	err = tx.Commit(ctx)
	return
}
func (q *PGQueue) Renew(ctx context.Context, op domain.Operation, worker string) error {
	tx, e := q.DB.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "UPDATE operations SET lease_until=now()+interval '45 seconds' WHERE id=$1 AND worker_id=$2 AND state='running' AND lease_until>now()", op.ID, worker)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("operation lease lost or cancelled")
	}
	tag, e = tx.Exec(ctx, "UPDATE resource_leases SET expires_at=now()+interval '45 seconds' WHERE resource_id=$1 AND operation_id=$2 AND worker_id=$3 AND expires_at>now()", op.ResourceID, op.ID, worker)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("resource lease lost")
	}
	return tx.Commit(ctx)
}
func (q *PGQueue) Finish(ctx context.Context, op domain.Operation, state, result, reason string) error {
	tx, e := q.DB.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	tag, e := tx.Exec(ctx, "UPDATE operations SET state=$2,result=$3,error=$4,finished_at=now(),lease_until=NULL WHERE id=$1 AND state='running' AND worker_id=$5", op.ID, state, security.Bounded(security.Redact(result), 65536, 2000), security.Bounded(security.Redact(reason), 2000, 30), op.WorkerID)
	if e != nil {
		return e
	}
	if state != "timeout" {
		_, e = tx.Exec(ctx, "DELETE FROM resource_leases WHERE resource_id=$1 AND operation_id=$2 AND worker_id=$3", op.ResourceID, op.ID, op.WorkerID)
	}
	if e != nil {
		return e
	}
	if tag.RowsAffected() > 0 {
		if e = store.AuditTx(ctx, tx, domain.Event{Actor: op.WorkerID, ActorType: "worker", Action: "operation." + state, Decision: state, Environment: op.Environment, ResourceID: op.ResourceID, Result: reason, Metadata: map[string]any{"operation_id": op.ID}}); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (q *PGQueue) Recover(ctx context.Context) error {
	tx, e := q.DB.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, "UPDATE operations SET state='timeout',error='worker lease expired; outcome unknown, manual reconciliation required; not retried',finished_at=now() WHERE state='running' AND lease_until<now() RETURNING id,resource_id,environment")
	if e != nil {
		return e
	}
	var recovered []domain.Operation
	for rows.Next() {
		var o domain.Operation
		if e = rows.Scan(&o.ID, &o.ResourceID, &o.Environment); e != nil {
			rows.Close()
			return e
		}
		recovered = append(recovered, o)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, o := range recovered {
		if e = store.AuditTx(ctx, tx, domain.Event{ActorType: "worker", Action: "operation.orphaned", Environment: o.Environment, ResourceID: o.ResourceID, Metadata: map[string]any{"operation_id": o.ID}}); e != nil {
			return e
		}
	} // Retain uncertain resource locks until an administrator explicitly reconciles.
	_, e = tx.Exec(ctx, `UPDATE operations o SET state='cancelled',finished_at=now(),error='rolling batch stopped by failure threshold' FROM batches b WHERE o.batch_id=b.id AND o.state IN ('queued','waiting_approval') AND ((NOT b.continue_on_error AND EXISTS(SELECT 1 FROM operations x WHERE x.batch_id=b.id AND x.state IN ('failed','timeout','rejected'))) OR (SELECT count(*) FROM operations x WHERE x.batch_id=b.id AND x.state IN ('failed','timeout','rejected'))>b.failure_threshold)`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

type Worker struct {
	Engine      *Engine
	Queue       *PGQueue
	ID          string
	Concurrency int
}

func (w *Worker) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < w.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					op, e := w.Queue.Claim(ctx, w.ID)
					if e != nil {
						if !errors.Is(e, pgx.ErrNoRows) && ctx.Err() == nil {
							slog.Error("claim failed", "error", e)
						}
						continue
					}
					w.execute(ctx, op)
				}
			}
		}()
	}
	recoverTick := time.NewTicker(15 * time.Second)
	defer recoverTick.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-recoverTick.C:
			if e := w.Queue.Recover(ctx); e != nil {
				slog.Error("recovery failed", "error", e)
			}
		}
	}
}
func (w *Worker) execute(parent context.Context, op domain.Operation) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	ctx, span := otel.Tracer("operations").Start(ctx, "operation.execute")
	defer span.End()
	done := make(chan struct{})
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		t := time.NewTicker(10 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				if e := w.Queue.Renew(ctx, op, w.ID); e != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { close(done); <-heartbeatDone }()
	result := ""
	state := "succeeded"
	var executionErr error
	executionErr = func() error {
		u, e := w.Engine.DB.User(ctx, op.Requester)
		if e != nil {
			return e
		}
		var mfa bool
		var tokenID string
		if e = w.Engine.DB.Pool.QueryRow(ctx, "SELECT auth_mfa,auth_token_id FROM operations WHERE id=$1", op.ID).Scan(&mfa, &tokenID); e != nil {
			return e
		}
		p := domain.Principal{User: u, MFA: mfa && u.MFAEnabled, TokenID: tokenID}
		if tokenID != "" {
			var scopes []byte
			if e = w.Engine.DB.Pool.QueryRow(ctx, "SELECT scopes FROM api_tokens WHERE id=$1 AND revoked_at IS NULL AND expires_at>now()", tokenID).Scan(&scopes); e != nil {
				return Denied{"requesting token revoked or expired"}
			}
			if e = json.Unmarshal(scopes, &p.Scopes); e != nil {
				return e
			}
		}
		r, e := w.Engine.DB.Resource(ctx, op.ResourceID)
		if e != nil {
			return e
		}
		h, e := w.Engine.DB.Host(ctx, r.HostID)
		if e != nil {
			return e
		}
		if h.Environment != op.Environment {
			return Denied{"environment changed; resubmit for policy evaluation"}
		}
		var savedTarget string
		if e = w.Engine.DB.Pool.QueryRow(ctx, "SELECT target_hash FROM operations WHERE id=$1", op.ID).Scan(&savedTarget); e != nil {
			return e
		}
		currentTarget, e := w.Engine.TargetHash(ctx, h, r)
		if e != nil {
			return e
		}
		if savedTarget == "" || savedTarget != currentTarget {
			return Denied{"connection or target changed; resubmit for approval"}
		}
		d, e := w.Engine.Authorize(ctx, p, r, h, Request{Action: op.Action, Parameters: op.Parameters, Agent: op.Agent, AgentMode: op.AgentMode})
		if e != nil {
			return e
		}
		if d.Approval {
			if op.ApprovalBy == "" {
				return Denied{"approval now required; resubmit"}
			}
			approver, e := w.Engine.DB.User(ctx, op.ApprovalBy)
			if e != nil || !rbac.Allowed(domain.Principal{User: approver}, "operation.approve", op.Environment) {
				return Denied{"approver no longer authorized"}
			}
		}
		a := w.Engine.Adapters[r.Provider]
		if e = w.Queue.Renew(ctx, op, w.ID); e != nil {
			return e
		}
		resolved, e := w.Engine.Parameters(ctx, op.Parameters)
		if e != nil {
			return e
		}
		executeOp := op
		executeOp.Parameters = resolved
		out, e := a.Execute(ctx, h, r, executeOp)
		result = out.Output
		if e != nil {
			return e
		}
		if op.BatchID != "" && domain.Contains([]string{"restart", "reload", "up", "recreate", "scale", "deploy", "run"}, op.Action) {
			deadline := time.NewTimer(60 * time.Second)
			defer deadline.Stop()
			tick := time.NewTicker(3 * time.Second)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-deadline.C:
					return fmt.Errorf("rolling health check timed out")
				case <-tick.C:
					rs, e := a.Discover(ctx, h)
					if e != nil {
						continue
					}
					_ = w.Engine.DB.UpsertResources(ctx, h.ID, r.Provider, rs)
					for _, current := range rs {
						if current.ExternalID == r.ExternalID && current.Health == "healthy" {
							return nil
						}
					}
				}
			}
		}
		refreshProvider := r.Provider
		if refreshProvider == "provisioning" {
			refreshProvider = "docker"
		}
		rs, e := w.Engine.Adapters[refreshProvider].Discover(ctx, h)
		if e == nil {
			e = w.Engine.DB.UpsertResources(ctx, h.ID, refreshProvider, rs)
		}
		if e != nil {
			result += "\nInventory refresh failed; perform discovery."
		}
		return nil
	}()
	if executionErr != nil {
		state = "failed"
		if errors.Is(executionErr, context.DeadlineExceeded) || errors.Is(executionErr, context.Canceled) {
			state = "timeout"
		}
		if IsDenied(executionErr) {
			state = "rejected"
		}
	}
	finalCtx, finalCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer finalCancel()
	reason := ""
	if executionErr != nil {
		reason = executionErr.Error()
	}
	if e := w.Queue.Finish(finalCtx, op, state, result, reason); e != nil {
		slog.Error("operation completion persistence failed", "operation", op.ID, "error", e)
	}
}
