package scheduler

import (
	"context"
	"fmt"
	"github.com/robfig/cron/v3"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"log/slog"
	"time"
)

type Scheduler struct {
	DB     *store.DB
	Engine *operations.Engine
}

func Due(data map[string]any, now time.Time) (time.Time, bool, error) {
	if !domain.Bool(data, "enabled") {
		return time.Time{}, false, nil
	}
	if expr := domain.String(data, "cron"); expr != "" {
		schedule, e := cron.ParseStandard("CRON_TZ=" + domain.String(data, "timezone") + " " + expr)
		if e != nil {
			return time.Time{}, false, e
		}
		candidate := schedule.Next(now.Truncate(time.Minute).Add(-time.Minute))
		return candidate, !candidate.After(now), nil
	}
	at, e := time.Parse(time.RFC3339, domain.String(data, "at"))
	if e != nil {
		return time.Time{}, false, e
	}
	return at, !at.After(now), nil
}
func (s *Scheduler) Tick(ctx context.Context) error {
	conn, e := s.DB.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var leader bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(7189942)").Scan(&leader); e != nil {
		return e
	}
	if !leader {
		return nil
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(7189942)")
	all, e := s.DB.Objects(ctx, "schedules")
	if e != nil {
		return e
	}
	for _, o := range all {
		at, due, e := Due(o.Data, time.Now())
		if e != nil || !due {
			continue
		}
		tag, e := s.DB.Pool.Exec(ctx, "INSERT INTO schedule_runs(schedule_id,scheduled_at) VALUES($1,$2) ON CONFLICT DO NOTHING", o.ID, at)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		u, e := s.DB.User(ctx, domain.String(o.Data, "requester"))
		var op domain.Operation
		if e == nil {
			params, _ := o.Data["parameters"].(map[string]any)
			op, e = s.Engine.Submit(ctx, domain.Principal{User: u, MFA: domain.Bool(o.Data, "auth_mfa") && u.MFAEnabled}, operations.Request{ResourceID: domain.String(o.Data, "resource_id"), Action: domain.String(o.Data, "action"), Parameters: params, Reason: "Scheduled: " + o.Name, IdempotencyKey: "schedule:" + o.ID + ":" + at.UTC().Format(time.RFC3339), RequestID: domain.ID()})
		}
		message := ""
		if e != nil {
			message = e.Error()
		}
		if _, e = s.DB.Pool.Exec(ctx, "UPDATE schedule_runs SET operation_id=$3,error=$4 WHERE schedule_id=$1 AND scheduled_at=$2", o.ID, at, op.ID, message); e != nil {
			return e
		}
		if e = s.DB.Audit(ctx, domain.Event{Actor: domain.String(o.Data, "requester"), ActorType: "scheduler", Action: "schedule.triggered", Environment: o.Environment, Result: message, Metadata: map[string]any{"schedule_id": o.ID, "operation_id": op.ID, "at": at}}); e != nil {
			return e
		}
	}
	return nil
}
func (s *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if e := s.Tick(ctx); e != nil {
				slog.Error("scheduler tick failed", "error", e)
			}
		}
	}
}

var _ = fmt.Sprint
