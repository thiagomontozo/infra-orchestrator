package agent

import (
	"context"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/operations"
	"log/slog"
	"time"
)

func (r *Runtime) Monitor(ctx context.Context) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if e := r.monitorTick(ctx); e != nil {
				slog.Error("agent monitor failed", "error", e)
			}
		}
	}
}
func (r *Runtime) monitorTick(ctx context.Context) error {
	conn, e := r.DB.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var leader bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(7729214)").Scan(&leader); e != nil || !leader {
		return e
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(7729214)")
	monitors, e := r.DB.Objects(ctx, "monitoring")
	if e != nil {
		return e
	}
	resources, e := r.DB.Resources(ctx)
	if e != nil {
		return e
	}
	for _, m := range monitors {
		mode := domain.String(m.Data, "mode")
		if !domain.Bool(m.Data, "enabled") || mode == "DISABLED" {
			continue
		}
		last, _ := time.Parse(time.RFC3339, domain.String(m.Data, "last_run"))
		if time.Since(last) < time.Duration(domain.Number(m.Data, "interval"))*time.Second {
			continue
		}
		m.Data["last_run"] = time.Now().UTC().Format(time.RFC3339)
		if e = r.DB.SaveObject(ctx, m); e != nil {
			return e
		}
		u, e := r.DB.User(ctx, domain.String(m.Data, "service_account_id"))
		if e != nil || !u.Service || !u.Enabled {
			continue
		}
		p := domain.Principal{User: u}
		for _, res := range resources {
			if res.Health != "unhealthy" {
				continue
			}
			h, e := r.DB.Host(ctx, res.HostID)
			if e != nil {
				continue
			}
			if m.Environment != "" && m.Environment != h.Environment {
				continue
			}
			if id := domain.String(m.Data, "resource_id"); id != "" && id != res.ID {
				continue
			}
			if id := domain.String(m.Data, "host_id"); id != "" && id != res.HostID {
				continue
			}
			if group := domain.String(m.Data, "group"); group != "" && !domain.Contains(h.Groups, group) {
				continue
			}
			rec, e := r.Analyze(ctx, p, res.ID, domain.String(m.Data, "provider_id"), "Analyze locally detected unhealthy resource")
			if e != nil {
				continue
			}
			if mode != "AUTOMATED_POLICY_CONTROLLED" {
				continue
			}
			suggested, _ := rec.Data["suggested_tool"].(map[string]any)
			action, providers, ok := toolAction(domain.String(suggested, "name"))
			if !ok || !domain.Contains(providers, res.Provider) {
				continue
			}
			var count int
			e = r.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM operations WHERE resource_id=$1 AND agent=true AND created_at>now()-interval '1 hour'", res.ID).Scan(&count)
			if e != nil || count >= 3 {
				continue
			}
			_, e = r.Engine.Submit(ctx, p, operations.Request{ResourceID: res.ID, Action: action, Reason: "Policy-controlled agent recommendation " + rec.ID, Agent: true, AgentMode: mode, IdempotencyKey: "monitor:" + rec.ID, RequestID: domain.ID()})
			if e != nil {
				slog.Info("agent action denied", "resource", res.ID, "reason", e)
			}
		}
	}
	return nil
}
