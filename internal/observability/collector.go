package observability

import (
	"context"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/discovery"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"log/slog"
	"strconv"
	"strings"
	"time"
)

type Finding struct {
	Key, Title, Severity, ResourceID, HostID, Environment string
	Evidence                                              string
}

func Evaluate(hosts []domain.Host, resources []domain.Resource) []Finding {
	out := []Finding{}
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		if h.State == "offline" {
			out = append(out, Finding{Key: "host-offline:" + h.ID, Title: h.Name + " is offline", Severity: "high", HostID: h.ID, Environment: h.Environment, Evidence: "Last SSH discovery failed"})
		}
		memory := domain.String(h.Facts, "memory")
		for _, line := range strings.Split(memory, "\n") {
			f := strings.Fields(line)
			if len(f) >= 4 && f[0] == "Mem:" {
				total, _ := strconv.ParseFloat(f[1], 64)
				used, _ := strconv.ParseFloat(f[2], 64)
				if total > 0 && used/total > 0.9 {
					out = append(out, Finding{Key: "host-memory:" + h.ID, Title: h.Name + " memory above 90%", Severity: "high", HostID: h.ID, Environment: h.Environment, Evidence: fmt.Sprintf("used %.1f%%", used/total*100)})
				}
			}
		}
		for _, line := range strings.Split(domain.String(h.Facts, "disk"), "\n") {
			f := strings.Fields(line)
			if len(f) >= 6 {
				pct, e := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
				if e == nil && pct >= 90 {
					out = append(out, Finding{Key: "host-disk:" + h.ID + ":" + f[5], Title: h.Name + " disk above 90%", Severity: "high", HostID: h.ID, Environment: h.Environment, Evidence: f[5] + " " + f[4]})
				}
			}
		}
	}
	for _, r := range resources {
		state := strings.ToLower(r.State)
		bad := r.Health == "unhealthy" || domain.Contains([]string{"failed", "fatal", "exited", "dead", "stopped", "crashloopbackoff", "error", "errored"}, state)
		if bad {
			out = append(out, Finding{Key: "resource:" + r.ID, Title: r.Name + " requires attention", Severity: "high", HostID: r.HostID, ResourceID: r.ID, Environment: r.Environment, Evidence: "state=" + r.State + ", health=" + r.Health})
		}
		if restarts := domain.Number(r.Metadata, "restarts"); restarts >= 5 {
			out = append(out, Finding{Key: "restart-loop:" + r.ID, Title: r.Name + " restart threshold exceeded", Severity: "medium", HostID: r.HostID, ResourceID: r.ID, Environment: r.Environment, Evidence: fmt.Sprintf("restart count %g", restarts)})
		}
	}
	return out
}

type Collector struct {
	DB        *store.DB
	Discovery *discovery.Service
}

func (c *Collector) Tick(ctx context.Context) error {
	conn, e := c.DB.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var leader bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(7710134)").Scan(&leader); e != nil || !leader {
		return e
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(7710134)")
	hosts, e := c.DB.Hosts(ctx)
	if e != nil {
		return e
	}
	for _, h := range hosts {
		if !h.Enabled {
			continue
		}
		if h.LastSeen != nil && time.Since(*h.LastSeen) < time.Minute {
			continue
		}
		probeCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		_, err := c.Discovery.Discover(probeCtx, h)
		cancel()
		if err != nil {
			slog.Warn("collector discovery failed", "host", h.ID, "error", err)
		}
	}
	hosts, e = c.DB.Hosts(ctx)
	if e != nil {
		return e
	}
	resources, e := c.DB.Resources(ctx)
	if e != nil {
		return e
	}
	findings := Evaluate(hosts, resources)
	active := map[string]bool{}
	for _, f := range findings {
		id := "alert-" + security.HashToken(f.Key)[:24]
		active[id] = true
		existing, err := c.DB.Object(ctx, "alerts", id)
		if err == nil && domain.String(existing.Data, "status") == "open" {
			continue
		}
		o := domain.Object{ID: id, Kind: "alerts", Name: f.Title, Environment: f.Environment, Data: map[string]any{"severity": f.Severity, "status": "open", "resource_id": f.ResourceID, "host_id": f.HostID, "evidence": f.Evidence, "source": "local_rules"}}
		if e = c.DB.SaveObject(ctx, o); e != nil {
			return e
		}
		if e = c.DB.Audit(ctx, domain.Event{ActorType: "collector", Action: "alert.created", HostID: f.HostID, ResourceID: f.ResourceID, Environment: f.Environment, Metadata: map[string]any{"alert_id": id, "title": f.Title}}); e != nil {
			return e
		}
	}
	alerts, e := c.DB.Objects(ctx, "alerts")
	if e != nil {
		return e
	}
	for _, a := range alerts {
		if domain.String(a.Data, "source") == "local_rules" && !active[a.ID] && domain.String(a.Data, "status") == "open" {
			a.Data["status"] = "resolved"
			if e = c.DB.SaveObject(ctx, a); e != nil {
				return e
			}
		}
	}
	deps, e := c.DB.Objects(ctx, "deployments")
	if e != nil {
		return e
	}
	for _, d := range deps {
		var state string
		var finished *time.Time
		e = c.DB.Pool.QueryRow(ctx, "SELECT state,finished_at FROM operations WHERE id=$1", domain.String(d.Data, "operation_id")).Scan(&state, &finished)
		if e == nil && domain.String(d.Data, "status") != state {
			d.Data["status"] = state
			d.Data["finished_at"] = finished
			if e = c.DB.SaveObject(ctx, d); e != nil {
				return e
			}
		}
	}
	return nil
}
func (c *Collector) Run(ctx context.Context) {
	tick := time.NewTicker(60 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if e := c.Tick(ctx); e != nil {
				slog.Error("collector failed", "error", e)
			}
		}
	}
}
