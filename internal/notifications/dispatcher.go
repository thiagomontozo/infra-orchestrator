package notifications

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/secrets"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"log/slog"
	"time"
)

type Dispatcher struct {
	DB      *store.DB
	Network *security.NetworkPolicy
	Secrets secrets.Provider
}

func (d *Dispatcher) Run(ctx context.Context) {
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if e := d.Tick(ctx); e != nil {
				slog.Error("notification dispatcher", "error", e)
			}
		}
	}
}
func (d *Dispatcher) Tick(ctx context.Context) error {
	conn, e := d.DB.Pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer conn.Release()
	var leader bool
	if e = conn.QueryRow(ctx, "SELECT pg_try_advisory_lock(9151832)").Scan(&leader); e != nil || !leader {
		return e
	}
	defer conn.Exec(context.Background(), "SELECT pg_advisory_unlock(9151832)")
	providers, e := d.DB.Objects(ctx, "notifications")
	if e != nil {
		return e
	}
	for _, o := range providers {
		if !domain.Bool(o.Data, "enabled") {
			continue
		}
		_, e = d.DB.Pool.Exec(ctx, `INSERT INTO notification_deliveries(event_id,provider_id) SELECT id,$1 FROM events WHERE topic IN ('host.offline','operation.failed','approval.requested','alert.created','incident.created','agent.recommendation') AND created_at>=$2 AND ($3='' OR environment=$3) ON CONFLICT DO NOTHING`, o.ID, o.CreatedAt, o.Environment)
		if e != nil {
			return e
		}
		rows, e := d.DB.Pool.Query(ctx, `SELECT e.id,e.topic,e.environment,e.payload FROM notification_deliveries d JOIN events e ON e.id=d.event_id WHERE d.provider_id=$1 AND d.status='pending' AND d.next_attempt<=now() AND d.attempts<5 ORDER BY e.id LIMIT 20`, o.ID)
		if e != nil {
			return e
		}
		items := []Notification{}
		for rows.Next() {
			var id int64
			var n Notification
			var b []byte
			if e = rows.Scan(&id, &n.Event, &n.Environment, &b); e != nil {
				rows.Close()
				return e
			}
			n.ID = fmt.Sprint(id)
			n.Message = security.Redact(string(b))
			items = append(items, n)
		}
		rows.Close()
		var secret string
		if sid := domain.String(o.Data, "secret_id"); sid != "" {
			b, e := d.Secrets.Get(ctx, sid)
			if e != nil {
				return e
			}
			secret = string(b)
		}
		var provider Provider
		if domain.String(o.Data, "type") == "email" {
			provider = &Email{Host: domain.String(o.Data, "smtp_host"), Port: domain.String(o.Data, "smtp_port"), Username: domain.String(o.Data, "username"), Password: secret, From: domain.String(o.Data, "from"), To: domain.String(o.Data, "to"), Network: d.Network}
		} else {
			provider = &Webhook{URL: domain.String(o.Data, "url"), Token: secret, Kind: domain.String(o.Data, "type"), Client: d.Network.Client(15 * time.Second)}
		}
		for _, n := range items {
			e = provider.Send(ctx, n)
			state, message := "sent", ""
			if e != nil {
				state = "pending"
				message = security.Bounded(security.Redact(e.Error()), 1000, 10)
			}
			_, e = d.DB.Pool.Exec(ctx, "UPDATE notification_deliveries SET status=$3,attempts=attempts+1,error=$4,next_attempt=now()+make_interval(secs=>LEAST(3600,30*power(2,attempts)::int)) WHERE event_id=$1 AND provider_id=$2", n.ID, o.ID, state, message)
			if e != nil {
				return e
			}
		}
	}
	return nil
}

var _ = json.Valid
