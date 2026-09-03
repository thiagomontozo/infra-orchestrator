package events

import (
	"context"
	"fmt"
	"github.com/nats-io/nats.go"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"log/slog"
	"time"
)

type Bus interface {
	Publish(context.Context, string, []byte, string) error
	Close() error
}
type NATS struct {
	conn *nats.Conn
	js   nats.JetStreamContext
}

func Connect(url string) (*NATS, error) {
	c, e := nats.Connect(url, nats.Name("infra-orchestrator"), nats.Timeout(5*time.Second), nats.MaxReconnects(-1))
	if e != nil {
		return nil, e
	}
	js, e := c.JetStream()
	if e != nil {
		c.Close()
		return nil, e
	}
	if _, e = js.StreamInfo("INFRA_EVENTS"); e != nil {
		_, e = js.AddStream(&nats.StreamConfig{Name: "INFRA_EVENTS", Subjects: []string{"infra.>"}, Storage: nats.FileStorage, Retention: nats.LimitsPolicy, MaxAge: 7 * 24 * time.Hour, MaxBytes: 256 * 1024 * 1024})
		if e != nil {
			c.Close()
			return nil, e
		}
	}
	return &NATS{c, js}, nil
}
func (n *NATS) Publish(ctx context.Context, topic string, b []byte, id string) error {
	_, e := n.js.Publish("infra."+topic, b, nats.MsgId(id), nats.Context(ctx))
	return e
}
func (n *NATS) Close() error { return n.conn.Drain() }
func Relay(ctx context.Context, db *store.DB, bus Bus) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if e := relayBatch(ctx, db, bus); e != nil {
				slog.Error("event outbox failed", "error", e)
			}
		}
	}
}
func relayBatch(ctx context.Context, db *store.DB, bus Bus) error {
	tx, e := db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	rows, e := tx.Query(ctx, "SELECT id,topic,payload FROM events WHERE published_at IS NULL ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 50")
	if e != nil {
		return e
	}
	type item struct {
		id    int64
		topic string
		body  []byte
	}
	items := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.id, &i.topic, &i.body); e != nil {
			rows.Close()
			return e
		}
		items = append(items, i)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, i := range items {
		if e = bus.Publish(ctx, i.topic, i.body, fmt.Sprint(i.id)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "UPDATE events SET published_at=now() WHERE id=$1", i.id); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
