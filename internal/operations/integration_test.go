package operations

import (
	"context"
	"encoding/json"
	"github.com/thiagomontozo/infra-orchestrator/internal/adapters"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/store"
	"os"
	"sync"
	"testing"
	"time"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	raw := os.Getenv("TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("TEST_DATABASE_URL required for PostgreSQL integration")
	}
	db, e := store.Open(context.Background(), raw)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(context.Background()); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(db.Pool.Close)
	return db
}
func seed(t *testing.T, db *store.DB, env string) (domain.Principal, domain.Resource) {
	t.Helper()
	ctx := context.Background()
	uid := domain.ID()
	u := domain.User{ID: uid, Username: uid, Email: uid + "@example.test", Role: "OPERATOR", Enabled: true, Environments: []string{"*"}}
	if e := db.CreateUser(ctx, u); e != nil {
		t.Fatal(e)
	}
	h := domain.Host{ID: domain.ID(), Name: "test", Environment: env, Enabled: true}
	if e := db.SaveHost(ctx, h); e != nil {
		t.Fatal(e)
	}
	r := domain.Resource{ExternalID: "abc123", Name: "api", Provider: "docker", Type: "docker_container", Environment: env}
	if e := db.UpsertResources(ctx, h.ID, "docker", []domain.Resource{r}); e != nil {
		t.Fatal(e)
	}
	var b []byte
	if e := db.Pool.QueryRow(ctx, "SELECT document FROM resources WHERE host_id=$1", h.ID).Scan(&b); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return domain.Principal{User: u}, r
}
func TestPostgresApprovalIdempotencyAndLocks(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	engine := &Engine{DB: db, Adapters: adapters.New(nil)}
	p, r := seed(t, db, "production")
	req := Request{ResourceID: r.ID, Action: "restart", Reason: "approved maintenance", IdempotencyKey: domain.ID(), RequestID: domain.ID()}
	op, e := engine.Submit(ctx, p, req)
	if e != nil {
		t.Fatal(e)
	}
	if op.State != "waiting_approval" {
		t.Fatal(op.State)
	}
	same, e := engine.Submit(ctx, p, req)
	if e != nil || same.ID != op.ID {
		t.Fatal("idempotency", e)
	}
	req.Action = "stop"
	if _, e = engine.Submit(ctx, p, req); e == nil {
		t.Fatal("idempotency collision allowed")
	}
	if e = engine.Approve(ctx, p, op.ID, true, "self approval"); e == nil {
		t.Fatal("self approval accepted")
	}
	uid := domain.ID()
	a := domain.User{ID: uid, Username: uid, Email: uid + "@example.test", Role: "APPROVER", Enabled: true, Environments: []string{"*"}}
	if e = db.CreateUser(ctx, a); e != nil {
		t.Fatal(e)
	}
	if e = engine.Approve(ctx, domain.Principal{User: a}, op.ID, true, "change reviewed"); e != nil {
		t.Fatal(e)
	}
	q := &PGQueue{DB: db}
	var claimed []domain.Operation
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			v, e := q.Claim(ctx, domain.ID())
			if e == nil {
				mu.Lock()
				claimed = append(claimed, v)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	n := 0
	for _, v := range claimed {
		if v.ID == op.ID {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("claimed %d times", n)
	}
	for _, v := range claimed {
		if e = q.Finish(ctx, v, "succeeded", "ok", ""); e != nil {
			t.Fatal(e)
		}
	}
	var count int
	if e = db.Pool.QueryRow(ctx, "SELECT count(*) FROM audit WHERE metadata->>'operation_id'=$1", op.ID).Scan(&count); e != nil || count < 3 {
		t.Fatal("audit timeline missing", count, e)
	}
	if _, e = db.Pool.Exec(ctx, "DELETE FROM audit WHERE metadata->>'operation_id'=$1", op.ID); e == nil {
		t.Fatal("audit deletion allowed")
	}
}
func TestRecoveryNeverRequeues(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	engine := &Engine{DB: db, Adapters: adapters.New(nil)}
	p, r := seed(t, db, "development")
	op, e := engine.Submit(ctx, p, Request{ResourceID: r.ID, Action: "restart", Reason: "recovery test", IdempotencyKey: domain.ID()})
	if e != nil {
		t.Fatal(e)
	}
	q := &PGQueue{DB: db}
	var claimed domain.Operation
	for i := 0; i < 100; i++ {
		claimed, e = q.Claim(ctx, "worker-recovery")
		if e != nil {
			t.Fatal(e)
		}
		if claimed.ID == op.ID {
			break
		}
		_ = q.Finish(ctx, claimed, "cancelled", "", "")
	}
	_, e = db.Pool.Exec(ctx, "UPDATE operations SET lease_until=now()-interval '1 minute' WHERE id=$1", op.ID)
	if e != nil {
		t.Fatal(e)
	}
	if e = q.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	op, e = engine.Get(ctx, op.ID)
	if e != nil || op.State != "timeout" {
		t.Fatal(op.State, e)
	}
	var leases int
	if e = db.Pool.QueryRow(ctx, "SELECT count(*) FROM resource_leases WHERE resource_id=$1", r.ID).Scan(&leases); e != nil || leases != 1 {
		t.Fatal("uncertain resource not quarantined", e)
	}
	_, _ = db.Pool.Exec(ctx, "DELETE FROM resource_leases WHERE resource_id=$1", r.ID)
}
func TestQueueBoundedRolling(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	engine := &Engine{DB: db, Adapters: adapters.New(nil)}
	p, r := seed(t, db, "development")
	var rs []domain.Resource
	for _, id := range []string{"a", "b", "c"} {
		rs = append(rs, domain.Resource{ExternalID: id, Name: id, Provider: "docker", Type: "docker_container", Environment: "development"})
	}
	if e := db.UpsertResources(ctx, r.HostID, "docker", rs); e != nil {
		t.Fatal(e)
	}
	all, e := db.Resources(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, v := range all {
		if v.HostID == r.HostID && v.ExternalID != "abc123" {
			ids = append(ids, v.ID)
		}
	}
	batch, ops, e := engine.Batch(ctx, p, Request{Action: "restart", Reason: "rolling restart", IdempotencyKey: domain.ID()}, ids, 1, 0, false)
	if e != nil {
		t.Fatal(e)
	}
	if len(ops) != 3 {
		t.Fatal(len(ops))
	}
	q := &PGQueue{DB: db}
	first, e := q.Claim(ctx, "rolling")
	if e != nil {
		t.Fatal(e)
	}
	if first.BatchID != batch {
		t.Fatalf("unexpected batch %s", first.BatchID)
	}
	if _, e = q.Claim(ctx, "second"); e == nil {
		t.Fatal("next batch started before health completion")
	}
	if e = q.Finish(ctx, first, "failed", "", "health unavailable"); e != nil {
		t.Fatal(e)
	}
	if e = q.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Millisecond)
	for _, v := range ops {
		actual, e := engine.Get(ctx, v.ID)
		if e != nil {
			t.Fatal(e)
		}
		if actual.State != "cancelled" && actual.State != "failed" {
			t.Fatal("batch failure threshold ignored", actual.State)
		}
	}
}
