package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/thiagomontozo/infra-orchestrator/internal/domain"
	"github.com/thiagomontozo/infra-orchestrator/internal/security"
	"github.com/thiagomontozo/infra-orchestrator/migrations"
	"sort"
	"time"
)

type DB struct{ Pool *pgxpool.Pool }
type Inventory interface {
	Host(context.Context, string) (domain.Host, error)
	Resource(context.Context, string) (domain.Resource, error)
	Resources(context.Context) ([]domain.Resource, error)
}

func Open(ctx context.Context, url string) (*DB, error) {
	cfg, e := pgxpool.ParseConfig(url)
	if e != nil {
		return nil, e
	}
	cfg.MaxConns = 32
	cfg.MinConns = 2
	cfg.MaxConnLifetime = 30 * time.Minute
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return nil, e
	}
	if e = p.Ping(ctx); e != nil {
		p.Close()
		return nil, e
	}
	return &DB{p}, nil
}
func (d *DB) Migrate(ctx context.Context) error {
	tx, e := d.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(78121455)"); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, "CREATE TABLE IF NOT EXISTS schema_migrations(version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"); e != nil {
		return e
	}
	files, e := migrations.Files.ReadDir(".")
	if e != nil {
		return e
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name() < files[j].Name() })
	for _, f := range files {
		var n int
		if e = tx.QueryRow(ctx, "SELECT count(*) FROM schema_migrations WHERE version=$1", f.Name()).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			continue
		}
		b, e := migrations.Files.ReadFile(f.Name())
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, string(b)); e != nil {
			return fmt.Errorf("migration %s: %w", f.Name(), e)
		}
		if _, e = tx.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES($1)", f.Name()); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}

const userCols = "id,username,email,password_hash,role,enabled,environments,mfa_required,mfa_secret,mfa_last,force_password,service,last_login"

func scanUser(row pgx.Row) (u domain.User, e error) {
	var env []byte
	e = row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.Role, &u.Enabled, &env, &u.MFARequired, &u.MFASecret, &u.MFALast, &u.ForcePassword, &u.Service, &u.LastLogin)
	if e == nil {
		e = json.Unmarshal(env, &u.Environments)
	}
	u.MFAEnabled = u.MFASecret != ""
	return
}
func (d *DB) User(ctx context.Context, id string) (domain.User, error) {
	return scanUser(d.Pool.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE id=$1", id))
}
func (d *DB) UserLogin(ctx context.Context, login string) (domain.User, error) {
	return scanUser(d.Pool.QueryRow(ctx, "SELECT "+userCols+" FROM users WHERE lower(username)=lower($1) OR lower(email)=lower($1)", login))
}
func (d *DB) Users(ctx context.Context) ([]domain.User, error) {
	rows, e := d.Pool.Query(ctx, "SELECT "+userCols+" FROM users ORDER BY username LIMIT 1000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.User{}
	for rows.Next() {
		u, e := scanUser(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (d *DB) CreateUser(ctx context.Context, u domain.User) error {
	env, _ := json.Marshal(u.Environments)
	_, e := d.Pool.Exec(ctx, "INSERT INTO users(id,username,email,password_hash,role,enabled,environments,mfa_required,force_password,service) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)", u.ID, u.Username, u.Email, u.PasswordHash, u.Role, u.Enabled, env, u.MFARequired, u.ForcePassword, u.Service)
	return e
}
func (d *DB) Host(ctx context.Context, id string) (h domain.Host, e error) {
	var b []byte
	e = d.Pool.QueryRow(ctx, "SELECT document,secret_id FROM hosts WHERE id=$1", id).Scan(&b, &h.SecretID)
	if e == nil {
		e = json.Unmarshal(b, &h)
	}
	return
}
func (d *DB) Hosts(ctx context.Context) ([]domain.Host, error) {
	rows, e := d.Pool.Query(ctx, "SELECT document,secret_id FROM hosts ORDER BY document->>'name' LIMIT 2000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Host{}
	for rows.Next() {
		var b []byte
		var h domain.Host
		if e = rows.Scan(&b, &h.SecretID); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &h); e != nil {
			return nil, e
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
func (d *DB) SaveHost(ctx context.Context, h domain.Host) error {
	b, e := json.Marshal(h)
	if e != nil {
		return e
	}
	_, e = d.Pool.Exec(ctx, "INSERT INTO hosts(id,document,secret_id) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET document=$2,secret_id=$3,updated_at=now()", h.ID, b, h.SecretID)
	return e
}

// ObserveHost updates collector-owned fields without overwriting an administrator's
// concurrent credential, fingerprint, environment or enabled changes.
func (d *DB) ObserveHost(ctx context.Context, h domain.Host) error {
	b, e := json.Marshal(map[string]any{"facts": h.Facts, "state": h.State, "last_seen": h.LastSeen})
	if e != nil {
		return e
	}
	_, e = d.Pool.Exec(ctx, `UPDATE hosts SET document=document||$2::jsonb,updated_at=now() WHERE id=$1 AND secret_id=$3 AND document->>'hostname'=$4 AND document->>'fingerprint'=$5`, h.ID, b, h.SecretID, h.Hostname, h.Fingerprint)
	return e
}
func (d *DB) Resource(ctx context.Context, id string) (r domain.Resource, e error) {
	var b []byte
	e = d.Pool.QueryRow(ctx, "SELECT document FROM resources WHERE id=$1", id).Scan(&b)
	if e == nil {
		e = json.Unmarshal(b, &r)
	}
	return
}
func (d *DB) Resources(ctx context.Context) ([]domain.Resource, error) {
	rows, e := d.Pool.Query(ctx, "SELECT document FROM resources ORDER BY document->>'name' LIMIT 10000")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Resource{}
	for rows.Next() {
		var b []byte
		var r domain.Resource
		if e = rows.Scan(&b); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &r); e != nil {
			return nil, e
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
func (d *DB) UpsertResources(ctx context.Context, host, provider string, resources []domain.Resource) error {
	tx, e := d.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	// Serialize inventories for a provider so a slower concurrent refresh cannot interleave writes.
	if _, e = tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", host+"/"+provider); e != nil {
		return e
	}
	ids := make([]string, 0, len(resources))
	for _, r := range resources {
		r.ID = security.HashToken(host + "/" + provider + "/" + r.ExternalID)[:32]
		ids = append(ids, r.ID)
		r.HostID = host
		r.Provider = provider
		r.UpdatedAt = time.Now().UTC()
		r.DiscoveredAt = r.UpdatedAt
		b, e := json.Marshal(r)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, "INSERT INTO resources(id,host_id,provider,external_id,document) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET document=$5,updated_at=now()", r.ID, host, provider, r.ExternalID, b); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE resources SET document=jsonb_set(jsonb_set(jsonb_set(document,'{state}','"missing"'),'{health}','"unknown"'),'{capabilities}','[]'),updated_at=now() WHERE host_id=$1 AND provider=$2 AND NOT(id=ANY($3::text[]))`, host, provider, ids)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (d *DB) Objects(ctx context.Context, kind string) ([]domain.Object, error) {
	rows, e := d.Pool.Query(ctx, "SELECT id,kind,name,environment,data,created_at,updated_at FROM objects WHERE kind=$1 ORDER BY created_at DESC LIMIT 2000", kind)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []domain.Object{}
	for rows.Next() {
		var o domain.Object
		var b []byte
		if e = rows.Scan(&o.ID, &o.Kind, &o.Name, &o.Environment, &b, &o.CreatedAt, &o.UpdatedAt); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(b, &o.Data); e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (d *DB) Object(ctx context.Context, kind, id string) (o domain.Object, e error) {
	var b []byte
	e = d.Pool.QueryRow(ctx, "SELECT id,kind,name,environment,data,created_at,updated_at FROM objects WHERE id=$1 AND kind=$2", id, kind).Scan(&o.ID, &o.Kind, &o.Name, &o.Environment, &b, &o.CreatedAt, &o.UpdatedAt)
	if e == nil {
		e = json.Unmarshal(b, &o.Data)
	}
	return
}
func (d *DB) SaveObject(ctx context.Context, o domain.Object) error {
	b, e := json.Marshal(o.Data)
	if e != nil {
		return e
	}
	_, e = d.Pool.Exec(ctx, "INSERT INTO objects(id,kind,name,environment,data) VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET name=$3,environment=$4,data=$5,updated_at=now() WHERE objects.kind=$2", o.ID, o.Kind, o.Name, o.Environment, b)
	return e
}
func AuditTx(ctx context.Context, tx pgx.Tx, a domain.Event) error {
	if a.Metadata == nil {
		a.Metadata = map[string]any{}
	}
	// Normalize typed structs and maps before recursively removing sensitive fields.
	raw, e := json.Marshal(a.Metadata)
	if e != nil {
		return e
	}
	var normalized any
	if e = json.Unmarshal(raw, &normalized); e != nil {
		return e
	}
	b, e := json.Marshal(security.SanitizeValue(normalized))
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, "INSERT INTO audit(actor,actor_type,source_ip,request_id,host_id,resource_id,environment,action,decision,result,metadata) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)", a.Actor, a.ActorType, a.SourceIP, a.RequestID, a.HostID, a.ResourceID, a.Environment, a.Action, a.Decision, security.Redact(a.Result), b)
	if e != nil {
		return e
	}
	payload, _ := json.Marshal(map[string]any{"action": a.Action, "resource_id": a.ResourceID, "host_id": a.HostID, "decision": a.Decision})
	_, e = tx.Exec(ctx, "INSERT INTO events(topic,environment,payload) VALUES($1,$2,$3)", a.Action, a.Environment, payload)
	return e
}
func (d *DB) Audit(ctx context.Context, a domain.Event) error {
	tx, e := d.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = AuditTx(ctx, tx, a); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (d *DB) RateLimit(ctx context.Context, key string, max int, window time.Duration) (bool, error) {
	var count int
	e := d.Pool.QueryRow(ctx, "INSERT INTO auth_limits(key,count,reset_at) VALUES($1,1,now()+$2::interval) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN auth_limits.reset_at<now() THEN 1 ELSE auth_limits.count+1 END,reset_at=CASE WHEN auth_limits.reset_at<now() THEN now()+$2::interval ELSE auth_limits.reset_at END RETURNING count", key, fmt.Sprintf("%f seconds", window.Seconds())).Scan(&count)
	return count <= max, e
}
