CREATE TABLE IF NOT EXISTS users (
 id text PRIMARY KEY, username text NOT NULL, email text NOT NULL, password_hash text NOT NULL DEFAULT '',
 role text NOT NULL CHECK(role IN ('ADMIN','OPERATOR','VIEWER','AUDITOR','APPROVER')), enabled boolean NOT NULL DEFAULT true,
 environments jsonb NOT NULL DEFAULT '["development"]', mfa_required boolean NOT NULL DEFAULT false,
 mfa_secret text NOT NULL DEFAULT '', mfa_last bigint NOT NULL DEFAULT -1, force_password boolean NOT NULL DEFAULT false,
 service boolean NOT NULL DEFAULT false, last_login timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
 external_subject text UNIQUE
);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_ci ON users(lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_ci ON users(lower(email));
CREATE TABLE IF NOT EXISTS sessions (
 id text PRIMARY KEY, user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash text NOT NULL UNIQUE,
 csrf_hash text NOT NULL, ip text NOT NULL, user_agent text NOT NULL, method text NOT NULL,
 mfa boolean NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), last_seen timestamptz NOT NULL DEFAULT now(),
 expires_at timestamptz NOT NULL, revoked_at timestamptz
);
CREATE TABLE IF NOT EXISTS api_tokens (
 id text PRIMARY KEY,user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,name text NOT NULL,
 token_hash text NOT NULL UNIQUE,scopes jsonb NOT NULL,expires_at timestamptz NOT NULL,revoked_at timestamptz,created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS auth_limits (key text PRIMARY KEY, count integer NOT NULL, reset_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS oidc_states (hash text PRIMARY KEY,nonce text NOT NULL,verifier text NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS secrets (id text PRIMARY KEY,ciphertext text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS hosts (id text PRIMARY KEY,document jsonb NOT NULL,secret_id text NOT NULL DEFAULT '',updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS resources (
 id text PRIMARY KEY,host_id text NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,provider text NOT NULL,external_id text NOT NULL,
 document jsonb NOT NULL,updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(host_id,provider,external_id)
);
CREATE TABLE IF NOT EXISTS objects (id text PRIMARY KEY,kind text NOT NULL,name text NOT NULL,environment text NOT NULL DEFAULT '',data jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS objects_kind_idx ON objects(kind);
CREATE TABLE IF NOT EXISTS operations (
 id text PRIMARY KEY, requester text NOT NULL REFERENCES users(id),resource_id text NOT NULL REFERENCES resources(id),host_id text NOT NULL REFERENCES hosts(id),
 action text NOT NULL,parameters jsonb NOT NULL DEFAULT '{}',environment text NOT NULL,risk text NOT NULL,
 state text NOT NULL CHECK(state IN ('pending','waiting_approval','approved','queued','running','succeeded','failed','cancelled','timeout','rejected')),
 request_id text NOT NULL,approval_by text NOT NULL DEFAULT '',reason text NOT NULL DEFAULT '',agent boolean NOT NULL DEFAULT false,agent_mode text NOT NULL DEFAULT '',auth_mfa boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(),started_at timestamptz,finished_at timestamptz,result text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',
 lease_until timestamptz,worker_id text NOT NULL DEFAULT '',idempotency_key text,request_hash text NOT NULL,
 batch_id text NOT NULL DEFAULT '',batch_index integer NOT NULL DEFAULT 0,
 UNIQUE(requester,idempotency_key)
);
CREATE INDEX IF NOT EXISTS operations_queue_idx ON operations(created_at) WHERE state='queued';
CREATE INDEX IF NOT EXISTS operations_batch_idx ON operations(batch_id,batch_index);
CREATE TABLE IF NOT EXISTS batches (id text PRIMARY KEY,requester text NOT NULL REFERENCES users(id),batch_size integer NOT NULL,failure_threshold integer NOT NULL,continue_on_error boolean NOT NULL,health_timeout integer NOT NULL DEFAULT 60,created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS resource_leases (resource_id text PRIMARY KEY,operation_id text NOT NULL,worker_id text NOT NULL,expires_at timestamptz NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id bigserial PRIMARY KEY,timestamp timestamptz NOT NULL DEFAULT now(),actor text NOT NULL DEFAULT '',actor_type text NOT NULL DEFAULT 'user',source_ip text NOT NULL DEFAULT '',request_id text NOT NULL DEFAULT '',host_id text NOT NULL DEFAULT '',resource_id text NOT NULL DEFAULT '',environment text NOT NULL DEFAULT '',action text NOT NULL,decision text NOT NULL DEFAULT '',result text NOT NULL DEFAULT '',metadata jsonb NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS events (id bigserial PRIMARY KEY,topic text NOT NULL,environment text NOT NULL DEFAULT '',payload jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT now(),published_at timestamptz);
CREATE TABLE IF NOT EXISTS schedule_runs (schedule_id text NOT NULL,scheduled_at timestamptz NOT NULL,operation_id text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',PRIMARY KEY(schedule_id,scheduled_at));
CREATE OR REPLACE FUNCTION audit_immutable() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'audit is append-only'; END; $$ LANGUAGE plpgsql;
DROP TRIGGER IF EXISTS audit_immutable ON audit;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_immutable();
