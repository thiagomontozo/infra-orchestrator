#!/usr/bin/env bash
set -euo pipefail
set -a
. .local/test.env
set +a
docker exec infra-orchestrator-test-postgres-1 psql -U orchestrator -d postgres -c 'CREATE DATABASE browser_acceptance OWNER orchestrator'
export DATABASE_URL="postgres://orchestrator:$TEST_DB_PASSWORD@127.0.0.1:55432/browser_acceptance?sslmode=disable"
export ENCRYPTION_KEY="$(openssl rand -base64 32)"
export APP_ENV=test PUBLIC_ORIGIN=http://127.0.0.1:18080 HTTP_ADDRESS=127.0.0.1:18080
export OUTBOUND_ALLOWED_CIDRS=127.0.0.0/8 E2E_BASE_URL=$PUBLIC_ORIGIN
export E2E_USERNAME=ci-admin E2E_PASSWORD="$(openssl rand -hex 24)"
export E2E_SSH_KEY="$(cat .local/ssh-test/test_key)"
export E2E_SSH_FINGERPRINT="$(docker exec infra-orchestrator-test-ssh-target-1 ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')"
printf '%s\n' "$E2E_PASSWORD" | .local/bin/infra-orchestrator admin create --username "$E2E_USERNAME" --email ci@example.test --password-stdin
.local/bin/server > .local/e2e-server.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
for i in $(seq 1 30); do curl --fail --silent "$E2E_BASE_URL/readyz" >/dev/null && break; sleep 1; done
curl --fail --silent "$E2E_BASE_URL/readyz" >/dev/null
cd web
npx playwright install --with-deps chromium
npm run test:e2e
