#!/usr/bin/env sh
set -eu
test ! -e .env || { echo '.env exists; preserve the encryption key.' >&2; exit 1; }
umask 077
db_password=$(openssl rand -hex 24)
encryption_key=$(openssl rand -base64 32)
sed -e "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$db_password/" -e "s|^ENCRYPTION_KEY=.*|ENCRYPTION_KEY=$encryption_key|" .env.example > .env
echo 'Created .env. Configure PUBLIC_ORIGIN and OUTBOUND_ALLOWED_CIDRS before starting.'
