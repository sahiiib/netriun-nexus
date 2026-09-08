#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")/.."
if [ -e .env ]; then
  echo '.env already exists; refusing to overwrite it.' >&2
  exit 1
fi
umask 077
database_password=$(openssl rand -hex 24)
redis_password=$(openssl rand -hex 24)
admin_password=$(openssl rand -hex 16)
encryption_key=$(openssl rand -base64 32)
cat > .env <<EOF
HTTP_ADDR=:8080
LOCAL_PORT=8080
POSTGRES_PORT=15432
REDIS_PORT=16379
APP_ORIGIN=http://localhost:8080
COOKIE_SECURE=false
TRUSTED_PROXY_CIDRS=
DATABASE_URL=postgres://ccmp:${database_password}@localhost:5432/ccmp?sslmode=disable
REDIS_URL=redis://:${redis_password}@localhost:6379/0
POSTGRES_PASSWORD=${database_password}
REDIS_PASSWORD=${redis_password}
ENCRYPTION_KEY=${encryption_key}
ADMIN_USERNAME=admin
ADMIN_PASSWORD=${admin_password}
EOF
echo 'Created .env with independent random passwords and an encryption key.'
echo 'Read ADMIN_PASSWORD in .env to sign in as admin.'
