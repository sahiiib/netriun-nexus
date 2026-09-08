.PHONY: run dev-deps build test vet up down

# Run the Go process on the host while PostgreSQL and Redis stay in containers.
# LOCAL_PORT, POSTGRES_PORT and REDIS_PORT may be overridden when their defaults
# are already in use. RUN_DATABASE_URL/RUN_REDIS_URL can target external services.
run: dev-deps
	@set -a; . ./.env; set +a; \
	docker compose stop app >/dev/null 2>&1 || true; \
	local_port="$${LOCAL_PORT:-8080}"; \
	db_port="$${POSTGRES_PORT:-15432}"; \
	redis_port="$${REDIS_PORT:-16379}"; \
	DATABASE_URL="$${RUN_DATABASE_URL:-postgres://ccmp:$${POSTGRES_PASSWORD}@127.0.0.1:$${db_port}/ccmp?sslmode=disable}" \
	REDIS_URL="$${RUN_REDIS_URL:-redis://:$${REDIS_PASSWORD}@127.0.0.1:$${redis_port}/0}" \
	HTTP_ADDR=":$${local_port}" \
	APP_ORIGIN="http://localhost:$${local_port}" \
	COOKIE_SECURE=false \
	go run ./cmd/nexus
dev-deps:
	docker compose up -d postgres redis
build:
	go build -trimpath -o bin/nexus ./cmd/nexus
test:
	go test -race ./...
vet:
	go vet ./...
up:
	docker compose up --build -d
down:
	docker compose down
