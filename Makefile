.PHONY: build test lint dev up down migrate admin security
build:
	go build -o bin/server ./cmd/server
	go build -o bin/worker ./cmd/worker
	go build -o bin/infra-orchestrator ./cmd/cli
	cd web && npm ci && npm run build
test:
	go test ./...
	cd web && npm test
lint:
	test -z "$$(gofmt -l cmd internal migrations)"
	go vet ./...
	cd web && npm run lint
dev:
	docker compose -f compose.yml -f compose.dev.yml up --build -d
up:
	docker compose up --build -d
down:
	docker compose down
migrate:
	go run ./cmd/cli migrate
admin:
	go run ./cmd/cli admin create --username "$(USER)" --email "$(EMAIL)"
security:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
	cd web && npm audit --audit-level=high
