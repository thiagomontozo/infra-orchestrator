# Desenvolvimento

Requisitos: Go 1.26.6+, Node 24, npm, Docker Compose e Git. `go mod download`; em web, `npm ci`. Gere `.env` com bootstrap e carregue as variáveis no processo. Compile `go build ./cmd/server`, `go build ./cmd/worker` e `go build ./cmd/cli`.

`go run ./cmd/cli migrate` aplica migrations. `go run ./cmd/cli admin create --username nome --email email` faz bootstrap. `go run ./cmd/server` serve API e web/dist. `npm run dev` usa Vite com proxy para API; PUBLIC_ORIGIN deve corresponder à origem usada pelo navegador.

Pastas internal separam identidade, segurança, storage, executores, adapters, operações, scheduler, observabilidade e agentes. Use context.Context, saídas limitadas, transações para estados críticos e testes de autorização. Não introduza endpoint que contorne o Operation Engine. Novas integrações precisam de implementação real e fixtures claramente identificadas.

`gofmt -w cmd internal migrations`, `go vet ./...`, `go test ./...`; frontend `npm run lint`, `npm test`, `npm run build`. No Windows, antivírus pode impedir remoção de executáveis temporários; `go test -work` retém a pasta temporária sem enfraquecer segurança. Não desative antivírus para obter teste verde.
