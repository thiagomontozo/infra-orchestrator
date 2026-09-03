# Resultados de validação

Data da última execução local: 2026-09-03. Ambiente: Windows 11, Go 1.26.6, Node 24, Docker Desktop 29.7.2, PostgreSQL 17.6, Redis 7.4.5, NATS 2.11.8 e um host SSH/Docker isolado em Docker-in-Docker. Os dados de teste, chaves e variáveis ficaram em `.local`, que não é versionado.

| Gate | Resultado | Evidência |
|---|---|---|
| Formatação Go | aprovado | `gofmt -w` aplicado; `git diff --check` sem erros |
| Vet Go | aprovado | `go vet ./cmd/... ./internal/... ./migrations/...` sem diagnóstico |
| Testes Go | aprovado | suíte completa do código da plataforma passou com `go test -count=1 -p 2 ./cmd/... ./internal/... ./migrations/...` |
| Auth/API integração | aprovado | login, cookies CSRF, renew, logout, RBAC/BOLA e produção negada foram exercitados contra PostgreSQL real |
| SSH | aprovado | handshake real, comando allowlisted e fingerprint inválida rejeitada |
| Docker remoto | aprovado | API Engine via socket Unix encaminhado por SSH; `docker info` e operação real passaram |
| Operations/PostgreSQL | aprovado | idempotência, autoaprovação negada, lock concorrente, recovery e rolling threshold |
| Segurança | aprovado | Argon2id, AES-GCM/AAD, TOTP/replay, SSRF, sanitização e manifestos host-escape |
| Adapters | aprovado | fixtures/parsers e validação para Docker, Compose, Podman, systemd, Kubernetes, Nomad, Swarm, Supervisor e PM2 |
| LLM | aprovado com mock | endpoints compatíveis OpenAI e tool injection/mismatch bloqueados |
| Frontend lint | aprovado | `npm run lint` |
| Frontend unit | aprovado | 2 arquivos / 6 testes do Vitest |
| Frontend build | aprovado | `npm run build`, Vite 7.3.6 |
| E2E completo | aprovado | Playwright: 5/5 cenários em 1,3 min, contra PostgreSQL novo e host SSH/Docker isolado |
| E2E — host e container | aprovado | fingerprint confirmado, SSH, discovery, criação `nginx:alpine`, logs e restart reais |
| E2E — aprovação | aprovado | OPERATOR solicitou restart de produção; APPROVER distinto aprovou; worker executou e auditoria registrou a decisão |
| E2E — IA | aprovado com mock local | diagnóstico com evidência limitada, tool assistida aguardou aprovação e `bash` foi rejeitado com 403 |
| Backend image | aprovado | imagem `scratch` reconstruída; CLI `version` respondeu `0.1.0`; inclui CA e base de fusos horários |
| Frontend image | aprovado | `infra-orchestrator-frontend:local` reconstruída e `/healthz` respondeu 200 na rede de serviço do Compose |
| Docker Compose | aprovado | `docker compose --env-file .env -f compose.yml config --quiet` sem erro |
| Gitleaks | aprovado | snapshot de 152 arquivos versionáveis, incluindo conteúdo novo: nenhum vazamento; o scan staged será repetido antes de cada commit |
| govulncheck atualizado | aprovado | `golang.org/x/vuln/cmd/govulncheck@v1.7.0`: 0 vulnerabilidades alcançáveis; 1 achado em módulo requerido, sem chamada pelo código |
| Trivy | aprovado | imagens backend e frontend: 0 vulnerabilidades High/Critical corrigíveis, com `--ignore-unfixed` |
| SBOM | aprovado | documentos CycloneDX gerados localmente para backend e frontend; a CI os gera como artefatos |

`go test ./...` encontrou também um pacote sem testes dentro de uma dependência frontend instalada localmente (`web/node_modules/flatted/golang/pkg/flatted`), sem erro. A CI executa os testes Go antes de `npm ci`, impedindo essa descoberta incidental. A configuração final preserva `go test ./...` como pedido, e o Makefile oferece os mesmos comandos.

Os gates de publicação ainda pendentes são revisão do Git, commits e execução do workflow após o push público. Integrações Kubernetes, Nomad, Swarm, Podman, Supervisor, PM2, Vault, LDAP/OIDC, SMTP/Slack/Teams e registries privados possuem implementação e testes locais de contrato/fixtures quando aplicável, mas não foram homologadas contra serviços corporativos reais neste ambiente.
