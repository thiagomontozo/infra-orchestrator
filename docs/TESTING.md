# Testes

Unitários: `go test ./...`; frontend `npm ci && npm run lint && npm test && npm run build` em web. Integrações PostgreSQL são habilitadas por TEST_DATABASE_URL. Sem ela, testes marcados condicionais são pulados e não contam como integração aprovada.

Gere TEST_DB_PASSWORD aleatório, chaves SSH de teste e `.local/ssh-test/authorized_keys`. Suba `docker compose --env-file .local/test.env -f compose.test.yml --profile remote up --build -d`. O target Docker-in-Docker usa daemon próprio e porta SSH localhost:55222. Nunca monte o socket Docker da máquina. TEST_SSH_KEY aponta para a chave privada correspondente; `go test ./internal/executor -run TestRemoteDockerSSH -v` exercita SSH real, Docker real e rejeição de fingerprint alterada.

PostgreSQL de teste usa tmpfs. O serviço executado para testes de navegador deve usar banco separado do teste de concorrência, evitando que o worker consuma operações inseridas pela fixture. E2E_USERNAME/E2E_PASSWORD referem-se a administrador exclusivo de teste; E2E_BASE_URL aponta para servidor real. E2E_SSH_KEY habilita o fluxo remoto. `npm run test:e2e` executa Playwright. E2E_BROWSER_PATH permite usar um Chromium instalado.

Testes com mock LLM verificam contrato HTTP e validação de resposta/tools; não medem acurácia de diagnóstico de um modelo. Parsers de runtimes externos não provam execução nesses runtimes. RESULTADOS: consulte [TEST_RESULTS](TEST_RESULTS.md), que distingue execução, fixture, skip e limitações.

Scanners: `go run golang.org/x/vuln/cmd/govulncheck@latest ./...`, `npm audit`, gitleaks, Trivy imagens e SBOM. CI executa gates no Linux. Não remova testes para alterar o resultado; corrija causa ou registre infraestrutura ausente.
