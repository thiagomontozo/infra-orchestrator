# Matriz de implementação

Esta versão contém implementação executável, mas não deve ser tratada como certificação integral dos 125 grupos de requisitos. A distinção abaixo faz parte da entrega. O resultado observado de cada comando está em [TEST_RESULTS](TEST_RESULTS.md).

| Área | Implementação | Limites de validação/escopo |
|---|---|---|
| Go API + React | API versionada, dashboard, formulários e dados reais | Listagens limitadas, sem paginação completa |
| Auth/RBAC | Argon2id, sessões, CSRF, tokens, escopos por ambiente, cinco roles | Roles personalizadas não implementadas |
| MFA | TOTP com proteção de replay; exigência por usuário/policy | WebAuthn/passkeys não implementados; SSO com MFA local obrigatório bloqueado |
| OIDC/LDAP | OIDC discovery/PKCE/nonce/group mapping; LDAP TLS e grupos no login | Sem tenant corporativo de teste; sync LDAP ocorre no login |
| Secrets | AES-GCM local e Vault KV v2 | Sem Vault externo configurado; rotação automática de chave pendente |
| SSH | Chave/agent/senha, fingerprint/known_hosts, timeout, bastion | SSH/Docker exercitados em fixture real; bastion físico não homologado |
| Discovery | Hosts e adapters com inventário persistido | Algumas métricas específicas dependem de inspect/status; sem histórico próprio |
| Docker | Inventário, inspect/stats/logs, ciclo de vida, pull/create/start | Provisionamento, logs e restart foram exercitados em daemon isolado; private registries precisam de credenciais reais |
| Compose/Podman | Comandos estruturados e parsers | Compose requer arquivos existentes; criação de Podman novo pela UI não implementada |
| systemd | Descoberta, journalctl e ações fixas | Sem VM systemd completa no ambiente local |
| Kubernetes | kubectl remoto e kubeconfig cifrado/HTTPS | Sem cluster externo para validar RBAC/rollout; kubeconfig exec não permitido |
| Swarm | Inventário, scale/restart/logs e deploy de stack JSON | Sem cluster multi-node; não há rollback de stack garantido |
| Nomad | Jobs/allocations/groups/nodes, run/stop/restart/logs | Sem cluster/ACL/driver externo homologado |
| Supervisor/PM2 | Descoberta, ações e logs | Fixtures de parsing/comandos; sem daemons externos homologados |
| Operações | Fila PostgreSQL, leases, idempotência, recovery, aprovação | Falhas de rede podem deixar outcome desconhecido, sem retry cego |
| Lotes/rolling | Tamanho, concorrência, threshold e verificação de health | Health precisa ser conhecido pelo adapter; sem canary de tráfego externo |
| Scheduler | One-shot/cron/timezone e policy | Deployment agendado não conectado; reserva órfã exige reconciliação |
| Maintenance | Policies avaliam janelas por timezone/horário | Registro administrativo de janela não é automaticamente vinculado à policy |
| Deployments | Metadados/histórico, operação, Kubernetes/Nomad/Compose/Swarm | Não restaura banco/volumes; Compose utiliza arquivo já administrado |
| GitOps | Observação/diff de manifesto remoto e deployment revisado | Sem clone/assinaturas/reconciliador contínuo |
| Logs | Tail limitado, busca, pausa, download e atualização periódica | Não há agregador completo ou garantia de todas as linhas entre polls |
| Métricas/traces | Prometheus e OTLP, métricas Go/process/banco | Sem dashboards históricos/TSDB incorporados |
| Alertas | Regras locais persistidas e resolução | Sem PromQL/on-call/silenciamento avançado |
| Notificações | Webhook/SMTP STARTTLS/Slack/Teams, fila de entrega | Sem envio real a destinatários externos; entrega pelo menos uma vez |
| Incidentes | CRUD/status/timeline descritiva/referências/auditoria | Correlação automática e timeline navegável completa pendentes |
| LLM | Models/chat, timeout, limites e diagnóstico estruturado | Protocolo com servidor de teste; nenhum modelo real certificado |
| Agentes | Advisory/assisted/automação explícita por policy, três tools de restart | Catálogo completo de consultas estruturadas ainda não exposto |
| Prompt injection | Dados não confiáveis separados, validação de tools/alvo e policy | Sanitização textual não é DLP universal; regras customizáveis por tenant pendentes |
| Distribuição | Server/worker, PostgreSQL locks, Redis, NATS outbox | Compose não fornece HA do banco/bus; failover de datacenter não testado |
| Auditoria | Eventos persistidos, trigger append-only, operações/aprovações transacionais | Algumas alterações administrativas e seu audit usam transações separadas |
| Segurança | Validação de input, rede default-deny, crypto, cookies, manifests restritos | Não equivale a pentest externo ou garantia de ausência de vulnerabilidades |

Não há dados fictícios injetados na aplicação. Mocks e fixtures ficam nos testes. Nenhuma integração externa é apresentada como validada apenas porque seu código compila. O README e os documentos de cada módulo descrevem como configurar e homologar cada integração.
