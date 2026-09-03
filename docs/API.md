# API

Base `/api/v1`; contrato em [openapi.yaml](openapi.yaml), servido em `/api/v1/openapi`. Autenticação por cookie HttpOnly ou Bearer token com hash persistido/scopes/expiração. Mutação por cookie requer Origin correspondente a PUBLIC_ORIGIN e X-CSRF-Token igual ao cookie io_csrf. Nunca coloque token em query string.

Operations, batches, provisioning e deployments usam Idempotency-Key. Respostas incluem X-Request-ID. Falhas usam JSON `{ "error": "..." }`. Autorização sempre ocorre no servidor; IDs fornecidos pelo cliente não autorizam acesso.

Grupos: auth, users, roles, sessions, tokens, hosts, kubernetes/clusters, resources, operations, deployments, schedules, policies, maintenance-windows, host-groups, environments, alerts, incidents, registries, notifications, gitops, llm/providers, agents, recommendations, audit, settings e dashboard. Objetos administrativos compartilham CRUD por kind validado. Approvals são operações waiting_approval e ações `/operations/{id}/approve`.

SSE `/events` envia eventos persistidos e aceita Last-Event-ID. Listagens têm limites (operações 500, recursos 10000, hosts 2000, objetos 2000); paginação cursor completa é uma limitação conhecida. Logs tail máximo 2000 linhas. Nenhuma rota oferece shell remoto genérico.
