# RBAC

ADMIN tem as permissões administrativas. OPERATOR pode operar recursos no seu escopo, criar containers, realizar deployments, gerir schedules e incidentes. VIEWER lê inventário/logs. AUDITOR acrescenta auditoria. APPROVER acrescenta aprovação e auditoria. Papéis fixos estão em `internal/rbac/rbac.go`; `/roles` retorna as permissões.

Cada usuário possui lista `environments`. `*` significa todos os ambientes. Fora de ADMIN, uma operação precisa satisfazer tanto a permissão quanto o escopo. Tokens não herdam wildcard: scopes explícitos são intersectados com as permissões da conta de serviço. O backend relê o usuário e o token no worker, verificando revogação.

Recursos são lidos pelo ambiente atual do host, e não somente pela cópia existente no inventário. Operações são revalidadas no momento da execução; mudança do ambiente provoca rejeição e nova submissão. Políticas nunca concedem permissão ausente no RBAC.

Não há editor de papéis personalizados nesta versão. Alterações de papéis fixos exigem revisão de código e testes. A UI reflete o RBAC por conveniência; todos os endpoints aplicam autorização no servidor.
