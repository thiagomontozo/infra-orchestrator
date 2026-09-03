# Alta disponibilidade e banco

PostgreSQL é a autoridade para users, sessions, api_tokens, auth_limits/login_failures, secrets, hosts, resources, objects, operations, batches, resource_leases, audit, events, schedule_runs e notification_deliveries. JSONB armazena documentos de inventário/configuração extensível; identidades, operações, locks e sessões possuem colunas/constraints relacionais. Migrations são embutidas e serializadas por advisory lock.

API e workers podem rodar separadamente. Use a mesma versão, banco, ENCRYPTION_KEY e configuração de rede. Claim usa SELECT FOR UPDATE SKIP LOCKED e lease por resource; heartbeat renova a cada 10 s, validade 45 s. Recovery não repete operação órfã, marca timeout e mantém lock para reconciliação. Scheduler/coletor/monitor/dispatchers usam locks PostgreSQL para tarefas exclusivas.

Redis é opcional para limitação compartilhada; autenticação mantém limites críticos no banco. NATS JetStream recebe uma outbox persistente, com ID de deduplicação e retenção limitada. Comandos são enfileirados no PostgreSQL, mantendo atomicidade entre operação, aprovação e audit. NATS indisponível não justifica replay destrutivo.

O Compose fornecido não é um cluster HA de PostgreSQL/Redis/NATS. Em produção, configure serviços redundantes, backups cifrados, restore testado, pool/conexões dimensionados, relógios sincronizados e monitoramento. Não houve ensaio de failover multi-datacenter. Exactly-once de efeitos SSH não é garantido por uma fila; outcomes desconhecidos exigem revisão humana.
