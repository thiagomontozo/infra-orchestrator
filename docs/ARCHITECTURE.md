# Arquitetura

O núcleo implementa módulos Go pequenos sobre `net/http` e pgx. Adapters e executors não conhecem a interface web. O modelo de recursos carrega capabilities calculadas no backend, e a UI mostra somente ações retornadas e permitidas pelo RBAC.

## Fronteiras

- `config`: valida ambiente, origem HTTPS, chave de criptografia e timeouts.
- `domain`: modelos persistidos e principal autenticado.
- `auth`, `rbac`, `policy`, `security`, `secrets`: identidade, escopos, decisão, criptografia e egress.
- `store`: PostgreSQL, migrations transacionais e interfaces de inventário.
- `executor`: transporte SSH, bastion e túnel para socket Docker; sem endpoint público de comandos.
- `adapters`: descoberta, parsers, capabilities e operações por runtime; Kubernetes também possui cliente HTTPS nativo.
- `operations`: autorização, idempotência, aprovações, fila e workers com leases.
- `discovery`, `observability`, `events`, `notifications`, `scheduler`: atualização de inventário e automação determinística.
- `llm`, `agent`: protocolo OpenAI-compatible, contexto limitado, diagnósticos tipados e tools permitidas.
- `api`: contratos HTTP e escopo por ambiente em todas as rotas protegidas.

## Modelo de dados

Tabelas relacionais: `users`, `sessions`, `api_tokens`, `hosts`, `resources`, `operations`, `batches`, `resource_leases`, `audit`, `events`, `secrets`, `schedule_runs`, `notification_deliveries`, `auth_limits`, `login_failures`, `oidc_states` e `schema_migrations`.

`hosts` e `resources` possuem documentos JSONB com chaves relacionais para inventário extensível. Configurações como políticas, providers, incidentes, schedules e deployments usam `objects(kind,id,environment,data)`, com validação específica na API. JSONB não permite entrada de SQL: valores usam parâmetros pgx. Referências a secrets ficam fora das representações públicas.

## Decisões

A fila de comandos usa PostgreSQL `FOR UPDATE SKIP LOCKED` e leases por recurso. Isso permite persistir operação, auditoria e evento na mesma transação. NATS distribui eventos; não é necessário coordenar duas transações para aceitar um comando. Redis é opcional para limites de API e não armazena o único estado de segurança.

Múltiplos processos podem executar API e workers. Advisory locks elegem uma instância para cada ciclo exclusivo de scheduler, collector, agente e dispatcher. Migrations também adquirem lock transacional.

O projeto utiliza uma estrutura mais compacta que os diretórios sugeridos: evitar módulos vazios mantém as fronteiras verificáveis. Integrações externas não validadas são listadas em STATUS.md.
