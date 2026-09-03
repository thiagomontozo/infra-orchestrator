# Docker e Compose

Descoberta usa `docker ps -a` e inspect limitado; ações incluem status, inspect, stats, start, stop, restart, pause/unpause e logs. O Docker daemon permanece remoto. Não exponha sua API TCP sem proteção: o provisionamento encaminha o socket Unix por SSH verificado.

Compose é descoberto por `docker compose ls` e `ps`; suporta projetos e serviços. Caminhos/nomes vêm do inventário e são validados, nunca de um campo shell. Up, down e recreate são operações sujeitas a policy; produção exige aprovação. Arquivos Compose precisam estar presentes e acessíveis no host. A criação de um novo serviço independente por imagem está em [PROVISIONING](PROVISIONING.md).

Saída/logs são limitados; inspect mascara Env e campos sensíveis. Stats é consulta pontual, não armazenamento histórico. Consulte a [API oficial do Docker](https://docs.docker.com/reference/api/engine/version/v1.48/) para o protocolo de pull e autenticação de registry.
