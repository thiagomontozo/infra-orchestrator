# Adapters

O núcleo depende de `Adapter`: Name, Detect, Discover, Capabilities, Execute, Logs. `Registry` escolhe implementação pelo provider persistido. Adapters não recebem uma string shell do usuário. O CLI constrói somente comandos permitidos, valida identificadores/opções, limita saída e escapa cada argumento.

| Provider | Transporte | Inventário e operações |
|---|---|---|
| docker / podman | SSH CLI | Containers, status, inspect, stats, logs e ciclo de vida |
| dockercompose / podmancompose | SSH CLI | Projetos/serviços, up/down/start/stop/restart/recreate/logs |
| systemd | SSH CLI | Serviços, status, logs, start/stop/restart/reload |
| kubernetes | kubectl remoto | Workloads e ações fixas, rollout, logs, scale, rollback |
| kubernetes-api | HTTPS | Inventário, pods/logs, scale, restart, apply e snapshot rollback |
| swarm | Docker CLI | Serviços, stacks/nodes, scale, update/restart, inspect/logs |
| nomad | Nomad CLI | Jobs, groups/allocations/nodes, run/stop/restart/status/logs |
| supervisor / pm2 | SSH CLI | Processos e ações de ciclo de vida/logs |
| provisioning | Docker Engine via SSH | Pull, create e start estruturados |

Consulte a matriz [STATUS](STATUS.md) para limites e evidência de execução. Capabilities são filtradas pelo backend conforme recurso e permissões; o frontend usa essa lista. Novo adapter exige parser/fixtures, validação de parâmetros, mapeamento RBAC, documentação e teste real quando disponível. Não basta adicionar um botão.
