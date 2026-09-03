# Podman

O adapter detecta o executável do usuário SSH e lê containers com JSON. Start, stop, restart, inspect, stats e logs usam comandos fixos. Podman rootless requer o mesmo usuário proprietário dos containers. `podman-compose` precisa estar instalado para projetos Compose.

Não há troca automática de usuário, acesso ao socket Docker local ou sudo genérico. A criação de novos containers pela API de provisionamento é específica do Docker nesta versão; Podman gerencia recursos existentes. Parsers têm fixtures, mas a execução em um host Podman externo não é considerada testada sem o relatório correspondente.
