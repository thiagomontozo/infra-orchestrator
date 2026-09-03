# systemd

Descoberta consulta `systemctl list-units` para serviços e interpreta estado load/active/sub. O adapter oferece status, start, stop, restart, reload e logs via journalctl com tail limitado. Serviços inexistentes/sem permissão retornam falha.

Use usuário SSH com leitura de journald e autorização Polkit específica para unidades que podem ser alteradas. A aplicação não configura permissões do sistema. O ambiente Docker de teste não executa um init systemd completo; parser e construção de comandos são testados localmente, e a integração real depende de uma VM Linux com systemd.
