# Scheduler

Cadastre Schedules com resource_id, action, parameters, motivo e run_at RFC3339 ou expressão cron de cinco campos, além de timezone IANA. As ações agendáveis são restart/start/stop/reload/scale. Cadastro de deployment agendado ainda não está conectado ao scheduler.

O scheduler utiliza lock PostgreSQL e `schedule_runs` único por schedule/instante. Cada disparo chama o Operation Engine com chave idempotente, relendo permissões e policies. Desativar/remover autorização do usuário impede a execução. Use service accounts com tokens/scopes para automação externa.

Instâncias usam o relógio e timezone configurados; sincronize NTP. Uma falha entre reserva do disparo e criação da operação pode exigir reconciliação do schedule_run. Não há replay automático ilimitado de horários perdidos nem garantia exactly-once sobre infraestrutura remota.
