# Alertas e notificações

Regras locais detectam host indisponível, recursos unhealthy/failed, uso elevado de disco/memória e excesso de reinícios a partir do inventário. Alertas são persistidos e resolvidos quando a condição observada desaparece. A LLM não é necessária para detectar essas condições.

Notifications oferece webhook, Slack, Teams e e-mail. Webhooks usam rede permitida, JSON e timeout; e-mail exige STARTTLS e valida certificado. Cadastre endpoints/credenciais na seção apropriada. Eventos são entregues por dispatcher durável com histórico, backoff e até cinco tentativas. Em falha após envio e antes do registro, pode ocorrer duplicação: consumidores de webhook devem deduplicar event_id.

Não há entrega externa comprovada sem configurar um destinatário real. CPU sustentada, regras PromQL, silenciamento avançado e escalonamento on-call ainda não são parte do motor local.
