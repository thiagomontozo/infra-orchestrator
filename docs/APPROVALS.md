# Aprovações

Produção exige aprovação para alterações, inclusive criação de containers. Policies podem exigir aprovação em outros ambientes. ASSISTED sempre exige revisão humana. ADMIN não aprova a própria operação: use outra pessoa autorizada, com role APPROVER ou permissão correspondente.

Em Aprovações, revise alvo, ação, ambiente, risco, parâmetros e motivo; aprove ou rejeite com justificativa. A decisão é transacional e auditada. O worker verifica novamente a autorização do aprovador e solicitante. Mudanças posteriores em ambiente, conexão ou identidade do recurso exigem reenvio.

Não há aprovação por e-mail nem aprovação de múltiplas etapas nesta versão. Notificações encaminham eventos, não credenciais de aprovação. O estado aprovado é enfileirado na mesma transação; não depende do navegador permanecer aberto.
