# Operation Engine

Toda mutação remota segue autenticação → RBAC → policy → aprovação quando necessária → fila durável → worker → adapter. Solicitações exigem recurso, ação estruturada, parâmetros, justificativa e Idempotency-Key. Reutilizar a chave com conteúdo diferente é rejeitado.

Estados persistidos: queued, waiting_approval, running, succeeded, failed, rejected, cancelled e timeout. Pending/approved são transições conceituais consolidadas na transação de criação/aprovação; não existe uma janela em memória na qual a ação pode escapar à política. Eventos registram criação, aprovação, início e conclusão.

Antes da execução, o worker relê usuário, token, permissões, política e aprovador. Um hash vincula o pedido ao endereço, usuário, credencial referenciada, fingerprint, bastion e identidade do recurso. Mudança exige novo pedido. Leases no PostgreSQL impedem ações concorrentes no mesmo recurso. Operação órfã ou timeout não é repetido e retém bloqueio para reconciliação administrativa.

Cancelamento de comando remoto não garante desfazer efeitos. Abra o estado real do recurso antes de reconciliar. A API `POST /resources/{id}/reconcile` exige ADMIN, confirmação e motivo, e libera somente lease vencida após verificação externa. Não use reconciliação como botão de repetir cegamente.

Lotes admitem até 500 recursos, batch_size de 1 a 20, failure_threshold e continue_on_error. O lote só pode executar após a criação completa. Grupos sucessivos aguardam os anteriores; operações de restart/reload/up/recreate/scale/deploy/run verificam health antes de avançar, por até 60 segundos. Health desconhecido interrompe o avanço. Cada recurso continua passando por RBAC/policy.
