# Agent runtime

Modos: DISABLED, ADVISORY, ASSISTED e AUTOMATED_POLICY_CONTROLLED. ADVISORY produz diagnóstico e recomendação, sem executar. ASSISTED transforma solicitação de tool validada em operação que aguarda aprovação. Automação exige regra explícita allow_agent, escopo adequado e identidade autorizada; produção mantém aprovação por padrão.

Ferramentas de mutação implementadas: restart_container, restart_service e restart_deployment. O alvo deve ser exatamente o recurso analisado, o provider deve corresponder e a recomendação precisa existir. Leitura de estado/logs/contexto é construída pelo backend; não há ferramentas shell ou parâmetros de CLI livres.

Monitoramento periódico atende recursos/hosts/grupos/ambientes configurados e chama LLM somente diante de anomalia local. Requer service account e possui limites persistidos de chamadas/ações. O scheduler/monitor usa lock distribuído para evitar disparos duplicados. As ferramentas de consulta independentes listadas na proposta original ainda não estão todas expostas como um catálogo de tool calling; o diagnóstico usa contexto selecionado internamente.
