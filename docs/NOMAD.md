# Nomad

O worker utiliza CLI Nomad do host SSH, com endereço/TLS/ACL configurados administrativamente nesse host. Descobre jobs e expande allocations/task groups/nodes quando a identidade tem acesso. Oferece status, run de job JSON validado, stop e restart de allocation. Logs são limitados e dependem da allocation selecionada.

O backend não aceita flags livres ou comandos Nomad. Job ID no documento precisa corresponder ao alvo; credenciais ACL não são fornecidas à LLM. Não há promessa de rollback sem histórico e artefato de implantação. Testes locais cobrem parsing e validação de comandos; um cluster Nomad real é necessário para homologar ACLs, drivers e comportamentos de rollout.
