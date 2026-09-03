# Criar containers e microsserviços

1. Cadastre e descubra um host Docker com SSH verificado.
2. Em Containers → Criar container, selecione host, nome, imagem, portas, variáveis de ambiente, memória e CPU.
3. Para imagem privada, cadastre registry com servidor, usuário e token. Selecione-o no formulário; o registry da imagem precisa corresponder à credencial.
4. Informe o motivo e envie. A solicitação entra no mesmo Operation Engine e exige aprovação em produção.
5. Acompanhe pull/create/start em Operações. Ao terminar, o inventário Docker é atualizado e o container pode ser consultado/reiniciado pela interface.

Docker Hub público funciona sem credencial; GHCR e outros registries Docker/OCI compatíveis usam o domínio na imagem. O worker envia `X-Registry-Auth` diretamente à API do daemon pelo túnel SSH. Não persiste `docker login` no destino. A saída do daemon é limitada e erros de pull são propagados. A rede do daemon, inclusive acesso a registries, deve ser restrita no host: a allowlist de saída do control plane não é um firewall do Docker remoto.

O spec é cifrado com hash de integridade. Não admite mounts do host, dispositivos, privileged, host networking ou comando shell livre. Aplica limites de CPU/memória/PIDs, no-new-privileges e remove capabilities, habilitando apenas CHOWN, SETUID, SETGID e NET_BIND_SERVICE para imagens usuais. Recomenda-se UID não root e filesystem read-only quando a imagem suportar. Portas permitem bind local ou todas as interfaces; restrinja o firewall do host.

Após iniciar, verifica que o processo continua running. Isso não prova prontidão da aplicação; configure HEALTHCHECK na imagem e valide o endpoint do serviço. Pulls usam referências informadas: prefira digest imutável em produção. Não há catálogo comercial ou build de código fonte integrado.
