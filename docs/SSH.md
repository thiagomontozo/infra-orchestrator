# SSH

O worker abre conexões com `golang.org/x/crypto/ssh`. O cadastro aceita chave privada, agent do processo ou senha opcional. Chaves e senhas ficam no SecretProvider. Prefira um usuário exclusivo e chave Ed25519; nunca cadastre root por conveniência.

Em Hosts, informe endereço, porta, usuário, método, ambiente e credencial. Obter fingerprint realiza somente handshake e encerra antes de autenticar. Compare o SHA256 com `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` obtido por console/canal confiável. Confirmar um valor obtido pela mesma rede, sem comparação externa, não elimina MITM inicial.

O executor verifica fingerprint persistida ou `SSH_KNOWN_HOSTS`. Não existe opção para ignorar a identidade. Mudanças exigem atualizar o cadastro e submeter novamente operações pendentes. Timeout de conexão e comando são configuráveis; cancelamento fecha a conexão. A concorrência é limitada por worker e pelo semáforo SSH. Não há pool de conexões de longa duração nesta versão.

Permissões remotas dependem do runtime. O grupo Docker equivale, na prática, a administração do host: use máquinas e contas dedicadas. Para systemd, prefira regras Polkit restritas aos serviços gerenciados. O programa não altera sudoers nem envia sudo arbitrário. Recursos sem permissão retornam erro auditável. Consulte [BASTION](BASTION.md) e [SECURITY](SECURITY.md).
