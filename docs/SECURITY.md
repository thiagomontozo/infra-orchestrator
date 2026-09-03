# Segurança e modelo de ameaça

## Proteções implementadas

- Passwords Argon2id (64 MiB, 3 iterações, paralelismo 2, salt aleatório).
- Sessões opacas de 256 bits; somente hashes no banco; cookie HttpOnly, SameSite=Strict, Secure em produção; CSRF e comparação exata de Origin nas mutações.
- Tokens de API com hash, expiração, revogação, conta de serviço e scopes sem wildcard.
- Escopo por ambiente na leitura e revalidação de RBAC/policy no worker antes da execução.
- Aprovação obrigatória para mutações em produção; nenhuma autoaprovação do solicitante.
- SSH sem `InsecureIgnoreHostKey`: pin SHA256 ou known_hosts; bastion também verificado.
- AES-256-GCM com AAD por identificação, ou Vault KV v2. Chave mestra fora do banco.
- Destinos resolvidos no momento da conexão e IPs conferidos contra CIDRs explícitos; redirects bloqueados; metadata/link-local/multicast bloqueados mesmo com CIDR amplo.
- Queries SQL parametrizadas, limite de body, headers e saída remota; React escapa conteúdo e CSP bloqueia scripts externos.
- Outputs, logs, labels e annotations são dados não confiáveis. Redação e limites precedem chamadas LLM.
- Auditoria append-only por trigger e operações de transição auditadas.

## Fronteiras importantes

O administrador do banco pode remover triggers: configure um papel de runtime sem privilégios DDL para maior garantia e exporte auditoria para armazenamento externo imutável. O usuário Docker remoto precisa de acesso ao socket; essa permissão equivale a amplo controle do host. Prefira Docker rootless e hosts dedicados conforme sua política.

Kubeconfigs aceitam CA, token e certificado incorporados. Não executam `exec`, não leem arquivos arbitrários e não aceitam TLS inseguro. O RBAC do cluster e admission controllers continuam obrigatórios para limitar manifestos. Políticas do control plane não substituem controles do runtime.

Portas de dados não são publicadas no compose de produção. Frontend escuta em localhost para um proxy HTTPS. Não exponha `/metrics` ou o banco publicamente. O backend não confia em `X-Forwarded-For` enviado pelo cliente; atrás de proxy, o IP auditado pode ser o do proxy.

## Recovery

Lease expirado é resultado incerto. O comando não volta para a fila; o recurso fica bloqueado até reconciliação explícita com evidência administrativa. Interrupção de SSH não prova cancelamento do efeito remoto. Consulte OPERATIONS.md.

## Verificação

Testes cobrem injeção de argumentos, adulteração de recurso, RBAC, CSRF, TOTP replay, troca de ciphertext, SSRF, prompt injection e auditoria. `govulncheck` e `npm audit` não substituem pentest. O relatório registra versões e resultados realmente executados.

Reportar vulnerabilidade de forma privada ao mantenedor, sem publicar credenciais, dumps ou detalhes exploráveis em issues abertas.
