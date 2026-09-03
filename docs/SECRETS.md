# Secrets

`internal/secrets.Provider` define Put/Get/Delete. O backend local cifra com AES-256-GCM, nonce aleatório e ID como dado autenticado. `ENCRYPTION_KEY` deve conter 32 bytes aleatórios em Base64, iguais em todas as instâncias. Preserve a chave fora do banco: perdê-la impede recuperar credenciais. Nunca altere-a sem um procedimento de recifragem e backup.

`SECRET_BACKEND=vault`, `VAULT_ADDR`, `VAULT_TOKEN` e `VAULT_MOUNT` habilitam Vault KV v2. A saída HTTP respeita a política de rede. Restrinja o token ao prefixo da aplicação. AWS Secrets Manager, Azure Key Vault e Kubernetes Secrets podem implementar a mesma interface; não possuem implementações nesta versão.

API não retorna chaves SSH, kubeconfigs, senhas, API keys, tokens de registry ou manifestos protegidos. Tokens da plataforma são mostrados uma vez e guardados como SHA-256. Variáveis de ambiente de containers e manifestos são cifrados, referenciados por ID e hash de integridade. APIs de leitura sanitizam campos sensíveis; nomes incomuns em logs livres podem exigir regras adicionais.
