# Implantação

Execute bootstrap para gerar `.env` local sem senha padrão. Configure APP_NAME, APP_ENV, PUBLIC_ORIGIN HTTPS, ENCRYPTION_KEY e OUTBOUND_ALLOWED_CIDRS. Suba `docker compose up --build -d`. O frontend escuta somente localhost por padrão: publique por proxy TLS autenticando certificados válidos. `/healthz` indica processo vivo; `/readyz` verifica banco.

Crie o administrador: `docker compose exec server /app/infra-orchestrator admin create --username seu-admin --email admin@example.com`. A senha é solicitada sem eco. Não copie chaves/tokens para imagens ou Git. Monte known_hosts/agent socket apenas quando usados; para credenciais por chave, use o cadastro cifrado.

Backend/frontend usam usuário não root, filesystem read-only e privilégios removidos no Compose. Redes internas isolam banco/cache/bus. Volumes persistem PostgreSQL/Redis/NATS. Faça backup consistente do banco e da chave mestra separadamente. O PostgreSQL do Compose opera em rede interna; use TLS para conexões fora dessa rede e serviços gerenciados.

`EMBEDDED_WORKER=false` e serviço worker separam API de execução. Aumente workers/concurrency conforme capacidade SSH, banco e risco. Não compartilhe socket Docker do host com o control plane. O único container privilegiado está na fixture de integração isolada, nunca no Compose de produção.

CA corporativa pode ser fornecida ao build por secret `extra_ca`; não desligue validação TLS. Validar scanners não substitui homologar OIDC/LDAP/SMTP/Vault/Kubernetes/Nomad reais. Consulte STATUS antes de produção.
