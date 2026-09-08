# Autenticação

Login local aceita username ou e-mail com senha de pelo menos 12 bytes. Não há conta nem senha padrão. `infra-orchestrator admin create` lê senha sem eco e persiste somente Argon2id. `admin reset-password` revoga sessões e força a troca no próximo login.

`POST /api/v1/auth/login` exige Origin configurada. Retorna usuário, estado MFA e CSRF; os cookies de sessão e CSRF são emitidos pelo servidor. `POST /auth/renew` substitui os tokens e limita renovação a sete dias desde a criação. Logout revoga a sessão persistida. Desativar usuário ou alterar papel revoga suas sessões.

Limites de IP e identificador persistem em PostgreSQL; falhas acumulam bloqueio progressivo. Redis pode aplicar limites de uso autenticado. A ausência do Redis não remove controles persistidos de login.

## TOTP

`/auth/mfa/enroll` gera segredo apenas para uma sessão sem TOTP ativo. `/auth/mfa/verify` valida seis dígitos, confirma a configuração e revoga outras sessões. O contador aceito é persistido para impedir replay. A chave fica criptografada. MFA pode ser exigido por usuário ou por regras de role/ambiente. Passkeys/WebAuthn não estão implementados.

## OIDC

Configurar `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI`, `OIDC_SCOPES`, `OIDC_GROUP_CLAIM` e `OIDC_ROLE_MAPPING`. Callback usa state de uso único, nonce, PKCE S256, validação de issuer/audience/assinatura e e-mail verificado. Uma identidade externa não é vinculada automaticamente a uma conta local de mesmo e-mail.

Role mapping é JSON de grupo para ADMIN/OPERATOR/VIEWER/AUDITOR/APPROVER. Novos usuários externos começam sem escopo de ambientes; o administrador deve concedê-los. OIDC com MFA local obrigatório é bloqueado; não há fluxo híbrido OIDC+TOTP nesta versão. Imponha MFA no IdP e valide a política corporativa antes de conceder acesso. Nenhum claim MFA externo é aceito implicitamente.

## LDAP / AD

Dois modos, escolhidos pela configuração. A senha do usuário nunca é armazenada em nenhum deles.

**Active Directory (`LDAP_SERVER` + `LDAP_DOMAIN`)** — o próprio usuário faz o bind com `login@LDAP_DOMAIN`; não existe conta de serviço. O login é validado contra `^[a-zA-Z0-9._-]+$` antes de compor o bind, o que descarta injeção de LDAP. Autenticado o bind, o diretório é pesquisado em `LDAP_BASE_DN` — derivado do domínio quando não informado (`CORP.EXAMPLE.COM` → `DC=CORP,DC=EXAMPLE,DC=COM`) — com `(sAMAccountName=%s)`. São lidos `sAMAccountName`, `displayName`, `mail`, `objectGUID`, `physicalDeliveryOfficeName` e `thumbnailPhoto`. O `objectGUID` (binário mixed-endian do AD, normalizado para a forma canônica) é a chave estável da identidade: renomear a conta no diretório não cria um usuário novo. Sem `mail` no diretório o e-mail é derivado de `sAMAccountName@LDAP_DOMAIN`, pois a conta local é indexada por e-mail.

**Diretório genérico (`LDAP_URL` + `LDAP_BIND_DN`)** — bind de pesquisa restrito sobre LDAPS, filtro escapado, descoberta de DN e novo bind com a senha fornecida. O DN é a chave da identidade.

Transporte: `ldaps://` valida o certificado; `ldap://` é promovido por StartTLS (`LDAP_STARTTLS`, padrão ativo). Se o controlador de domínio não publica certificado, `LDAP_ALLOW_PLAINTEXT=true` permite seguir sem cifra — a senha trafega em claro na rede interna, e serve apenas a domínios que ainda não publicam certificado. `LDAP_CA_CERT` aponta para o PEM da CA interna que assina o certificado do controlador, permitindo validação completa sem expor a conexão; `LDAP_TLS_SKIP_VERIFY` cifra sem autenticar o par e serve apenas enquanto a CA não estiver disponível.

`LDAP_ROLE_MAPPING` mapeia grupos lidos de `LDAP_GROUP_ATTRIBUTE` (padrão `memberOf`) para roles, vencendo a de maior privilégio. O diretório só decide a role quando algum grupo mapeado casa: sem correspondência — inclusive com o mapeamento vazio — a role atribuída localmente por um administrador permanece, e o login não a sobrescreve. Contas externas novas nascem como `VIEWER` sem escopo de ambientes. A mesma regra vale para OIDC. Sincronização de identidade, role, nome, lotação e foto acontece no login; a foto é devolvida apenas em `GET /api/v1/auth/me`, fora das listagens. Sincronização periódica completa do diretório não está implementada.

Serviços e tokens não fazem login interativo. Tokens exigem usuário marcado como conta de serviço, scopes, expiração e armazenamento em hash.
