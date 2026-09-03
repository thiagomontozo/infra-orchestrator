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

Somente LDAPS com validação TLS. Bind de pesquisa restrito, filtro escapado, descoberta de DN e novo bind com a senha fornecida. A senha do usuário não é armazenada. `LDAP_ROLE_MAPPING` mapeia grupos lidos de `LDAP_GROUP_ATTRIBUTE`; padrão `memberOf`. Sincronização de identidade e role acontece no login. Sincronização periódica completa do diretório não está implementada.

Serviços e tokens não fazem login interativo. Tokens exigem usuário marcado como conta de serviço, scopes, expiração e armazenamento em hash.
