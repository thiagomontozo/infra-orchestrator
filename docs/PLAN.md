# Plano e registro de execução

Inspeção em 2026-09-02: diretório vazio, sem Git e sem código anterior. Go 1.26.5 e Node 24 disponíveis. GitHub CLI autenticado. Docker instalado, daemon inicialmente indisponível.

## Arquitetura decidida

Monorepo Go + React/TypeScript/Vite. PostgreSQL é a fonte de verdade para identidades, sessões, inventário, políticas, operações, fila durável, leases, auditoria e eventos. Workers independentes consomem operações com SKIP LOCKED e locks por recurso. Redis oferece limites distribuídos; NATS JetStream replica eventos via outbox. Sem shell público. Adapters constroem somente comandos permitidos, com argumentos validados e escapados. SSH verifica fingerprints/known_hosts, inclusive bastion.

O runtime hospedado do Sites (Cloudflare Workers) não executa o backend Go/SSH; a stack explicitamente solicitada prevalece. O frontend será servido com o backend via containers. O usuário solicitou explicitamente publicação em repositório GitHub **público**, substituindo o padrão privado da especificação inicial.

## Etapas

1. Core: configuração, migrations, segurança, autenticação, MFA, RBAC, políticas, auditoria e API.
2. SSH, secrets, hosts, discovery e adapters com testes de parsers/comandos.
3. Operações, aprovação, fila, workers, locks, recovery, rolling e scheduler.
4. Observabilidade, incidentes, deployments, GitOps e agentes estruturados.
5. Interface completa conectada à API, testes de frontend e E2E.
6. Hardening, testes de integração, builds, scanners, documentação e publicação.

## Critério de evidência

Nenhuma integração será apresentada como validada sem execução. Fixtures cobrem protocolos/parsers, mas não substituem testes com clusters, provedores SSO, Vault ou LLM reais. O relatório final distingue implementação, validação local e limitações. Não publicar antes dos gates disponíveis passarem. Recursos Docker serão nomeados pelo projeto e removidos ao final; nunca usar prune global.
