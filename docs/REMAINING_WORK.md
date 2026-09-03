# Partes finais de entrega

Este arquivo separa o encerramento da implementação em blocos verificáveis. Cada bloco só avança quando seu resultado é registrado.

## Parte 1 — Runtime de containers

- Substituir o runtime Alpine do backend por runtime mínimo sem OpenSSL.
- Atualizar o Nginx unprivileged para versão com correções disponíveis.
- Buildar backend e frontend novamente.
- Executar healthcheck e Trivy nas duas imagens.

Critério: nenhuma vulnerabilidade HIGH/CRITICAL corrigível nos runtimes gerados.

## Parte 2 — Fluxos de aceitação

- Subir servidor com banco isolado e fixture SSH/Docker.
- Reexecutar os cinco cenários Playwright: autenticação, administração, host/provisionamento, aprovação e agente LLM.
- Manter captura visual do dashboard como artefato local de validação.

Critério: todos os cenários passam sem dados fictícios ou acesso shell.

## Parte 3 — Contratos e revisão

- Gerar OpenAPI a partir das rotas registradas e conferir que não há diff.
- Repetir format, vet, testes Go, lint/test/build web, npm audit, govulncheck e secret scan.
- Atualizar TEST_RESULTS e FINAL_REPORT somente com resultados efetivos.

Critério: nenhuma falha de gate; achados sem correção disponível ficam documentados.

## Parte 4 — Git público

- Revisar arquivos versionados e `.gitignore`.
- Criar commits incrementais: plataforma, interface/documentação e hardening/CI.
- Criar `thiagomontozo/infra-orchestrator` como público, enviar `main` e confirmar URL/commit.

Critério: repositório público contém somente arquivos necessários, sem `.env`, chaves, tokens ou artefatos.

## Parte 5 — Limpeza

- Parar o Compose de teste.
- Remover imagens e cache BuildKit criados exclusivamente para esta plataforma, após o push.
- Manter apenas fonte, documentação e resultados não sensíveis necessários.

Critério: nenhum container, imagem ou cache do projeto permanece no Docker local.
