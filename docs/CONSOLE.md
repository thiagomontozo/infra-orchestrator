# Console interativo

O console anexa um shell dentro de um container, pela mesma conexão SSH que o
orquestrador já usa para as demais operações. Ele fica na aba **Console** do painel
de um recurso.

## Postura de segurança

Esta funcionalidade é uma mudança deliberada de postura do projeto, decidida
explicitamente e registrada aqui:

- A permissão `container.exec` é concedida a `OPERATOR` e `ADMIN` **em todos os
  ambientes, inclusive `production`**, e **sem aprovação de segunda pessoa** — ao
  contrário das operações de mudança, que passam por `operations.Engine`.
- A allowlist de binários em `executor.Command.Render` continua valendo no host:
  o console e o agente chegam ao container por `docker exec`, um programa já
  aceito, e nenhum caminho novo de execução no host é aberto. Dentro do
  container, porém, o comando é livre — é essa a fronteira que muda.
- O agente deixa de ser apenas consultivo neste escopo: com `llm.use` e
  `container.exec`, o modelo executa comandos dentro do container aberto. O risco
  correspondente está em [AGENT_SECURITY.md](AGENT_SECURITY.md).

## Alcance

Só recursos com container próprio aceitam console:

| Provider | Tipo | Alvo |
| --- | --- | --- |
| `docker`, `podman` | `docker_container`, `podman_container` | `external_id` do recurso |
| `dockercompose`, `podmancompose` | `docker_compose_service` | `metadata.container` |

Um projeto compose (`docker_compose_project`) não tem container próprio. A aba mostra
os serviços do projeto e o console abre no serviço escolhido.

O comando executado é `docker exec --interactive --tty <container> <shell>`, com o
shell restrito a `sh` ou `bash`. O binário continua passando pela allowlist de
`executor.Command.Render`, a mesma que protege todas as outras operações — o console
não abre um caminho novo para executar programas no host.

## Autorização

- Permissão `container.exec`, concedida a `OPERATOR` e `ADMIN`. Papéis de leitura não
  enxergam a aba e a rota recusa a conexão.
- `resource.read` no ambiente do host, como em qualquer recurso.
- Liberado em todos os ambientes, inclusive `production`. Diferente de uma operação de
  escrita, o console **não** passa por aprovação de segunda pessoa: quem tem
  `container.exec` executa comandos arbitrários dentro do container imediatamente.
- Limite de 20 sessões por usuário por hora e teto de 30 minutos por sessão.

## Transporte

`GET /api/v1/resources/{id}/console` faz upgrade para WebSocket.

- Frames binários carregam a entrada do teclado e a saída do terminal.
- Frames de texto carregam apenas `{"rows":n,"cols":n}` para redimensionar o PTY.
- O servidor envia ping a cada 25s para o proxy não derrubar sessões ociosas.

O handshake é um `GET` e portanto chega com o cookie de sessão mas sem o header
`X-CSRF-Token` exigido nas rotas de escrita. A defesa contra outro site abrir um shell
com o cookie do usuário é a checagem de `Origin` contra `PUBLIC_ORIGIN`, obrigatória
nessa rota. O nginx precisa repassar `Upgrade`/`Connection` — já configurado em
`deployments/nginx.conf`.

## Auditoria

Duas entradas por sessão:

- `resource.console` na abertura, com recurso, host, ambiente, container e shell.
- `resource.console_ended` no fim, com duração em segundos e o motivo do encerramento.

**O conteúdo da sessão não é gravado.** A auditoria registra que houve um shell, por
quem e por quanto tempo, não os comandos digitados. Se o requisito for gravar comandos,
isso exige um registrador no meio do stream e ainda não existe.

A saída do terminal também não passa por `security.Redact`: sequências de escape são o
que faz o terminal funcionar, e reescrevê-las corromperia a tela. Segredos exibidos
dentro do container aparecem na tela do operador como apareceriam num SSH direto.

## IA no mesmo container

Abaixo do terminal, quem tem `llm.use` além de `container.exec` conversa com o agente
sobre o container aberto. Nos dois modos o backend executa
`docker exec <container> sh -c <comando>` no **mesmo container do console** e devolve a
saída ao modelo como evidência.

**Chat** (`POST /api/v1/agents/chat`) é o modo normal: você manda uma mensagem, a IA roda
até 6 comandos para responder e escreve em prosa o que observou, o que concluiu e o que
mudou. A conversa continua — a próxima mensagem chega com o histórico. Diferente do modo
autônomo, aqui a IA **pode alterar coisas dentro do container** quando você pede uma
correção, e a política exige que ela diga exatamente o que mudou. Reiniciar o container em
si continua fora do alcance dela: isso é operação, e passa por RBAC, política e aprovação.

**Diagnóstico estruturado** (`POST /api/v1/agents/debug`) é o modo autônomo: uma pergunta,
até 8 passos de investigação sem sua intervenção, e um diagnóstico validado no schema —
que pode trazer um `suggested_tool` de reinício para você solicitar com aprovação na aba
de IA. Use quando quiser o laudo, não a conversa.

### Acompanhando ao vivo

O painel usa `POST /api/v1/agents/chat/stream`, que responde em Server-Sent Events e
mostra a troca acontecendo: o raciocínio do modelo enquanto ele escreve, cada comando no
momento em que começa a rodar, a saída quando chega, e a resposta sendo redigida. Os
eventos são `open`, `step`, `reasoning`, `thought`, `command`, `result` e, ao final,
`done` com a conversa gravada — ou `error`. Como o stream abre com HTTP 200 antes de a
conversa começar, uma negativa de permissão chega como evento `error`, não como 403.

O `thought` é um campo do JSON que o modelo devolve, extraído incrementalmente de um
documento ainda incompleto. Já `reasoning` é o canal separado que alguns modelos emitem
(`reasoning_content`), repassado quando existe. `POST /api/v1/agents/chat` continua
disponível e devolve a mesma troca em JSON, para uso por script. Um provedor que não
suporte `stream: true` não quebra o chat: se nada chegou ao usuário ainda, o backend
refaz a chamada em modo bufferizado e entrega a resposta de uma vez.

### Conversas

Cada conversa é um objeto `conversations`, guardado no servidor com as mensagens e, em
cada resposta da IA, os comandos que ela rodou com saída e status. O painel reabre a
conversa mais recente daquele container ao ser aberto de novo; **Nova conversa** começa
outra. `GET /api/v1/agents/chat?resource_id=` lista as suas.

Conversas são **privadas de quem as abriu** — nem ADMIN lê a conversa alheia por essa
rota. Isso não esconde nada de auditoria: todo comando executado está em `agent.exec`,
com autor, container, comando, status e duração. O que fica privado é o texto que a
pessoa escreveu, não o que a máquina fez.

Limites: 60 mensagens por usuário por hora, 4000 caracteres por mensagem, 60 mensagens
guardadas por conversa (as mais antigas caem). Para caber no contexto, o histórico
reenviado ao modelo traz a saída completa só do último comando; os anteriores viram uma
linha dizendo que rodaram e como terminaram.

O comando é livre — não há allowlist de programas dentro do container. A autorização é
verificada uma vez, no início: `llm.use`, `resource.read` e `container.exec` no ambiente
do host, exatamente o que o console interativo já exige. O script chega ao runtime como
um único argumento citado, então o que ele escreve vale dentro do container e nunca na
linha de comando do host.

Limites de execução, comuns aos dois modos: 60 comandos por usuário por hora, mais 5
sessões autônomas por hora. Cada comando tem o timeout de `SSH_COMMAND_TIMEOUT`, e a
saída entregue ao modelo é truncada em 6000 bytes/200 linhas e passa por
`security.Redact`. Uma falha de transporte encerra a sessão em vez de virar evidência; um
exit code diferente de zero é resultado normal e segue para o modelo.

Diferente do console, **os comandos do agente são gravados**: cada um gera um evento
`agent.exec` na auditoria com container, comando, status e duração. A sessão autônoma
guarda o `transcript` no objeto `recommendations` junto do diagnóstico e fecha com
`agent.debug`; o chat guarda os comandos dentro da própria mensagem da IA e registra
`agent.chat` por troca.

O risco que isso cria está em [AGENT_SECURITY.md](AGENT_SECURITY.md): uma linha de log
ou de saída pedindo para executar algo é evidência não confiável, mas quem escolhe o
próximo comando é o modelo, e não existe mais uma allowlist estrutural atrás dele.

## Copiar e colar

- **Copiar**: botão copia a seleção ou, sem seleção, todo o buffer visível. Atalho
  `Ctrl+Shift+C`.
- **Colar**: `Ctrl+V` funciona sempre (o navegador entrega o evento de colagem direto ao
  terminal). O botão **Colar** e o atalho `Ctrl+Shift+V` usam a API de área de
  transferência, que os navegadores só liberam em contexto seguro — servindo a UI por
  HTTP puro, o botão avisa e o `Ctrl+V` segue valendo. Publicar a UI em HTTPS libera os
  dois caminhos.
