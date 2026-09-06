# Console interativo de container

A aba **Console** da tela de recurso abre um shell dentro do container, com PTY
real: `vim`, `htop`, `less` e `Ctrl+C` funcionam como funcionariam num SSH direto.

## Postura de segurança

Esta funcionalidade é uma mudança deliberada de postura do projeto, decidida
explicitamente e registrada aqui:

- A permissão `container.exec` é concedida a `OPERATOR` e `ADMIN` **em todos os
  ambientes, inclusive `production`**, e **sem aprovação de segunda pessoa** — ao
  contrário das operações de mudança, que passam por `operations.Engine`.
- O restante do projeto mantém a postura anterior: a política do agente continua
  afirmando que a IA não tem shell nem execução direta, e a allowlist de binários
  em `executor.Command.Render` continua valendo — inclusive para o console.

## Caminho da requisição

```
navegador --(WebSocket)--> nginx --(upgrade)--> server --(SSH + PTY)--> host --> docker exec
```

`GET /api/v1/resources/{id}/console` faz upgrade para WebSocket.

### Protocolo

| Frame | Sentido | Conteúdo |
| --- | --- | --- |
| binário | cliente → servidor | teclado |
| binário | servidor → cliente | saída do terminal |
| texto | cliente → servidor | `{"rows":n,"cols":n}` |

O servidor envia ping a cada 25s para o proxy não derrubar uma sessão ociosa.

## Camadas de verificação

Todas acontecem **antes** do upgrade. Depois dele a resposta está sequestrada e a
única coisa que o handler ainda consegue fazer é fechar o socket.

1. **Autenticação** — o wrapper `Server.route` já exige sessão válida, MFA
   registrado e senha não expirada.
2. **`resource.read`** no ambiente do host, via `visibleResource`.
3. **`container.exec`** no ambiente do host, via `rbac.Permission(provider,"exec")`.
4. **`Origin` idêntico a `PUBLIC_ORIGIN`.** Ver abaixo — é a defesa central.
5. **`adapters.ConsoleCommand`** resolve o alvo e recusa o que não for um
   container único.
6. **Orçamento** de 20 sessões por usuário por hora (`auth_limits`, chave
   `console:<user_id>`).
7. **`executor.Command.Render`** aplica a allowlist de binários do host.

### Por que a checagem de `Origin` é obrigatória

Um upgrade de WebSocket é um `GET`, e `auth.Authenticate` **não** valida CSRF nem
`Origin` em `GET`. O handshake, portanto, chega com o cookie de sessão e sem
`X-CSRF-Token`. A comparação explícita de `Origin` com `s.Config.Origin` no
handler é a única coisa entre o cookie do usuário e um shell aberto por outro
site.

Por isso `websocket.Accept` roda com `InsecureSkipVerify: true`: a checagem
própria da biblioteca compara com o header `Host` e rejeitaria a origem que chega
pelo proxy. A verificação não foi removida, foi substituída por uma mais estrita.

**Remover a comparação de `Origin` reintroduz cross-site WebSocket hijacking.**

## Alvos aceitos

| Provider | Tipo | Container |
| --- | --- | --- |
| `docker`, `podman` | `docker_container`, `podman_container` | `external_id` |
| `dockercompose`, `podmancompose` | `docker_compose_service` | `metadata.container` |

Um **projeto** compose não tem container próprio: a aba lista os serviços do
mesmo host cujo `metadata.project` corresponde ao `external_id` do projeto e pede
que um seja escolhido. Kubernetes, systemd, nomad, swarm, supervisor e pm2 são
recusados — não há um container único ao qual anexar.

O shell é restrito a `sh` ou `bash`. O identificador do container passa por
`executor.ValidRef` antes de virar argumento.

## Limites

- 30 minutos por sessão, aplicados no `context` e no `executor.Terminal`.
- 20 sessões por usuário por hora.
- 64 KB por frame de entrada.
- `CommandTimeout` (90s) **não** se aplica: ele existe para comandos de uma
  tacada e cortaria uma sessão em uso.

## Limitações conhecidas, todas deliberadas

1. **O botão "Colar" exige HTTPS.** `navigator.clipboard` só existe em contexto
   seguro. Servida em HTTP, a UI captura a falha e orienta usar `Ctrl+V`, que
   passa pelo tratamento nativo do xterm e funciona sempre. Não existe outra API
   de leitura de área de transferência em contexto inseguro — publicar a UI em
   HTTPS é a única correção. Copiar tem fallback via `document.execCommand` e
   funciona nos dois casos.
2. **A sessão não é gravada.** A auditoria registra `resource.console` na abertura
   (recurso, host, ambiente, container, shell) e `resource.console_ended` no fim
   (duração, motivo). **Os comandos digitados não entram na auditoria.** Gravá-los
   exigiria um registrador no meio do stream.
3. **A saída não passa por `security.Redact`.** Sequências de escape são o que faz
   o terminal funcionar e reescrevê-las corromperia a tela. Segredos exibidos
   dentro do container aparecem como apareceriam num SSH direto.
4. **Sem aprovação de segunda pessoa, inclusive em produção.**

## nginx

O upgrade exige `map $http_upgrade $connection_upgrade` no contexto `http` — o
arquivo é incluído a partir de `conf.d/`, então o `map` no topo é válido — mais
os headers `Upgrade`/`Connection` e timeouts de 3600s em `location /api/`.

## Diagnóstico

| Sintoma | Causa provável |
| --- | --- |
| 401 no upgrade | `Origin` diferente de `PUBLIC_ORIGIN` |
| 403 no upgrade | papel sem `container.exec` |
| 429 no upgrade | orçamento de 20 sessões/hora esgotado |
| 400 no upgrade | recurso sem container anexável, ou shell fora da lista |
| conecta e cai em ~30s | `ReadTimeout` do `http.Server` — os deadlines são zerados com `http.NewResponseController` |
| conecta e cai ociosa | proxy sem os headers de upgrade ou com timeout curto |

```sh
docker compose logs server --since 10m | grep -i console
```

```sql
select timestamp, actor, action, metadata from audit
where action in ('resource.console','resource.console_ended')
order by id desc limit 10;
```
