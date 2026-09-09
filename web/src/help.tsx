import {Fragment,useEffect,useRef,useState,type ReactNode} from 'react';
import {Activity,ArrowRight,Box,Clock,Cloud,FileText,GitBranch,LayoutDashboard,LifeBuoy,type LucideIcon,Rocket,Search,Server,ShieldCheck,Sparkles,Users,Wrench,Zap} from 'lucide-react';
import {Empty,Modal} from './components';

/** A help topic is data, not markup, so the search box can read every line it renders. */
type Block={p:string}|{steps:string[]}|{items:[string,string][]}|{note:string};
type Topic={id:string;title:string;icon:LucideIcon;summary:string;page?:string;blocks:Block[]};

export const topics:Topic[]=[
{id:'inicio',title:'Primeiros passos',icon:Rocket,summary:'O que é o control plane e o caminho mínimo até a primeira operação.',blocks:[
 {p:'O infra-orchestrator conecta hosts Linux por SSH, descobre o que roda neles e executa alterações como operações auditadas — com permissão, política, aprovação e trilha. A interface nunca executa comandos direto no host: ela cria solicitações que o worker processa.'},
 {steps:[
  'Suba o control plane com Docker Compose usando o .env gerado pelo bootstrap (scripts/bootstrap.sh ou bootstrap.ps1).',
  'Crie o primeiro administrador no servidor: docker compose exec server /app/infra-orchestrator admin create --username seu-admin --email admin@example.com. Não existe credencial padrão.',
  'Entre com usuário e senha. Se o ambiente tiver LDAP/Active Directory ou SSO, escolha o provedor na tela de login.',
  'Conclua a segurança da conta quando solicitado: troca de senha inicial e cadastro do MFA, se obrigatório.',
  'Cadastre um host em Infraestrutura › Hosts, teste o SSH e execute a descoberta.',
  'Abra um recurso descoberto, peça uma ação com justificativa e acompanhe o resultado em Operações.']},
 {note:'Em produção use HTTPS atrás de proxy reverso, com PUBLIC_ORIGIN igual à URL pública — a configuração de produção recusa origem HTTP. O nome exibido no topo e no login vem de APP_NAME.'}]},

{id:'interface',title:'Navegação e interface',icon:LayoutDashboard,summary:'Menu, busca, filtro de ambiente, atualização em tempo real e atalhos.',page:'dashboard',blocks:[
 {p:'O menu lateral agrupa as páginas em Visão geral, Infraestrutura, Operações, Observabilidade, Inteligência artificial e Administração. Só aparecem os itens permitidos ao seu papel — quem não administra não vê Usuários, Tokens, Políticas, Notificações nem Configurações.'},
 {items:[
  ['Busca','Filtra a lista da página atual por qualquer texto do registro: nome, estado, ambiente, identificador ou metadados.'],
  ['Ambiente','Restringe a listagem a development, testing, homologation, staging ou production.'],
  ['Atualizar','Recarrega os dados da página. A tela também se atualiza sozinha quando o servidor emite eventos.'],
  ['Ao vivo / Reconectando','Estado do canal de eventos. "Ao vivo" indica que mudanças no servidor chegam à tela em segundos; "Reconectando" indica que o canal caiu e só a atualização manual traz novidades.'],
  ['Adicionar','Abre o formulário de criação da página atual. Aparece apenas para quem tem a permissão de escrita correspondente.'],
  ['Endereço','Cada página tem seu próprio endereço com # (por exemplo #hosts), então favoritos e links diretos funcionam.']]},
 {p:'Em telas estreitas o menu lateral abre pelo botão de três traços, à esquerda da trilha de navegação.'},
 {note:'Pressione F1 ou ? em qualquer tela para abrir esta ajuda já no assunto da página em que você está.'}]},

{id:'conta',title:'Sua conta, senha e MFA',icon:ShieldCheck,summary:'Segurança da conta, autenticação em dois fatores e sessões.',page:'sessions',blocks:[
 {p:'Clique no seu nome, na barra superior, para abrir Segurança da conta.'},
 {items:[
  ['Trocar senha','Informe a senha atual e a nova. Contas marcadas com troca obrigatória só chegam ao workspace depois disso.'],
  ['MFA (TOTP)','Gere o segredo, cadastre-o no aplicativo autenticador e confirme com um código de seis dígitos. Contas com MFA obrigatório concluem o login somente após esse cadastro.'],
  ['Código no login','O campo Código MFA da tela de entrada só precisa ser preenchido por contas com TOTP ativo.'],
  ['Sair','Encerra a sessão atual no servidor, não apenas no navegador.'],
  ['Sessões','A página Administração › Sessões lista usuário, IP, método, último acesso, expiração e MFA, e permite revogar qualquer sessão. A sua aparece marcada como sessão atual.']]},
 {note:'Sessões e tokens são reconferidos a cada uso: revogar tem efeito imediato na próxima requisição.'}]},

{id:'hosts',title:'Hosts, bastions e grupos',icon:Server,summary:'Cadastro por SSH, confirmação de fingerprint, teste de conexão e descoberta.',page:'hosts',blocks:[
 {steps:[
  'Em Hosts, clique em Adicionar host e informe nome, ambiente, hostname ou IP, porta SSH e um usuário não root.',
  'Escolha a autenticação: chave SSH privada, SSH agent do worker ou senha. A credencial é gravada criptografada e nunca é devolvida pela API — ao editar, deixe o campo em branco para manter a atual.',
  'Se o host só for alcançável por um salto, selecione um Bastion já cadastrado; caso contrário mantenha Conexão direta.',
  'Clique em Obter fingerprint, compare o SHA256 exibido com o valor obtido por um canal confiável (console do servidor, inventário, provisionamento) e marque a confirmação. Sem confirmar, o host não é salvo.',
  'Salve, use Testar SSH para validar a conexão e Descobrir para inventariar runtimes e recursos.']},
 {items:[
  ['Grupos e tags','Campos livres separados por vírgula. Grupos organizam operações e políticas por conjunto de hosts; tags ajudam na busca.'],
  ['Grupos de hosts','A página guarda descrição e concorrência sugerida para operações que percorrem o grupo.'],
  ['Detalhes','Mostra o registro completo do host, incluindo os fatos coletados na descoberta.'],
  ['Runtimes','A coluna Runtimes lista o que foi encontrado no host: docker, podman, systemd, supervisor, pm2, swarm, kubernetes, nomad.']]},
 {note:'A descoberta é repetível e não altera nada no host. Rode de novo depois de instalar um runtime, subir serviços novos ou alterar a configuração remota.'}]},

{id:'recursos',title:'Containers, serviços e o painel do recurso',icon:Box,summary:'Listas por runtime, ações, logs, console interativo e operações em lote.',page:'resources',blocks:[
 {p:'Todos os recursos reúne tudo que a descoberta encontrou. Containers filtra Docker, Podman e Compose; Serviços filtra systemd, Supervisor, PM2 e Swarm; Logs abre a mesma lista voltada à leitura de registros. Clique em Gerenciar (ou Abrir logs) para abrir o painel do recurso.'},
 {items:[
  ['Visão geral','Identificador, tipo, estado, namespace e metadados. Os botões no topo são as capacidades do recurso: leitura (inspect, stats, status, describe, events, rollout_status, rollout_history) responde na hora na aba Resultado; escrita (start, stop, restart, reload, scale, rollback) abre a confirmação com justificativa e vira uma operação.'],
  ['Logs','Escolha de 100 a 2000 linhas, filtre por texto, use Acompanhar para recarregar a cada quatro segundos e baixe o trecho exibido.'],
  ['Console','Shell interativo em containers Docker e Podman e em serviços Compose, para quem tem a permissão container.exec. Em projetos Compose escolha antes o serviço. Copiar e colar usam Ctrl+Shift+C e Ctrl+Shift+V.'],
  ['Resultado','Última saída de leitura ou o JSON da operação solicitada.'],
  ['Análise com IA','Diagnóstico do recurso por um provedor LLM configurado. Exige a permissão llm.use.']]},
 {p:'Para criar um serviço novo, use Containers › Criar container: selecione um host Docker já descoberto, a imagem, a credencial de registry, as portas (do host e do container, com a interface de publicação), o usuário UID:GID, memória, CPUs, política de reinício, variáveis de ambiente (uma por linha, CHAVE=valor) e a justificativa. O worker baixa a imagem pela API do Docker sobre SSH e cria o container; o pedido aparece em Operações.'},
 {p:'Para agir sobre vários recursos, marque as caixas na lista e use Operação rolling. Só são oferecidas ações comuns a todos os selecionados, e você define o tamanho do lote, o máximo de falhas toleradas e a justificativa.'},
 {note:'Publique portas em 127.0.0.1 quando o serviço não precisar ser alcançável de fora do host, e prefira um usuário sem privilégios dentro do container.'}]},

{id:'kubernetes',title:'Kubernetes e Nomad',icon:Cloud,summary:'Clusters por kubeconfig ou kubectl do host, namespaces e rollout.',page:'kubernetes',blocks:[
 {p:'Há dois caminhos para o Kubernetes: usar o kubectl já configurado em um host descoberto, ou cadastrar o cluster na própria página com Adicionar cluster e um kubeconfig.'},
 {note:'O kubeconfig precisa trazer CA, token ou certificado incorporados. Plugins exec e TLS inseguro são recusados. O conteúdo é armazenado criptografado e não retorna pela API.'},
 {items:[
  ['Namespaces','A lista tem um seletor de namespace, além da busca e do filtro de ambiente.'],
  ['Rollout','No painel do recurso, rollout_status e rollout_history são leituras; scale e rollback são operações com justificativa e passam por política e aprovação.'],
  ['Nomad','Tem página própria, com a mesma mecânica de listagem, painel e operações.'],
  ['Deployment','Aplicar manifesto novo é feito em Operações › Deployments, não pelo painel do recurso.']]}]},

{id:'operacoes',title:'Operações e aprovações',icon:Activity,summary:'Ciclo de vida de uma solicitação, revisão humana e cancelamento.',page:'operations',blocks:[
 {p:'Toda alteração vira uma operação registrada: quem pediu, o que pediu, em qual ambiente, por quê, o risco avaliado e o resultado. A execução acontece no worker, a partir de uma fila durável — fechar o navegador não interrompe nada.'},
 {items:[
  ['queued','Aceita e aguardando o worker.'],
  ['waiting_approval','Política ou ambiente exigem decisão humana antes de executar.'],
  ['running','Em execução no host ou no cluster.'],
  ['succeeded','Concluída; o resultado bruto fica em Detalhes.'],
  ['failed','O adaptador retornou erro; a mensagem fica em Detalhes.'],
  ['rejected','Um aprovador recusou a solicitação com justificativa.']]},
 {steps:[
  'A página Aprovações lista o que está em waiting_approval.',
  'Quem tem a permissão operation.approve e não é o solicitante abre Revisar.',
  'Escolha aprovar ou rejeitar e registre a justificativa — ela entra na trilha de auditoria.',
  'Aprovada, a operação volta para a fila e executa em seguida.']},
 {p:'O solicitante e o ADMIN podem cancelar enquanto a operação está em fila, aguardando aprovação ou em execução. Detalhes mostra ação, motivo, solicitante, aprovador e resultado.'},
 {note:'Alterações em produção sempre exigem a aprovação de outra pessoa: ninguém aprova a própria solicitação.'}]},

{id:'deployments',title:'Deployments, GitOps e registries',icon:GitBranch,summary:'Publicar versões, comparar com o repositório e guardar credenciais de imagem.',page:'deployments',blocks:[
 {steps:[
  'Em Deployments, clique em Novo deployment e escolha um recurso Compose, Kubernetes, Nomad ou Swarm.',
  'Informe a versão e, quando fizer sentido, o artifact/imagem e o commit.',
  'Para Kubernetes e Nomad, cole o manifesto JSON — nome e namespace precisam corresponder ao recurso escolhido. Compose aplica os arquivos já presentes no host.',
  'Justifique e solicite. O deployment segue o mesmo fluxo das demais operações, com política e aprovação.']},
 {items:[
  ['GitOps','Aponta uma URL HTTPS de manifesto no repositório para um recurso de destino, com token de leitura opcional. O botão Comparar mostra a diferença entre o manifesto do repositório e o estado atual.'],
  ['Registries de imagens','Guarda servidor (docker.io, ghcr.io ou um registry interno), usuário e senha ou token. As credenciais são usadas no momento do pull e não geram docker login no host remoto.']]}]},

{id:'agendamentos',title:'Agendamentos e janelas de manutenção',icon:Clock,summary:'Ações recorrentes ou datadas e o período em que podem ocorrer.',page:'schedules',blocks:[
 {items:[
  ['Agendamentos','Informe o Resource ID, a ação (restart, start, stop, reload ou scale), um cron (por exemplo 0 3 * * 0) ou uma data única em RFC3339, o timezone e se está ativo.'],
  ['Janelas de manutenção','Definem início e fim no formato HH:MM e o timezone. Os dias da semana ficam em Configurações adicionais (JSON), no campo days, com 0 para domingo.'],
  ['Parâmetros','O bloco Configurações adicionais (JSON) também recebe parameters do agendamento — por exemplo o número de réplicas de um scale.']]},
 {note:'Cada disparo agendado cria uma operação comum: passa por política, pode exigir aprovação e aparece na auditoria como qualquer outra.'}]},

{id:'observabilidade',title:'Logs, alertas, métricas e incidentes',icon:Zap,summary:'Acompanhar o ambiente e transformar sinal em incidente tratado.',page:'alerts',blocks:[
 {items:[
  ['Logs','Lista de recursos direcionada à leitura: abre o painel na aba Logs, com filtro por texto, acompanhamento contínuo e download.'],
  ['Alertas','Sinais coletados do ambiente, com severidade e evidência. Quem tem incident.manage pode usar Criar incidente para abrir um registro já vinculado ao alerta e ao recurso.'],
  ['Métricas','Resumo dos contadores persistidos. O endpoint /metrics publica métricas do processo Go, dos hosts, dos recursos e dos estados das operações para o Prometheus, na rede privada do control plane.'],
  ['Incidentes','Status open, investigating, mitigated, resolved ou closed, severidade, responsável e uma descrição usada como timeline.']]}]},

{id:'ia',title:'Inteligência artificial',icon:Sparkles,summary:'Provedores LLM, diagnósticos, agentes e monitoramento de anomalias.',page:'providers',blocks:[
 {steps:[
  'Em Provedores LLM, adicione a URL ou IP:porta de um serviço compatível com /v1/models e /v1/chat/completions, o modelo, a API key (se houver), o timeout, o limite de contexto e marque como habilitado.',
  'Libere o destino em OUTBOUND_ALLOWED_CIDRS: o control plane só fala com redes explicitamente permitidas.',
  'Use Testar para validar a conexão antes de usar o provedor em diagnósticos.']},
 {items:[
  ['Diagnóstico sob demanda','No painel de um recurso, aba Análise com IA. O modelo recebe um contexto limitado e sanitizado e responde separando fatos observados, hipóteses prováveis e ações recomendadas.'],
  ['Diagnósticos','Guarda o que foi gerado. Quando o diagnóstico traz uma ferramenta sugerida, você pode solicitá-la — ela entra no fluxo normal de RBAC, política e aprovação.'],
  ['Agentes','Modo DISABLED, ADVISORY, ASSISTED ou AUTOMATED_POLICY_CONTROLLED, provedor, conta de serviço e intervalo em segundos. O agente age com as permissões da conta de serviço, nunca com as suas.'],
  ['Monitoramento','Mesma configuração aplicada a um recurso, host ou grupo, para procurar anomalias em intervalo fixo.'],
  ['Console com IA','No console de um container é possível pedir uma investigação: o modelo propõe comandos, mostra o raciocínio e o resultado vira um diagnóstico estruturado.']]},
 {note:'A resposta do modelo é hipótese, não verdade verificada. Ações sugeridas continuam sujeitas a permissão, política e aprovação humana.'}]},

{id:'administracao',title:'Usuários, papéis, tokens e políticas',icon:Users,summary:'Quem entra, o que pode fazer, em quais ambientes e sob quais regras.',page:'users',blocks:[
 {items:[
  ['Usuários','Criação e edição de conta: papel, ambientes de escopo (separados por vírgula, * para todos), MFA obrigatório, troca de senha na próxima entrada e habilitar ou desabilitar. Contas de serviço também são criadas aqui.'],
  ['Papéis','ADMIN administra tudo. OPERATOR opera recursos no seu escopo, cria containers, faz deployments e cuida de agendamentos e incidentes. VIEWER lê inventário e logs. AUDITOR acrescenta auditoria. APPROVER acrescenta aprovação e auditoria. A página lista as permissões de cada papel.'],
  ['Escopo de ambiente','Fora do ADMIN, uma operação só passa quando a permissão e o ambiente do recurso estão no escopo do usuário.'],
  ['Tokens','Gere um token para uma conta de serviço com nome, scopes e validade. O valor aparece uma única vez, os scopes são intersectados com as permissões da conta e a revogação vale imediatamente.'],
  ['Políticas','Regra por ação e, opcionalmente, papel, host, grupo ou recurso: negar, exigir aprovação, exigir MFA ou permitir que o agente a utilize. Use Configurações adicionais (JSON) para amarrar a regra a uma janela de manutenção.'],
  ['Notificações','Canal webhook, e-mail por SMTP, Slack ou Teams para os eventos do control plane.'],
  ['Configurações','Observações administrativas e ajustes gerais do workspace.']]},
 {note:'Prefira contas de serviço com scopes mínimos e validade curta para automações e para os agentes.'}]},

{id:'auditoria',title:'Auditoria e rastreabilidade',icon:FileText,summary:'A trilha somente-acréscimo de tudo que foi decidido e executado.',page:'audit',blocks:[
 {p:'A trilha registra data, evento, ator, ambiente, decisão e metadados expansíveis. A página mostra as últimas trezentas entradas e aceita busca por texto — combine com o filtro de ambiente para investigar um caso específico.'},
 {p:'Entram na trilha, entre outros: entradas e saídas de sessão, criação de operações, decisões de aprovação, execuções e seus resultados, revogações de sessão e token, e alterações de usuários e políticas.'},
 {note:'A auditoria é visível para quem tem a permissão audit.read — AUDITOR, APPROVER e ADMIN.'}]},

{id:'estados',title:'Glossário de estados',icon:LifeBuoy,summary:'O que significam as etiquetas coloridas nas listas.',blocks:[
 {items:[
  ['online / offline','Resultado do último teste de conexão SSH com o host.'],
  ['healthy / degraded / unhealthy','Saúde do recurso relatada pelo runtime na última descoberta ou leitura.'],
  ['unknown','O runtime não informou o dado; normalmente basta rodar a descoberta de novo.'],
  ['queued / running','Operação na fila ou em execução.'],
  ['waiting_approval','Operação parada aguardando decisão humana.'],
  ['succeeded / failed / rejected','Desfecho da operação: concluída, com erro ou recusada na revisão.'],
  ['low / medium / high / critical','Risco da operação ou severidade do alerta e do incidente.'],
  ['development … production','Ambiente do registro. Produção recebe as regras mais estritas.'],
  ['enabled / disabled / revoked','Estado de contas, integrações, sessões e tokens.']]}]},

{id:'problemas',title:'Solução de problemas',icon:Wrench,summary:'Os erros mais comuns e o que verificar em cada um.',blocks:[
 {items:[
  ['A barra mostra "Reconectando"','O canal de eventos caiu. A interface continua funcionando com o botão Atualizar. Verifique o proxy reverso (buffering em respostas de streaming) e se a sessão continua válida.'],
  ['Testar SSH falha','Confirme usuário, porta e credencial e, se houver salto, o bastion escolhido. Fingerprint diferente da cadastrada indica troca de chave do servidor — investigue antes de atualizar o valor.'],
  ['A descoberta não traz recursos','O usuário SSH precisa de acesso aos runtimes do host (por exemplo pertencer ao grupo docker ou alcançar o socket do podman). Ajuste e execute a descoberta novamente.'],
  ['A operação ficou em waiting_approval','Falta a decisão de outra pessoa com a permissão operation.approve. O solicitante não pode aprovar a própria operação.'],
  ['O botão Adicionar não aparece','A página exige uma permissão de escrita que o seu papel não tem, ou o ambiente do registro está fora do seu escopo.'],
  ['Testar o provedor LLM falha','Revise URL e porta, o nome do modelo, a API key e se o destino está liberado em OUTBOUND_ALLOWED_CIDRS.'],
  ['Erro de origem, sessão ou CSRF','A sessão expirou ou a página foi aberta em uma origem diferente de PUBLIC_ORIGIN. Recarregue e entre novamente.'],
  ['Logs vazios','O recurso pode não expor logs pelo runtime, ou o intervalo escolhido não tem linhas. Aumente o número de linhas e limpe o filtro de texto.']]}]}];

/** Which topic answers the page the user is looking at. */
const byPage:Record<string,string>={dashboard:'interface',hosts:'hosts','host-groups':'hosts',containers:'recursos',services:'recursos',resources:'recursos',logs:'recursos',kubernetes:'kubernetes',nomad:'kubernetes',operations:'operacoes',approvals:'operacoes',deployments:'deployments',gitops:'deployments',registries:'deployments',schedules:'agendamentos','maintenance-windows':'agendamentos',alerts:'observabilidade',metrics:'observabilidade',incidents:'observabilidade',providers:'ia',agents:'ia',monitoring:'ia',recommendations:'ia',users:'administracao',roles:'administracao',tokens:'administracao',policies:'administracao',notifications:'administracao',settings:'administracao',sessions:'conta',audit:'auditoria'};
function text(t:Topic){return [t.title,t.summary,...t.blocks.flatMap(b=>'p' in b?[b.p]:'note' in b?[b.note]:'steps' in b?b.steps:b.items.flat())].join(' ').toLowerCase()}
/** Ranks a match so a search lands on the topic that actually covers the term, not merely the first that mentions it. */
function score(t:Topic,q:string){return (t.title.toLowerCase().includes(q)?100:0)+text(t).split(q).length-1}

function Blocks({blocks}:{blocks:Block[]}){return <>{blocks.map((b,i)=>'p' in b?<p key={i}>{b.p}</p>:'note' in b?<div className="notice" key={i}>{b.note}</div>:'steps' in b?<ol className="help-steps" key={i}>{b.steps.map((s,j)=><li key={j}>{s}</li>)}</ol>:<dl className="help-items" key={i}>{b.items.map(([term,definition])=><Fragment key={term}><dt>{term}</dt><dd>{definition}</dd></Fragment>)}</dl>)}</>}

export function Help({page,close,navigate}:{page:string;close:()=>void;navigate:(p:string)=>void}):ReactNode{
 const[query,setQuery]=useState('');const[selected,setSelected]=useState(byPage[page]||'inicio');const content=useRef<HTMLElement>(null);const current=useRef<HTMLButtonElement>(null);
 const q=query.trim().toLowerCase();
 const list=topics.filter(t=>text(t).includes(q));
 const topic=list.find(t=>t.id===selected)||(q?[...list].sort((a,b)=>score(b,q)-score(a,q))[0]:list[0]);
 useEffect(()=>{if(content.current)content.current.scrollTop=0;current.current?.scrollIntoView({block:'nearest',inline:'nearest'})},[topic?.id]);
 return <Modal title="Central de ajuda" onClose={close} wide>
  <div className="search help-search"><Search size={17}/><input autoFocus aria-label="Buscar na ajuda" placeholder="Buscar por assunto: fingerprint, aprovação, token, cron…" value={query} onChange={e=>setQuery(e.target.value)}/></div>
  {topic?<div className="help-layout">
   <nav className="help-index" aria-label="Assuntos da ajuda">{list.map(t=><button key={t.id} ref={topic.id===t.id?current:undefined} className={topic.id===t.id?'selected':''} onClick={()=>setSelected(t.id)}><t.icon size={17}/><span>{t.title}</span></button>)}</nav>
   <article className="help-content" ref={content}><h3>{topic.title}</h3><p className="help-summary">{topic.summary}</p><Blocks blocks={topic.blocks}/>
    <div className="help-footer"><span>Dúvida sobre outro assunto? Use a busca acima ou pressione F1 dentro da página.</span>{topic.page&&<button className="text-button" onClick={()=>{navigate(topic.page!);close()}}>Abrir a página<ArrowRight size={15}/></button>}</div></article>
  </div>:<Empty title="Nenhum assunto encontrado">Tente outro termo, como host, operação, aprovação, deployment, token ou provedor.</Empty>}
 </Modal>;
}
