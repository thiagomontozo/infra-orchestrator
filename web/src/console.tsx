import {useCallback,useEffect,useMemo,useRef,useState,type FormEvent} from 'react';
import {ClipboardPaste,Copy,Plug,PlugZap,Plus,SendHorizontal,Sparkles,Trash2} from 'lucide-react';
import {Terminal} from '@xterm/xterm';
import {FitAddon} from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import {api,stream,type Obj,type Resource,type Session,allowed} from './api';
import {Badge,ErrorBox} from './components';

const attachable=['docker_container','podman_container','docker_compose_service'];
const projects=['docker_compose_project','podman_compose_project'];
const providers=['docker','podman','dockercompose','podmancompose'];
/** Mirror agent.DebugSteps and agent.ChatSteps: the backend stops there. */
const debugSteps=8;
const chatSteps=6;

/** Live is the exchange currently streaming in, before the server commits it. */
type Live={thought:string;reasoning:string;reply:string;commands:Record<string,any>[]};

/** consoleTarget reports whether a resource can host a shell itself, and whether it is a
 *  compose project, which has no container of its own and needs a service chosen first. */
export function consoleTarget(r:Resource){return providers.includes(r.provider)&&(attachable.includes(r.type)||projects.includes(r.type))}
export function consoleVisible(r:Resource,s:Session){return allowed(s,'container.exec')&&consoleTarget(r)}

/** Falls back to execCommand because navigator.clipboard is unavailable on pages served
 *  over plain HTTP, which is how this UI is reached today. */
async function copyToClipboard(text:string){
 try{await navigator.clipboard.writeText(text);return true}catch{/* insecure context */}
 const a=document.createElement('textarea');a.value=text;a.style.position='fixed';a.style.opacity='0';document.body.appendChild(a);a.select();
 try{return document.execCommand('copy')}catch{return false}finally{document.body.removeChild(a)}
}

export function Console({resource,notify,session,onDiagnosis}:{resource:Resource;notify:(s:string)=>void;session:Session;onDiagnosis?:(o:Obj)=>void}){
 const isProject=projects.includes(resource.type);
 const[services,setServices]=useState<Resource[]>([]);
 const[target,setTarget]=useState(isProject?'':resource.id);
 const[shell,setShell]=useState('sh');
 const[state,setState]=useState<'idle'|'connecting'|'open'|'closed'>('idle');
 const[error,setError]=useState('');
 const[llmProviders,setLlmProviders]=useState<Obj[]>([]);
 const[llmProvider,setLlmProvider]=useState('');
 const[conversation,setConversation]=useState<Obj>();
 const[draft,setDraft]=useState('');
 const[pending,setPending]=useState('');
 const[live,setLive]=useState<Live>();
 const[sending,setSending]=useState(false);
 const[debugging,setDebugging]=useState(false);
 const canDebug=allowed(session,'llm.use');
 const messages=(conversation?.data.messages||[]) as Record<string,any>[];
 const host=useRef<HTMLDivElement>(null);
 const term=useRef<Terminal>(null);
 const fit=useRef<FitAddon>(null);
 const socket=useRef<WebSocket>(null);
 const abort=useRef<AbortController|null>(null);
 const log=useRef<HTMLDivElement>(null);
 const encoder=useMemo(()=>new TextEncoder(),[]);

 useEffect(()=>{if(!isProject)return;api<Resource[]>('/resources').then(all=>{
  const own=all.filter(v=>v.host_id===resource.host_id&&v.type==='docker_compose_service'&&v.metadata?.project===resource.external_id);
  setServices(own);if(own.length)setTarget(own[0].id)}).catch(e=>setError(e.message))},[isProject,resource.host_id,resource.external_id]);

 useEffect(()=>{if(canDebug)api<Obj[]>('/llm/providers').then(v=>{setLlmProviders(v);if(v.length)setLlmProvider(v[0].id)}).catch(()=>{})},[canDebug]);

 /** Reopens the most recent conversation about this container, so closing the panel does
  *  not throw away the thread. Conversations are per-user and stay on the server. */
 useEffect(()=>{if(!canDebug||!target){setConversation(undefined);return}
  let active=true;
  api<Obj[]>(`/agents/chat?resource_id=${target}`).then(v=>{if(active)setConversation(v[0])}).catch(()=>{});
  return()=>{active=false}},[canDebug,target]);

 useEffect(()=>{const el=log.current;if(el)el.scrollTop=el.scrollHeight},[messages.length,live,pending]);

 const disconnect=useCallback(()=>{socket.current?.close();socket.current=null},[]);

 /** Sends one message and follows the exchange as it happens: the model's thinking, each
  *  command as it starts, its output as it lands, and the answer as it is written. The
  *  turn is only committed on the done event, which carries the stored conversation. */
 async function send(e:FormEvent<HTMLFormElement>){
  e.preventDefault();
  const text=draft.trim();
  if(!text||!target||!llmProvider)return;
  const controller=new AbortController();abort.current=controller;
  setSending(true);setError('');setPending(text);setDraft('');setLive({thought:'',reasoning:'',reply:'',commands:[]});
  try{
   await stream('/agents/chat/stream',{conversation_id:conversation?.id||'',resource_id:target,provider_id:llmProvider,message:text},({event,data})=>{
    if(event==='thought')setLive(v=>v&&{...v,thought:v.thought+data.text});
    else if(event==='reasoning')setLive(v=>v&&{...v,reasoning:v.reasoning+data.text});
    else if(event==='reply')setLive(v=>v&&{...v,reply:v.reply+data.text});
    // The thought that led to a command belongs with it, and the next step starts clean.
    else if(event==='command')setLive(v=>v&&{...v,thought:'',commands:[...v.commands,{command:data.command,thought:v.thought,status:''}]});
    else if(event==='result')setLive(v=>v&&{...v,commands:v.commands.map((c,i)=>i===v.commands.length-1?{...c,status:data.status,output:data.output,seconds:data.seconds}:c)});
    else if(event==='error')setError(data.error);
    else if(event==='done'){setConversation(data);setPending('')}
   },controller.signal);
  }catch(e){if(!controller.signal.aborted){setError((e as Error).message);setDraft(text)}}
  finally{abort.current=null;setSending(false);setPending('');setLive(undefined)}}

 /** Runs the autonomous session instead of a conversation: the agent investigates on its
  *  own and returns a structured diagnosis, which can carry a restart suggestion for
  *  approval. Shown in the AI tab, where that suggestion becomes a request. */
 async function diagnose(){
  if(!target||!llmProvider)return;
  setDebugging(true);setError('');
  try{
   const o=await api<Obj>('/agents/debug','POST',{resource_id:target,provider_id:llmProvider,question:'Investigue o estado deste container e explique o que está errado.'});
   notify(`Diagnóstico concluído após ${o.data.commands??0} comando(s) no container`);
   onDiagnosis?.(o);
  }catch(e){setError((e as Error).message)}finally{setDebugging(false)}}

 const connect=useCallback(()=>{
  if(!target||!host.current)return;
  setError('');setState('connecting');
  const t=new Terminal({fontSize:13,fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',cursorBlink:true,scrollback:5000,theme:{background:'#0f1720',foreground:'#e6edf3'}});
  const f=new FitAddon();t.loadAddon(f);t.open(host.current);f.fit();
  term.current=t;fit.current=f;
  const url=`${location.protocol==='https:'?'wss':'ws'}://${location.host}/api/v1/resources/${target}/console?shell=${shell}&rows=${t.rows}&cols=${t.cols}`;
  const ws=new WebSocket(url);ws.binaryType='arraybuffer';socket.current=ws;
  ws.onopen=()=>{setState('open');t.focus()};
  ws.onmessage=e=>t.write(new Uint8Array(e.data as ArrayBuffer));
  ws.onerror=()=>setError('Falha na conexão com o console. Verifique a permissão container.exec e se o container está em execução.');
  ws.onclose=()=>{setState('closed');t.write('\r\n\x1b[33m— sessão encerrada —\x1b[0m\r\n')};
  t.onData(d=>{if(ws.readyState===WebSocket.OPEN)ws.send(encoder.encode(d))});
  t.attachCustomKeyEventHandler(e=>{
   if(e.type!=='keydown'||!e.ctrlKey||!e.shiftKey)return true;
   if(e.key==='C'||e.key==='c'){void copy();return false}
   if(e.key==='V'||e.key==='v'){void paste();return false}
   return true});
 },[target,shell,encoder]);

 useEffect(()=>()=>{socket.current?.close();term.current?.dispose();abort.current?.abort()},[]);

 useEffect(()=>{
  const el=host.current;if(!el)return;
  const observer=new ResizeObserver(()=>{const f=fit.current,t=term.current,ws=socket.current;if(!f||!t)return;
   try{f.fit()}catch{return}
   if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({rows:t.rows,cols:t.cols}))});
  observer.observe(el);return()=>observer.disconnect()},[]);

 async function copy(){
  const t=term.current;if(!t)return;
  const selection=t.getSelection();
  const buffer=t.buffer.active;
  let text=selection;
  if(!text){const lines:string[]=[];for(let i=0;i<buffer.length;i++)lines.push(buffer.getLine(i)?.translateToString(true)??'');text=lines.join('\n').replace(/\n+$/,'')}
  notify(await copyToClipboard(text)?(selection?'Seleção copiada':'Conteúdo do console copiado'):'Não foi possível copiar. Use Ctrl+C do navegador.')}

 async function paste(){
  const ws=socket.current;if(ws?.readyState!==WebSocket.OPEN)return;
  try{const text=await navigator.clipboard.readText();if(text)ws.send(encoder.encode(text))}
  catch{notify('A leitura da área de transferência exige HTTPS. Use Ctrl+V para colar no console.')}}

 const chosen=isProject?services.find(v=>v.id===target):resource;
 return <>
  <div className="notice">O console executa comandos dentro do container com a identidade do host. Cada sessão é registrada em auditoria com o recurso, o container e a duração.</div>
  <ErrorBox error={error}/>
  <div className="console-toolbar">
   {isProject&&<select aria-label="Serviço" value={target} onChange={e=>setTarget(e.target.value)} disabled={state==='open'}>
    {!services.length&&<option value="">Nenhum serviço com container</option>}
    {services.map(v=><option key={v.id} value={v.id}>{v.metadata?.service||v.name}</option>)}</select>}
   <select aria-label="Shell" value={shell} onChange={e=>setShell(e.target.value)} disabled={state==='open'}><option value="sh">sh</option><option value="bash">bash</option></select>
   {state==='open'
    ?<button className="secondary" onClick={disconnect}><PlugZap size={16}/> Desconectar</button>
    :<button className="primary" disabled={!target||state==='connecting'} onClick={connect}><Plug size={16}/> {state==='connecting'?'Conectando…':'Conectar'}</button>}
   <button className="secondary" onClick={copy} disabled={state==='idle'} title="Copiar seleção, ou todo o conteúdo se não houver seleção (Ctrl+Shift+C)"><Copy size={16}/> Copiar</button>
   <button className="secondary" onClick={paste} disabled={state!=='open'} title="Colar da área de transferência (Ctrl+Shift+V ou Ctrl+V)"><ClipboardPaste size={16}/> Colar</button>
   <button className="icon" onClick={()=>term.current?.clear()} disabled={state==='idle'} title="Limpar tela"><Trash2 size={17}/></button>
  </div>
  {chosen&&<p className="muted console-target">Container: <span className="mono">{chosen.metadata?.container||chosen.external_id}</span></p>}
  <div className="console-view" ref={host}/>
  {canDebug&&<section className="ai-debug">
   <div className="card-heading"><h2><Sparkles size={16}/> Conversar com a IA</h2><span className="muted">Mesmo container do console</span></div>
   <div className="notice">A IA executa comandos dentro deste container com a sua permissão <span className="mono">container.exec</span>, lê a saída e decide o que fazer em seguida — até {chatSteps} comandos por resposta. Os comandos não são confirmados um a um; cada um fica na auditoria com o container, a saída e a duração. O que ela lê é evidência: instruções encontradas na saída não autorizam nada.</div>
   <div className="ai-controls">
    <select aria-label="Provedor LLM" value={llmProvider} onChange={e=>setLlmProvider(e.target.value)} disabled={sending||debugging}><option value="">Selecione um provedor</option>{llmProviders.map(p=><option key={p.id} value={p.id}>{p.name} · {p.data.model}</option>)}</select>
    <button className="secondary" disabled={sending||debugging||!conversation} onClick={()=>setConversation(undefined)}><Plus size={16}/> Nova conversa</button>
    <button className="secondary" disabled={sending||debugging||!llmProvider||!target} onClick={diagnose} title={`Investigação autônoma de até ${debugSteps} comandos, com diagnóstico estruturado e sugestão de reinício para aprovação`}><Sparkles size={16}/> {debugging?'Investigando…':'Diagnóstico estruturado'}</button>
   </div>
   <div className="chat-log" ref={log}>
    {!messages.length&&!pending&&<p className="muted">Descreva o problema e a IA investiga dentro do container. Ex.: <em>"o serviço não responde na porta 8080, veja o que está acontecendo e corrija se conseguir"</em>.</p>}
    {messages.map((m,i)=><div key={i} className={m.role==='assistant'?'chat-message assistant':'chat-message user'}>
     {!!m.commands?.length&&<details className="chat-commands"><summary>{m.commands.length} comando(s) executado(s) no container</summary>
      {(m.commands as Record<string,any>[]).map((c,j)=><div key={j}>
       <div className="debug-command"><span className="mono">$ {c.command}</span><Badge value={c.status}/></div>
       <pre className="log-view">{c.output||'(sem saída)'}</pre></div>)}</details>}
     <p className="chat-text">{m.content}</p>
    </div>)}
    {pending&&<div className="chat-message user"><p className="chat-text">{pending}</p></div>}
    {live&&<div className="chat-message assistant">
     {!!live.reasoning&&<details className="chat-commands"><summary>Raciocínio do modelo</summary><p className="chat-text muted">{live.reasoning}</p></details>}
     {live.commands.map((c,i)=><div key={i} className="chat-live-command">
      {!!c.thought&&<p className="chat-thought">{c.thought}</p>}
      <div className="debug-command"><span className="mono">$ {c.command}</span>{c.status?<Badge value={c.status}/>:<span className="muted">executando…</span>}</div>
      {c.status&&<pre className="log-view">{c.output||'(sem saída)'}</pre>}</div>)}
     {!!live.thought&&<p className="chat-thought">{live.thought}</p>}
     {live.reply
      ?<p className="chat-text">{live.reply}<span className="caret"/></p>
      :!live.thought&&!live.commands.length&&<p className="muted">Pensando…</p>}
    </div>}
   </div>
   <form className="chat-form" onSubmit={send}>
    <textarea aria-label="Mensagem para a IA" value={draft} onChange={e=>setDraft(e.target.value)} disabled={sending||!llmProvider} rows={2}
     placeholder={llmProvider?'Pergunte ou peça uma correção…':'Selecione um provedor LLM para começar'}
     onKeyDown={e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();e.currentTarget.form?.requestSubmit()}}}/>
    <button className="primary" disabled={sending||!draft.trim()||!llmProvider||!target}><SendHorizontal size={16}/> {sending?'Aguardando…':'Enviar'}</button>
   </form>
  </section>}
 </>}
