import {useCallback,useEffect,useRef,useState} from 'react';
import {ClipboardCopy,ClipboardPaste,Play,Square} from 'lucide-react';
import {FitAddon} from '@xterm/addon-fit';
import {Terminal} from '@xterm/xterm';
import '@xterm/xterm/css/xterm.css';
import {allowed,api,type Resource,type Session} from './api';
import {ErrorBox} from './components';

const pasteHint='Colar pelo botão exige HTTPS. Use Ctrl+V, que funciona sempre.';

// A console needs exactly one container. Containers carry their own id, compose
// services carry it in metadata, and a compose project has none of its own — one
// of its services has to be chosen first.
export function consoleTarget(r:Resource):'direct'|'select'|null{
 if((r.provider==='docker'||r.provider==='podman')&&(r.type==='docker_container'||r.type==='podman_container'))return 'direct';
 if((r.provider==='dockercompose'||r.provider==='podmancompose')&&r.type==='docker_compose_service')return 'direct';
 if((r.provider==='dockercompose'||r.provider==='podmancompose')&&(r.type==='docker_compose_project'||r.type==='podman_compose_project'))return 'select';
 return null;
}

export function consoleVisible(session:Session,r:Resource){return allowed(session,'container.exec')&&consoleTarget(r)!==null}

function bufferText(t:Terminal){
 const b=t.buffer.active;const lines:string[]=[];
 for(let i=0;i<b.length;i++)lines.push(b.getLine(i)?.translateToString(true)??'');
 return lines.join('\n').replace(/\n+$/,'');
}

// document.execCommand is deprecated but it is the only copy path that works
// outside a secure context, which is where this UI runs over plain HTTP.
function legacyCopy(text:string){
 const area=document.createElement('textarea');
 area.value=text;area.style.position='fixed';area.style.opacity='0';
 document.body.appendChild(area);area.select();
 try{return document.execCommand('copy')}catch{return false}finally{document.body.removeChild(area)}
}

export function Console({resource,notify}:{resource:Resource;notify:(s:string)=>void}){
 const mode=consoleTarget(resource);
 const [services,setServices]=useState<Resource[]>([]);
 const [target,setTarget]=useState(mode==='direct'?resource.id:'');
 const [shell,setShell]=useState('sh');
 const [status,setStatus]=useState<'idle'|'connecting'|'open'|'closed'>('idle');
 const [error,setError]=useState('');
 const holder=useRef<HTMLDivElement|null>(null);
 const term=useRef<Terminal|null>(null);
 const fit=useRef<FitAddon|null>(null);
 const socket=useRef<WebSocket|null>(null);

 useEffect(()=>{
  if(mode!=='select')return;
  api<Resource[]>('/resources')
   .then(list=>setServices(list.filter(r=>r.host_id===resource.host_id&&r.type==='docker_compose_service'&&String(r.metadata?.project??'')===resource.external_id)))
   .catch(e=>setError((e as Error).message));
 },[mode,resource.host_id,resource.external_id]);

 const copy=useCallback(async()=>{
  const t=term.current;if(!t)return;
  const text=t.hasSelection()?t.getSelection():bufferText(t);
  if(!text){notify('Nada para copiar.');return}
  try{
   if(window.isSecureContext&&navigator.clipboard)await navigator.clipboard.writeText(text);
   else if(!legacyCopy(text))throw new Error('copy refused');
   notify(t.hasSelection()?'Seleção copiada.':'Conteúdo do terminal copiado.');
  }catch{
   if(legacyCopy(text))notify('Conteúdo do terminal copiado.');
   else setError('Não foi possível copiar.');
  }
 },[notify]);

 // There is no clipboard read API outside a secure context. The button says so
 // instead of failing silently; Ctrl+V goes through xterm's own paste handling
 // and works regardless.
 const paste=useCallback(async()=>{
  const ws=socket.current;const t=term.current;
  if(!ws||ws.readyState!==WebSocket.OPEN)return;
  if(!window.isSecureContext||!navigator.clipboard?.readText){setError(pasteHint);return}
  try{
   const text=await navigator.clipboard.readText();
   if(text)ws.send(new TextEncoder().encode(text));
   t?.focus();
  }catch{setError(pasteHint)}
 },[]);

 const disconnect=useCallback(()=>{
  socket.current?.close(1000,'closed by user');socket.current=null;
  term.current?.dispose();term.current=null;fit.current=null;
  setStatus('idle');
 },[]);

 const connect=useCallback(()=>{
  const el=holder.current;
  if(!el||!target||socket.current)return;
  setError('');setStatus('connecting');
  const t=new Terminal({fontSize:13,fontFamily:'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',cursorBlink:true,scrollback:5000,theme:{background:'#0b1020',foreground:'#e6ebff'}});
  const f=new FitAddon();
  t.loadAddon(f);t.open(el);f.fit();
  term.current=t;fit.current=f;
  t.attachCustomKeyEventHandler(ev=>{
   if(ev.type!=='keydown'||!ev.ctrlKey||!ev.shiftKey)return true;
   const key=ev.key.toLowerCase();
   if(key==='c'){void copy();return false}
   if(key==='v'){void paste();return false}
   return true;
  });
  const scheme=location.protocol==='https:'?'wss':'ws';
  const ws=new WebSocket(`${scheme}://${location.host}/api/v1/resources/${target}/console?shell=${encodeURIComponent(shell)}&rows=${t.rows}&cols=${t.cols}`);
  ws.binaryType='arraybuffer';
  socket.current=ws;
  const encoder=new TextEncoder();
  ws.onopen=()=>{setStatus('open');t.focus()};
  ws.onmessage=ev=>t.write(new Uint8Array(ev.data as ArrayBuffer));
  ws.onclose=ev=>{
   setStatus('closed');
   if(ev.code!==1000)setError(ev.reason||'Conexão encerrada. Sem permissão container.exec, ou a origem não confere com PUBLIC_ORIGIN.');
   socket.current=null;
  };
  t.onData(d=>{if(ws.readyState===WebSocket.OPEN)ws.send(encoder.encode(d))});
 },[target,shell,copy,paste]);

 useEffect(()=>{
  const el=holder.current;if(!el)return;
  const observer=new ResizeObserver(()=>{
   const t=term.current,f=fit.current,ws=socket.current;
   if(!t||!f)return;
   f.fit();
   if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({rows:t.rows,cols:t.cols}));
  });
  observer.observe(el);
  return()=>observer.disconnect();
 },[]);

 useEffect(()=>()=>{socket.current?.close();term.current?.dispose()},[]);

 const live=status==='open'||status==='connecting';
 return <>
  <div className="notice">Sessão interativa dentro do container. Os comandos digitados não são gravados na auditoria — só a abertura e o encerramento da sessão. A saída não é redigida.</div>
  <ErrorBox error={error}/>
  <div className="console-toolbar">
   {mode==='select'&&<select aria-label="Serviço" value={target} onChange={e=>setTarget(e.target.value)} disabled={live}>
    <option value="">Selecione um serviço</option>
    {services.map(s=><option key={s.id} value={s.id}>{s.name} · {s.state}</option>)}
   </select>}
   <select aria-label="Shell" value={shell} onChange={e=>setShell(e.target.value)} disabled={live}>
    <option value="sh">sh</option>
    <option value="bash">bash</option>
   </select>
   {live
    ?<button className="secondary" onClick={disconnect}><Square size={16}/> Encerrar</button>
    :<button className="primary" disabled={!target} onClick={connect}><Play size={16}/> Conectar</button>}
   <button className="secondary" onClick={()=>void copy()} disabled={status!=='open'}><ClipboardCopy size={16}/> Copiar</button>
   <button className="secondary" onClick={()=>void paste()} disabled={status!=='open'}><ClipboardPaste size={16}/> Colar</button>
   <span className="console-status">{status==='open'?'conectado':status==='connecting'?'conectando…':status==='closed'?'encerrado':'desconectado'}</span>
  </div>
  <div className="console-surface" ref={holder}/>
  <p className="console-hint">Ctrl+Shift+C copia a seleção, ou a tela inteira se não houver seleção. Ctrl+Shift+V cola. Ctrl+V também cola e não depende de HTTPS. Sessões expiram em 30 minutos.</p>
 </>;
}
