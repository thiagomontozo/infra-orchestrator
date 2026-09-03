import {useEffect,useRef,type ReactNode} from 'react';
import {X,Inbox,LoaderCircle} from 'lucide-react';
export function Badge({value}:{value:string}){return <span className={`badge state-${value?.toLowerCase().replaceAll(' ','-')}`}>{value||'unknown'}</span>}
export function Empty({title='Nenhum registro',children}:{title?:string;children?:ReactNode}){return <div className="empty"><Inbox size={34}/><h3>{title}</h3>{children&&<p>{children}</p>}</div>}
export function Loading(){return <div className="loading" role="status"><LoaderCircle className="spin"/> Carregando dados…</div>}
export function Modal({title,children,onClose,wide=false}:{title:string;children:ReactNode;onClose:()=>void;wide?:boolean}){const ref=useRef<HTMLDialogElement>(null);useEffect(()=>{const d=ref.current;d?.showModal();return()=>d?.close()},[]);return <dialog ref={ref} className={wide?'modal wide':'modal'} onCancel={onClose}><header><h2>{title}</h2><button className="icon" onClick={onClose} aria-label="Fechar"><X/></button></header>{children}</dialog>}
export function Field({label,children,hint}:{label:string;children:ReactNode;hint?:string}){return <div className="field"><label><span>{label}</span>{children}</label>{hint&&<small>{hint}</small>}</div>}
export function ErrorBox({error}:{error:string}){return error?<div className="error" role="alert">{error}</div>:null}
export function JsonView({value}:{value:unknown}){return <pre className="json">{typeof value==='string'?value:JSON.stringify(value,null,2)}</pre>}
