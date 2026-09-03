export type User={id:string;username:string;email:string;role:string;enabled:boolean;environments:string[];mfa_required:boolean;mfa_enabled:boolean;force_password_change:boolean;service_account:boolean};
export type Session={user:User;permissions:string[];mfa:boolean;session_id?:string;name?:string};
export type Host={id:string;name:string;description:string;hostname:string;port:number;username:string;auth_method:string;fingerprint:string;environment:string;groups:string[];tags:string[];enabled:boolean;bastion_id:string;state:string;facts:Record<string,any>;last_seen?:string};
export type Resource={id:string;host_id:string;name:string;provider:string;type:string;external_id:string;namespace:string;environment:string;state:string;health:string;capabilities:string[];metadata:Record<string,any>};
export type Operation={id:string;requester:string;resource_id:string;action:string;environment:string;risk:string;state:string;reason:string;created_at:string;result:string;error:string;approval_by:string;parameters:Record<string,any>};
export type Obj={id:string;kind:string;name:string;environment:string;data:Record<string,any>;created_at:string};
export const environments=['development','testing','homologation','staging','production'];
export function allowed(session:Session,permission:string){return session.permissions.includes('*')||session.permissions.includes(permission)}
export function csrf(){return document.cookie.split('; ').find(c=>c.startsWith('io_csrf='))?.split('=')[1]||''}
export async function api<T=any>(path:string,method='GET',body?:unknown):Promise<T>{const res=await fetch('/api/v1'+path,{method,credentials:'same-origin',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf(),...(method==='POST'?{'Idempotency-Key':crypto.randomUUID()}: {})},...(body===undefined?{}:{body:JSON.stringify(body)})});const data=await res.json().catch(()=>({error:'Resposta inválida do servidor'}));if(!res.ok)throw new Error(data.error||`HTTP ${res.status}`);return data as T}
export function when(s?:string){return s?new Date(s).toLocaleString('pt-BR',{dateStyle:'short',timeStyle:'short'}):'—'}
