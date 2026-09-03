import {readFileSync,writeFileSync} from 'node:fs';
// JSON is valid YAML 1.2; generate from registered routes to prevent undocumented endpoints.
const source=readFileSync('internal/api/server.go','utf8');
const routes=[...source.matchAll(/(?:s\.route\(|s\.Mux\.HandleFunc\()"(GET|POST|PUT|DELETE) (\/api\/v1[^" ]*)"/g)];
const ref=name=>({$ref:'#/components/schemas/'+name});
const schemas={
 Error:{type:'object',required:['error'],properties:{error:{type:'string'}}},
 Login:{type:'object',required:['login','password'],properties:{login:{type:'string'},password:{type:'string',format:'password'},code:{type:'string',pattern:'^[0-9]{6}$'},method:{type:'string',enum:['local','ldap']}}},
 Host:{type:'object',required:['name','hostname','port','username','auth_method','environment','fingerprint','fingerprint_confirmed'],properties:{name:{type:'string'},description:{type:'string'},hostname:{type:'string'},port:{type:'integer',minimum:1,maximum:65535},username:{type:'string'},auth_method:{enum:['key','agent','password']},credential:{type:'string',writeOnly:true},fingerprint:{type:'string'},fingerprint_confirmed:{type:'boolean'},environment:{type:'string'},groups:{type:'array',items:{type:'string'}},tags:{type:'array',items:{type:'string'}},enabled:{type:'boolean'},bastion_id:{type:'string'}}},
 Resource:{type:'object',properties:Object.fromEntries(['id','host_id','provider','type','name','external_id','namespace','state','health','environment'].map(k=>[k,{type:'string'}]).concat([['capabilities',{type:'array',items:{type:'string'}}],['metadata',{type:'object'}]]))},
 OperationRequest:{type:'object',required:['resource_id','action','reason'],properties:{resource_id:{type:'string'},action:{type:'string',description:'Must be an advertised capability authorized for this resource.'},parameters:{type:'object',additionalProperties:true},reason:{type:'string',minLength:3,maxLength:2000}}},
 Operation:{type:'object',properties:{id:{type:'string'},resource_id:{type:'string'},action:{type:'string'},state:{enum:['queued','waiting_approval','running','succeeded','failed','cancelled','timeout','rejected']},risk:{enum:['low','medium','high']},approval_by:{type:'string'},result:{type:'string'},error:{type:'string'},created_at:{type:'string',format:'date-time'}}},
 Object:{type:'object',required:['name','data'],properties:{id:{type:'string',readOnly:true},name:{type:'string'},environment:{type:'string'},data:{type:'object',additionalProperties:true}}},
 Provider:{type:'object',required:['name','data'],properties:{name:{type:'string'},environment:{type:'string'},data:{type:'object',properties:{base_url:{type:'string',format:'uri'},model:{type:'string'},provider_type:{type:'string'},api_key:{type:'string',writeOnly:true},enabled:{type:'boolean'},timeout:{type:'number',minimum:1,maximum:180},max_context:{type:'integer'}}}}},
 ContainerSpec:{type:'object',required:['name','image','memory_mb','cpus','restart_policy'],properties:{name:{type:'string',maxLength:63},image:{type:'string'},registry_id:{type:'string'},environment:{type:'object',additionalProperties:{type:'string'},writeOnly:true},memory_mb:{type:'integer',minimum:16,maximum:262144},cpus:{type:'number',minimum:0.1,maximum:64},read_only:{type:'boolean'},user:{type:'string',description:'UID[:GID]'},restart_policy:{enum:['no','always','unless-stopped','on-failure']},ports:{type:'array',maxItems:32,items:{type:'object',properties:{container:{type:'integer'},host:{type:'integer'},protocol:{enum:['tcp','udp']},bind_ip:{enum:['127.0.0.1','0.0.0.0']}}}}}},
 Provision:{type:'object',required:['host_id','spec','reason'],properties:{host_id:{type:'string'},spec:ref('ContainerSpec'),reason:{type:'string',minLength:3}}},
 Approval:{type:'object',required:['approve','reason'],properties:{approve:{type:'boolean'},reason:{type:'string',minLength:3}}},
 Cluster:{type:'object',required:['name','environment','kubeconfig'],properties:{name:{type:'string'},environment:{type:'string'},kubeconfig:{type:'string',writeOnly:true}}},
 Analyze:{type:'object',required:['resource_id','provider_id'],properties:{resource_id:{type:'string'},provider_id:{type:'string'},question:{type:'string'}}},
 Tool:{type:'object',required:['tool','resource_id','reason','recommendation_id'],properties:{tool:{enum:['restart_container','restart_service','restart_deployment']},resource_id:{type:'string'},reason:{type:'string'},recommendation_id:{type:'string'}}}
};
const spec={openapi:'3.1.0',info:{title:'infra-orchestrator API',version:'0.1.0',description:'Authenticated infrastructure control plane. All remote mutations pass through RBAC, policy and the operation queue. Responses never expose stored credentials.'},servers:[{url:'/'}],security:[{session:[]},{bearer:[]}],paths:{},components:{securitySchemes:{session:{type:'apiKey',in:'cookie',name:'io_session'},bearer:{type:'http',scheme:'bearer'}},schemas}};
for(const [,method,path] of routes){
 const lower=method.toLowerCase(),op={operationId:(lower+'_'+path).replace(/[^A-Za-z0-9_]/g,'_'),summary:method+' '+path,tags:[path.split('/')[3]],responses:{'200':{description:'Successful query or mutation'},'400':{description:'Invalid structured input',content:{'application/json':{schema:ref('Error')}}},'401':{description:'Authentication required'},'403':{description:'RBAC, policy, MFA, environment or CSRF denied'},'404':{description:'Resource not found'},'429':{description:'Rate limit exceeded'}}};
 const params=[...path.matchAll(/\{([^}]+)\}/g)].map(([,name])=>({name,in:'path',required:true,schema:{type:'string'}}));
 if(method!=='GET')params.push({name:'X-CSRF-Token',in:'header',required:false,description:'Required for cookie authentication; value from io_csrf cookie.',schema:{type:'string'}});
 if(method==='POST'&&(/operations$|operations\/batch$|provisioning|deployments\/execute|\/rollback$|agents\/tools$/.test(path)))params.push({name:'Idempotency-Key',in:'header',required:true,schema:{type:'string',maxLength:128}});
 if(path.endsWith('/logs'))params.push({name:'tail',in:'query',schema:{type:'integer',minimum:1,maximum:2000,default:200}},{name:'download',in:'query',schema:{type:'boolean'}});
 if(path.endsWith('/read'))params.push({name:'action',in:'query',required:true,schema:{type:'string',enum:['status','inspect','stats','describe','events','rollout_status','rollout_history']}});
 if(path.endsWith('/events')){params.push({name:'Last-Event-ID',in:'header',schema:{type:'string'}});op.responses['200']={description:'Persistent event stream',content:{'text/event-stream':{schema:{type:'string'}}}};}
 if(params.length)op.parameters=params;
 if(/auth\/(login|config|oidc\/start|oidc\/callback)$|\/openapi$/.test(path))op.security=[];
 let schema;
 if(method==='POST'&&path.endsWith('/auth/login'))schema=ref('Login');
 else if(/POST|PUT/.test(method)&&/\/hosts(?:\/\{id\})?$/.test(path))schema=ref('Host');
 else if(method==='POST'&&path.endsWith('/operations'))schema=ref('OperationRequest');
 else if(path.endsWith('/approve'))schema=ref('Approval');
 else if(path.endsWith('/provisioning/containers'))schema=ref('Provision');
 else if(path.endsWith('/kubernetes/clusters'))schema=ref('Cluster');
 else if(path.endsWith('/agents/analyze'))schema=ref('Analyze');
 else if(path.endsWith('/agents/tools'))schema=ref('Tool');
 else if(/POST|PUT/.test(method)&&/\/llm\/providers(?:\/\{id\})?$/.test(path))schema=ref('Provider');
 else if(/POST|PUT/.test(method)&&path.includes('{kind}'))schema=ref('Object');
 else if(/POST|PUT/.test(method))schema={type:'object',additionalProperties:true,description:'Endpoint-specific structured fields; see module documentation and source request type.'};
 if(schema)op.requestBody={required:true,content:{'application/json':{schema}}};
 if(method==='POST'&&/operations$|provisioning\/containers$|deployments\/execute$|agents\/tools$/.test(path))op.responses['202']={description:'Operation queued or waiting for approval',content:{'application/json':{schema:ref('Operation')}}};
 spec.paths[path]??={};spec.paths[path][lower]=op;
}
writeFileSync('docs/openapi.yaml',JSON.stringify(spec,null,2)+'\n');
console.log(`Documented ${routes.length} registered API routes.`);
