// Paired A10 cache observation. All captures/secrets belong in a private directory.
import { parseArgs } from 'node:util';
import { resolve } from 'node:path';
import{createHash,X509Certificate}from'node:crypto';
import {createSecureServer} from 'node:http2';import https from 'node:https';import {spawn} from 'node:child_process';import {once} from 'node:events';import{readFileSync,writeFileSync,appendFileSync,mkdirSync,existsSync,mkdtempSync}from'node:fs';import{join}from'node:path';import{setTimeout as delay}from'node:timers/promises';

const {values}=parseArgs({options:{out:{type:'string'},actor:{type:'string'},chrome:{type:'string'},build:{type:'string'},client:{type:'string'},profile:{type:'string'},peer:{type:'string'},cert:{type:'string'},key:{type:'string'},scenarios:{type:'string'},protocols:{type:'string'}}});
for(const key of ['out','actor','cert','key','scenarios','protocols'])if(!values[key])throw Error(`missing --${key}`);
if(!['chrome','client'].includes(values.actor))throw Error('actor must be chrome or client');
if(values.actor==='chrome'&&(!values.chrome||!values.build))throw Error('Chrome requires --chrome and --build');
if(values.actor==='client'&&(!values.client||!values.profile))throw Error('Client requires --client and explicit --profile JSON');
const base=resolve(values.out),chrome=values.chrome,scenarios=JSON.parse(readFileSync(values.scenarios)),results=[];
mkdirSync(base,{mode:0o700});writeFileSync(join(base,'arguments.json'),JSON.stringify(values,null,2),{mode:0o600});
for(let cohort=1;cohort<=2;cohort++)for(const protocol of values.protocols.split(',')){
 if(!['h1','h2','h3'].includes(protocol))throw Error('unsupported protocol');
 const dir=join(base,`${values.actor}-${cohort}-${protocol}`);mkdirSync(dir,{mode:0o700});const seen=[],counts=new Map();
 const handler=(req,res)=>{const u=new URL(req.url,'https://local');const s=scenarios.find(s=>u.pathname==='/case/'+s.id);const n=(counts.get(u.pathname)||0)+1;counts.set(u.pathname,n);const row={url:req.url,n,protocol:req.httpVersion,headers:req.rawHeaders,at:Date.now()};seen.push(row);appendFileSync(join(dir,'requests.ndjson'),JSON.stringify(row)+'\n');
  if(!s){res.writeHead(200,{'cache-control':'no-store','content-type':'text/html'});res.end('<!doctype html><link rel="icon" href="data:,"><body>cache witness</body>');return}
  const date=new Date(),headers={'cache-control':s.cache_control,'date':date.toUTCString(),'age':'120','expires':new Date(date.getTime()+(s.expires==='future'?600:-600)*1000).toUTCString(),'content-type':'text/plain'};
  if(s.validators==='both'||s.validators==='etag')headers.etag='"v1"';if(s.validators==='both'||s.validators==='modified')headers['last-modified']='Wed, 21 Oct 2026 07:28:00 GMT';
  const status=n>1&&!s.changed&&(req.headers['if-none-match']||req.headers['if-modified-since'])?304:200;row.response={status,headers};res.writeHead(status,headers);res.end(status===304?'':`body-${s.id}-${n}`);
 };

 const opts={key:readFileSync(values.key),cert:readFileSync(values.cert)};
 let server,peer,origin;
 const observed=()=>protocol==='h3'?readFileSync(join(dir,'peer/requests.ndjson'),'utf8').trim().split('\n').filter(Boolean).map(line=>{const r=JSON.parse(line);return {...r,headers:Object.entries(r.headers).flatMap(([k,v])=>v.flatMap(x=>[k.toLowerCase(),x]))}}):seen;
 if(protocol==='h3'){
  if(!values.peer)throw Error('H3 requires --peer');
  peer=spawn(values.peer,['-out',join(dir,'peer'),'-cert',values.cert,'-key',values.key,'-scenarios',values.scenarios],{stdio:['ignore','pipe','pipe']});peer.stderr.on('data',b=>appendFileSync(join(dir,'peer.log'),b));
  for(let i=0;i<400&&!existsSync(join(dir,'peer/address.json'));i++){if(peer.exitCode!==null)throw Error('peer exited');await delay(25)}
  ({origin}=JSON.parse(readFileSync(join(dir,'peer/address.json'))));
 }else{
  server=protocol==='h2'?createSecureServer({...opts,allowHTTP1:false},handler):https.createServer(opts,handler);
  server.on('keylog',line=>appendFileSync(join(dir,'tls.keys'),line));server.listen(0,'127.0.0.1');await once(server,'listening');origin=`https://127.0.0.1:${server.address().port}`;
 }
 try{
 if(values.actor==='client'){
  const output=join(dir,'api.json');const actor=spawn(values.client,['-origin',origin,'-scenarios',values.scenarios,'-out',output,'-profile',values.profile,...(protocol==='h3'?['-h3']:[])],{stdio:['ignore','pipe','pipe']});
  actor.stdout.on('data',b=>appendFileSync(join(dir,'actor.log'),b));actor.stderr.on('data',b=>appendFileSync(join(dir,'actor.log'),b));const[code]=await once(actor,'exit');if(code!==0)throw Error('actor exit '+code);
  for(const row of JSON.parse(readFileSync(output)))results.push({...row,cohort,protocol,origin,requests:observed().filter(r=>r.url==='/case/'+row.id)});
  writeFileSync(join(base,'results.json'),JSON.stringify(results,null,2),{mode:0o600});
 }else{
 const udd=mkdtempSync(join(dir,'user-data-'));const flags=[`--user-data-dir=${udd}`,'--remote-debugging-port=0','--no-startup-window',...(protocol==='h3'?[`--origin-to-force-quic-on=${new URL(origin).host}`,'--enable-quic']:[]),'--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps',`--ignore-certificate-errors-spki-list=${createHash('sha256').update(new X509Certificate(opts.cert).publicKey.export({type:'spki',format:'der'})).digest('base64')}`,`--log-net-log=${join(dir,'chrome-netlog.json')}`];writeFileSync(join(dir,'flags.json'),JSON.stringify(flags));const child=spawn(chrome,flags,{stdio:['ignore','pipe','pipe'],env:Object.fromEntries(Object.entries(process.env).filter(([k])=>k.toUpperCase()!=='SSLKEYLOGFILE'))});child.stdout.on('data',b=>appendFileSync(join(dir,'chrome.log'),b));child.stderr.on('data',b=>appendFileSync(join(dir,'chrome.log'),b));let ws;
 try{for(let i=0;i<300&&!existsSync(join(udd,'DevToolsActivePort'));i++){if(child.exitCode!==null)throw Error('Chrome exited');await delay(50)}const[port,path]=readFileSync(join(udd,'DevToolsActivePort'),'utf8').split('\n');ws=new WebSocket(`ws://127.0.0.1:${port}${path}`);await once(ws,'open');let seq=0;const pending=new Map(),loaded=new Set();ws.onmessage=ev=>{const m=JSON.parse(ev.data);appendFileSync(join(dir,'cdp.ndjson'),JSON.stringify(m)+'\n');if(m.method==='Page.lifecycleEvent'&&m.params.name==='DOMContentLoaded')loaded.add(m.sessionId+':'+m.params.loaderId);if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);clearTimeout(p.timer);m.error?p.reject(Error(JSON.stringify(m.error))):p.resolve(m.result)}};const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq,timer=setTimeout(()=>{pending.delete(id);reject(Error(method+' timeout'))},20000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}))});const version=await send('Browser.getVersion');if(version.product!==`Chrome/${values.build}`)throw Error('wrong build '+version.product);writeFileSync(join(dir,'version.json'),JSON.stringify(version));const{targetId}=await send('Target.createTarget',{url:'about:blank',newWindow:true,background:true,windowState:'minimized'});const{windowId}=await send('Browser.getWindowForTarget',{targetId});await send('Browser.setWindowBounds',{windowId,bounds:{windowState:'minimized'}});const{sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});await send('Page.enable',{},sessionId);await send('Page.setLifecycleEventsEnabled',{enabled:true},sessionId);await send('Network.enable',{},sessionId);const nav=await send('Page.navigate',{url:origin+'/start'},sessionId);for(let i=0;i<400&&!loaded.has(sessionId+':'+nav.loaderId);i++)await delay(10);if(!loaded.has(sessionId+':'+nav.loaderId))throw Error('page not loaded');
 for(const s of scenarios){const expression=`(async()=>{const results=[];for(let i=0;i<2;i++){const r=await fetch(${JSON.stringify('/case/'+s.id)},{cache:'default'});results.push({status:r.status,body:await r.text()})}return results})()`;const r=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);if(r.exceptionDetails)throw Error(JSON.stringify(r.exceptionDetails));const row={cohort,protocol,id:s.id,origin,api:r.result.value,requests:observed().filter(r=>r.url==='/case/'+s.id)};results.push(row);writeFileSync(join(base,'results.json'),JSON.stringify(results,null,2));console.log(JSON.stringify({cohort,protocol,id:s.id,origin_requests:row.requests.length,validators:row.requests.map(r=>r.headers.filter((_,i)=>i%2===0&&r.headers[i].toLowerCase().startsWith('if-')))}));if(s.id==='single-600'&&row.requests.length!==1)throw Error('positive cache hit missing');}
 await send('Browser.close');
 }finally{ws?.close();if(child.exitCode===null){await Promise.race([once(child,'exit'),delay(5000)]);if(child.exitCode===null)child.kill('SIGTERM')}}

 }
 }finally{
  if(peer){peer.kill('SIGTERM');await once(peer,'exit')}
  if(server){server.closeAllConnections?.();await new Promise(r=>server.close(r))}
 }
}
