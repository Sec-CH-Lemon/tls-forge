// Native observer only. No browser policy is selected here; the paired client
// reads an explicit executable JSON profile. Raw outputs stay private.
import {spawn} from 'node:child_process';
import {existsSync,mkdtempSync,readFileSync,writeFileSync,appendFileSync,rmSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
const[chrome,out,sampleText,...extra]=process.argv.slice(2);const scenario=JSON.parse(readFileSync(join(out,'scenario.json'),'utf8'));const samples=Number(sampleText??scenario.connections_per_cohort);
if(!Number.isInteger(samples)||samples<1||samples>4096)throw new Error('invalid sample count');
const config=JSON.parse(readFileSync(join(out,'address.json'),'utf8'));
const udd=mkdtempSync(join(tmpdir(),'tls-forge-a8-h3-'));
const flags=[`--user-data-dir=${udd}`,`--log-net-log=${join(out,'chrome-netlog.json')}`,'--remote-debugging-port=0','--no-startup-window','--no-first-run','--no-default-browser-check','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps','--disable-features=ChromeWhatsNewUI','--lang=en-US','--enable-quic','--ignore-certificate-errors',`--ignore-certificate-errors-spki-list=${config.spki}`,`--origin-to-force-quic-on=${new URL(config.origin).host}`,...extra];
const child=spawn(chrome,flags,{stdio:['ignore','pipe','pipe'],env:Object.fromEntries(Object.entries(process.env).filter(([name])=>name.toUpperCase()!=='SSLKEYLOGFILE'))});child.stdout.on('data',b=>appendFileSync(join(out,'chrome.log'),b));child.stderr.on('data',b=>appendFileSync(join(out,'chrome.log'),b));
const sleep=ms=>new Promise(r=>setTimeout(r,ms));let ws;
const pending=new Map();const loaded=new Set();let seq=0;
try{
 for(let i=0;i<300&&!existsSync(join(udd,'DevToolsActivePort'));i++){if(child.exitCode!==null)throw new Error('Chrome exited');await sleep(100);}
 const[port,path]=readFileSync(join(udd,'DevToolsActivePort'),'utf8').split('\n');ws=new WebSocket(`ws://127.0.0.1:${port}${path}`);await new Promise((r,j)=>{ws.onopen=r;ws.onerror=j;});
 ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.method==='Page.lifecycleEvent'&&m.params.name==='DOMContentLoaded')loaded.add(m.sessionId+':'+m.params.loaderId);if(m.id&&pending.has(m.id)){const{resolve,reject,timer}=pending.get(m.id);pending.delete(m.id);clearTimeout(timer);m.error?reject(new Error(JSON.stringify(m.error))):resolve(m.result);}};
 const send=(method,params={},sessionId)=>new Promise((resolve,reject)=>{const id=++seq;const timer=setTimeout(()=>{pending.delete(id);reject(new Error('CDP timeout '+method));},30000);pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})}));});
 const version=await send('Browser.getVersion');if(version.product!==`Chrome/${config.expected_version}`)throw new Error('browser version differs from pinned installer: '+version.product);const anchor=await send('Target.createTarget',{url:'about:blank',newWindow:true,background:true,windowState:'minimized'});let anchorWindow;for(let i=0;i<40;i++){anchorWindow=await send('Browser.getWindowForTarget',{targetId:anchor.targetId});if(anchorWindow.bounds.windowState==='minimized')break;await sleep(25);}if(anchorWindow.bounds.windowState!=='minimized')throw new Error('anchor window not minimized');const targetId=anchor.targetId;const{sessionId}=await send('Target.attachToTarget',{targetId,flatten:true});await send('Page.enable',{},sessionId);await send('Page.setLifecycleEventsEnabled',{enabled:true},sessionId);await send('Network.enable',{},sessionId);await send('Security.setIgnoreCertificateErrors',{ignore:true},sessionId);const offset=((await(await fetch(config.api+'/stats')).json()).connections??[]).length;const events=[];writeFileSync(join(out,'chrome-metadata.json'),JSON.stringify({version,flags,samples,scenario:'normal context,one persistent minimized tab per independent process;fresh document per navigation;server tickets disabled;peer closed only after3 completed H3 GETs;2 independent launches'},null,2));
 for(let n=0;n<samples;n++){
  try{
   let window;const windowStates=[];for(let i=0;i<40;i++){window=await send('Browser.getWindowForTarget',{targetId});windowStates.push({time:Date.now(),bounds:window.bounds});if(window.bounds.windowState==='minimized')break;await sleep(25);}appendFileSync(join(out,'window-states.jsonl'),JSON.stringify({case:n+1,states:windowStates})+'\n');if(window.bounds.windowState!=='minimized'||window.windowId!==anchorWindow.windowId)throw new Error('target not in minimized anchor window before navigation');
   const visible=await send('Runtime.evaluate',{expression:'({focus:document.hasFocus(),visibility:document.visibilityState})',returnByValue:true},sessionId);if(visible.result.value.focus||visible.result.value.visibility!=='hidden')throw new Error('tab not hidden/unfocused before navigation');const nav=await send('Page.navigate',{url:config.origin+scenario.requests[0].path},sessionId);appendFileSync(join(out,'navigate.jsonl'),JSON.stringify(nav)+'\n');
   let ready=false;
   for(let i=0;i<200;i++){const r=await send('Runtime.evaluate',{expression:'document.body?.textContent.includes("A8 H3 observed")',returnByValue:true},sessionId);if(loaded.has(sessionId+':'+nav.loaderId)&&r.result.value){ready=true;break;}await sleep(50);}
   if(!ready){const info=await send('Runtime.evaluate',{expression:'JSON.stringify({url:location.href,body:document.body?.textContent})',returnByValue:true},sessionId);writeFileSync(join(out,'failed-document.json'),JSON.stringify(info,null,2));throw new Error('navigation did not reach owned H3 peer');}
   const text=[];
   for(const stimulus of scenario.requests.slice(1)){
    await sleep(scenario.request_gap_ms);
    const expression=`fetch(${JSON.stringify(stimulus.path)},{headers:${JSON.stringify({[scenario.request_header.name]:scenario.request_header.value})}}).then(r=>r.text())`;
    const result=await send('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true},sessionId);
    if(result.exceptionDetails)throw new Error('fetch evaluation failed');text.push(result.result.value);
   }
   const r=await send('Runtime.evaluate',{expression:`({nav:performance.getEntriesByType('navigation').map(e=>e.nextHopProtocol),fetch:performance.getEntriesByType('resource').filter(e=>new URL(e.name).pathname.startsWith('/step')).map(e=>e.nextHopProtocol),navigator:{user_agent:navigator.userAgent,platform:navigator.platform,language:navigator.language}})`,returnByValue:true},sessionId);
   r.result.value.text=text;
   if(r.exceptionDetails)throw new Error('browser evaluation failed: '+JSON.stringify(r.exceptionDetails));const observed=r.result.value;
   if(observed.text.length!==2||observed.text.some(x=>!x.includes('A8 H3 observed'))||observed.nav.length!==1||observed.nav[0]!=='h3'||observed.fetch.length!==2||observed.fetch.some(x=>x!=='h3'))throw new Error('actual H3 response/sequence refused: '+JSON.stringify(observed));
   events.push({case:n+1,focus_before_navigation:visible.result.value,window:window.bounds,navigation:observed.nav,fetch:observed.fetch,navigator:observed.navigator});
   writeFileSync(join(out,'browser-cases.json'),JSON.stringify(events,null,2));
  }finally{await fetch(config.api+'/close',{method:'POST'});}
  let settled=false;
  for(let i=0;i<100;i++){
   const stats=await(await fetch(config.api+'/stats')).json();const connections=stats.connections??[];
   if(connections.length>offset+n+1)throw new Error('extra connection in cold context');
   if(connections.length===offset+n+1&&connections[offset+n].closed&&Object.keys(connections[offset+n].requests).length===3){settled=true;break;}
   await sleep(20);
  }
  if(!settled)throw new Error('context did not close exactly one3-request H3 connection');
 }
 await send('Browser.close');
}catch(e){writeFileSync(join(out,'driver-error.txt'),String(e.stack??e));if(ws?.readyState===WebSocket.OPEN)ws.send(JSON.stringify({id:++seq,method:'Browser.close'}));await sleep(1000);throw e;}
finally{if(ws)ws.close();for(const p of pending.values()){clearTimeout(p.timer);p.reject(new Error('driver closed'));}pending.clear();if(child.exitCode===null)child.kill('SIGTERM');await Promise.race([new Promise(r=>child.on('exit',r)),sleep(3000)]);if(child.exitCode===null)child.kill('SIGKILL');rmSync(udd,{recursive:true,force:true});}
