let csrf='',revision=0,setupCompleted=false;const el=id=>document.getElementById(id);const message=t=>el('message').textContent=t;
async function api(path,body){const r=await fetch('/admin/api/'+path,{method:body?'POST':'GET',cache:'no-store',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf,'X-Requested-With':'SecurityAppliance'},body:body?JSON.stringify(body):undefined});const data=await r.json();if(!r.ok)throw Error(data.error||'Request failed');return data;}
async function updateApi(form){const r=await fetch('/admin/api/updates',{method:'POST',headers:{'X-CSRF-Token':csrf,'X-Requested-With':'SecurityAppliance'},body:form});const data=await r.json();if(!r.ok)throw Error(data.error||'Update failed');return data;}
function requestAdminPassword(action){const password=window.prompt('Enter your current administrator password to '+action+'.');return password===null||password===''?null:password;}
async function load(){const auth=await api('auth');csrf=auth.csrf||'';document.body.classList.toggle('signed-out',!auth.authenticated);if(auth.authenticated){el('content').before(el('message'));}else{el('login').append(el('message'));}el('login').hidden=auth.authenticated;el('content').hidden=!auth.authenticated;el('logout').hidden=!auth.authenticated||Boolean(auth.buildMode);el('buildAuthBanner').hidden=!auth.buildMode;el('adminMenu').open=false;el('adminUsername').textContent=auth.authenticated?auth.username:'';el('adminAvatar').textContent=auth.authenticated?auth.username.slice(0,1).toUpperCase():'';if(!auth.authenticated)return;const data=await api('config');revision=data.revision;setupCompleted=data.completed;updateSetupNavigation();if(!setupCompleted){location.hash='first-deployment-setup';}else if(location.hash==='#first-deployment-setup'){location.hash='overview-panel';}showPage();for(const [k,v]of Object.entries(data.config)){const field=el('configform').elements[k];if(field)field.value=Array.isArray(v)?v.join(', '):v??'';}el('configform').elements.fqdn.value=data.config.hostname+'.'+data.config.domain;updateNetworkFields();updateServicePageIdentity(data.config);timezoneStatus().catch(e=>message(e.message));await Promise.all([services(),accounts(),operationsStatus(),sessionPolicyStatus()]);}
function values(){const v=Object.fromEntries(new FormData(el('configform')));const fqdn=(v.fqdn||'').trim().toLowerCase();const labels=fqdn.split('.');v.hostname=(v.hostname||'').trim().toLowerCase();if(labels.length<2||labels[0]!==v.hostname)throw Error('The FQDN must start with the appliance hostname.');v.domain=labels.slice(1).join('.');delete v.fqdn;for(const k of ['dns','ntp','admin_cidrs'])v[k]=v[k].split(',').map(x=>x.trim()).filter(Boolean);if(v.network_mode==='dhcp'){v.ip='';v.prefix='';v.gateway='';}return v;}
el('loginform').onsubmit=async e=>{e.preventDefault();try{await api('login',Object.fromEntries(new FormData(e.target)));e.target.reset();message('');await load();}catch(e){message(e.message);}};
el('logout').onclick=async()=>{try{await api('logout',{});await load();}catch(e){message(e.message);}};
el('configform').onsubmit=async e=>{e.preventDefault();try{if(!el('networkAcknowledge').checked)throw Error('Acknowledge the connection warning before applying configuration.');const password=el('configPassword').value;if(!password)throw Error('Enter the administrator password to apply configuration.');await api('timezone',{timezone:el('timezoneSelect').value,password});const saved=await api('setup/save',{config:values(),revision});revision=saved.revision;const r=await api('setup/apply',{revision,password});sessionStorage.setItem('networkToken',r.token);el('configPassword').value='';showPage();message('Configuration is applying. Reconnect if needed and confirm access within two minutes. Destination: '+r.address);}catch(e){message(e.message);}};
load().catch(e=>message(e.message));
async function timezoneStatus(){const r=await api('timezone');el('timezoneSelect').value=r.timezone;el('currentTimezone').textContent='Current timezone: '+r.timezone+'.';}
el('timezoneSave').onclick=async()=>{try{const password=el('configPassword').value;if(!password)throw Error('Enter the administrator password below before saving the timezone.');const r=await api('timezone',{timezone:el('timezoneSelect').value,password});el('currentTimezone').textContent='Current timezone: '+r.timezone+'.';el('configPassword').value='';message(r.notice);}catch(e){message(e.message);}};
function updateNetworkFields(){const disabled=el('configform').elements.network_mode.value==='dhcp';for(const name of ['ip','prefix','gateway'])el('configform').elements[name].disabled=disabled;}
el('configform').elements.network_mode.onchange=updateNetworkFields;
el('networkAcknowledge').onchange=()=>{el('applyConfiguration').disabled=!el('networkAcknowledge').checked;};
el('confirm').onclick=async()=>{try{const password=el('configPassword').value;if(!password)throw Error('Enter the administrator password to confirm access.');await api('setup/confirm',{token:sessionStorage.getItem('networkToken')||'',password});sessionStorage.removeItem('networkToken');el('configPassword').value='';el('networkAcknowledge').checked=false;el('applyConfiguration').disabled=true;showPage();message('Network settings confirmed.');}catch(e){message(e.message);}};
el('setupAcknowledged').onchange=()=>{el('complete').disabled=!el('setupAcknowledged').checked||!preflightReady;};
el('complete').onclick=async()=>{try{await api('setup/complete',{acknowledged:el('setupAcknowledged').checked});setupCompleted=true;el('setupAcknowledged').checked=false;el('complete').disabled=true;updateSetupNavigation();location.hash='overview-panel';showPage();message('First deployment setup complete.');}catch(e){message(e.message);}};
el('certstatus').onclick=async()=>{try{const r=await api('certificates');el('certdetails').textContent=r.fqdn+'\n'+r.details+'\n'+(r.enrolled?'CA certificate installed':'Bootstrap certificate');}catch(e){message(e.message);}};
el('certcsr').onclick=async()=>{const password=requestAdminPassword('generate or retrieve the certificate request');if(!password)return;try{const r=await api('certificates',{operation:'csr',password});el('csr').value=r.csr;message('CSR ready for '+r.fqdn+'. Copy the request to your CA.');}catch(e){message(e.message);}};
el('certdiscard').onclick=async()=>{if(!confirm('Discard the pending CSR? Any certificate signed for it will no longer be usable.'))return;const password=requestAdminPassword('discard the pending certificate request');if(!password)return;try{await api('certificates',{operation:'discard',password});el('csr').value='';message('Pending CSR discarded.');}catch(e){message(e.message);}};
el('certimport').onclick=async()=>{const password=requestAdminPassword('install the certificate');if(!password)return;try{const r=await api('certificates',{operation:'import',password,certificate:el('certificate').value,ca:el('ca').value,intermediates:el('intermediates').value});el('csr').value='';el('certdetails').textContent=r.details;message('Certificate installed. Connect using '+r.fqdn+' and trust your CA in the browser.');}catch(e){message(e.message);}};
el('changepassword').onclick=async()=>{try{if(el('newpassword').value!==el('repeatpassword').value)throw Error('New passwords do not match.');const password=requestAdminPassword('change your password');if(!password)return;await api('account/password',{password,new_password:el('newpassword').value});for(const id of ['newpassword','repeatpassword'])el(id).value='';await load();message('Password changed; all sessions signed out. Sign in with the new password.');}catch(e){message(e.message);}};
async function auditHistory(){try{const r=await api('audit');el('audit').textContent=r.events.map(v=>new Date(v.at*1000).toISOString()+' | '+v.actor+' | '+v.action+' | '+v.outcome).join('\n')||'No audit events.';}catch(e){message(e.message);}}
el('auditrefresh').onclick=auditHistory;

async function updateStatus(){
 const r=await api('updates');
 el('updateStatus').querySelector('p').textContent='Installed version: '+r.version+'. Previous version: '+(r.previousVersion||'unavailable')+'. Signature verification: '+(r.signatureVerification?'ready':'unavailable')+'. Rollback material: '+(r.rollbackAvailable?'available':'not present')+'.';
 const root=el('updateHistory');root.replaceChildren();
 const current=document.createElement('p');current.textContent='Installed: '+(r.installedAt?new Date(r.installedAt*1000).toLocaleString():'Unavailable')+' · Bundle SHA-256: '+(r.bundleSha256||'Unavailable')+' · Manifest SHA-256: '+(r.manifestSha256||'Unavailable')+' · Signing-key SHA-256: '+(r.signingKeySha256||'Unavailable')+' · Health: '+(r.healthResult||'Unavailable');root.append(current);
 for(const entry of (r.history||[]).slice().reverse()){const line=document.createElement('p');line.textContent=(entry.operation==='restore'?'Restored ':'Installed ')+(entry.version||'unknown')+' at '+new Date(entry.installedAt*1000).toLocaleString()+' · '+(entry.healthResult||'unknown');root.append(line);}
 el('restorePriorRelease').disabled=!r.rollbackAvailable;
}
el('restorePriorRelease').onclick=async()=>{if(!confirm('Restore the prior signed release? Management will restart and current update files will be replaced.'))return;const password=requestAdminPassword('restore the prior release');if(!password)return;try{await api('updates/restore',{confirmed:true,password});message('Prior release restored. Reconnecting to management.');setTimeout(()=>load().catch(()=>{}),6000);}catch(e){message(e.message);}};
el('installUpdate').onclick=async()=>{const file=el('updateBundle').files[0];if(!file){message('Select a signed appliance update bundle.');return;}if(!confirm('Install signed appliance update '+file.name+'? Management may restart.'))return;const password=requestAdminPassword('install the signed appliance update');if(!password)return;const form=new FormData();form.append('password',password);form.append('bundle',file,file.name);try{message('Verifying and installing the signed update.');const result=await updateApi(form);el('updateBundle').value='';message('Signed update '+result.version+' installed. Management may reconnect briefly.');setTimeout(()=>load().catch(()=>{}),6000);}catch(e){message(e.message);await updateStatus().catch(()=>{});}};

async function accounts(){
 const r=await api('accounts');const list=el('adminUsers');list.replaceChildren();
 for(const account of r.accounts){
  const row=document.createElement('div');row.className='admin-user-item';
  const identity=document.createElement('div');identity.className='admin-user-identity';
  const avatar=document.createElement('span');avatar.className='admin-user-avatar';avatar.textContent=account.username.slice(0,1).toUpperCase();
  const name=document.createElement('span');const strong=document.createElement('strong');strong.textContent=account.username;
  const detail=document.createElement('small');detail.textContent=(account.current?'Current session · ':'')+(account.enabled?'Enabled':'Disabled')+' · '+account.activeSessions+' active session(s) · Last login: '+(account.lastSuccessfulLogin?new Date(account.lastSuccessfulLogin*1000).toLocaleString():'Never');
  name.append(strong,detail);identity.append(avatar,name);row.append(identity);
  const actions=document.createElement('div');actions.className='admin-user-actions';
  const action=(label,operation)=>{const button=document.createElement('button');button.type='button';button.className='secondary';button.textContent=label;button.onclick=async()=>{if(!confirm(label+' for '+account.username+'?'))return;const password=requestAdminPassword(label.toLowerCase()+' for '+account.username);if(!password)return;try{await api('accounts',{operation,username:account.username,password});if(operation==='revoke-sessions'&&account.current){await load();return;}await accounts();message(label+' completed for '+account.username+'.');}catch(e){message(e.message);}};actions.append(button);};
  action('Revoke sessions','revoke-sessions');
  if(!account.current){action(account.enabled?'Disable':'Enable',account.enabled?'disable':'enable');action('Remove','delete');}
  row.append(actions);list.append(row);
 }
}
async function sessionPolicyStatus(){const r=await api('session-policy');el('idleMinutes').value=Math.round(r.idleSeconds/60);el('sessionPolicyResult').textContent='Current idle timeout: '+Math.round(r.idleSeconds/60)+' minutes.';}
el('saveIdleTimeout').onclick=async()=>{const value=Number(el('idleMinutes').value);if(!Number.isInteger(value)||value<5||value>60){message('Choose an idle timeout from 5 to 60 minutes.');return;}const password=requestAdminPassword('change the session idle timeout');if(!password)return;try{const r=await api('session-policy',{idleSeconds:value*60,password});el('sessionPolicyResult').textContent='Idle timeout saved: '+Math.round(r.idleSeconds/60)+' minutes.';message('Session policy updated.');}catch(e){message(e.message);}};
el('createAdmin').onclick=async()=>{const password=requestAdminPassword('create an administrator');if(!password)return;try{await api('accounts',{operation:'create',username:el('createAdminUsername').value,new_password:el('createAdminPassword').value,password});el('createAdminUsername').value='';el('createAdminPassword').value='';await accounts();message('Administrator added.');}catch(e){message(e.message);}};
function formatBytes(value){if(!Number.isFinite(value))return 'Unavailable';const units=['B','KiB','MiB','GiB','TiB'];let size=Math.abs(value),index=0;while(size>=1024&&index<units.length-1){size/=1024;index++;}return (value<0?'-':'')+size.toFixed(index<2?0:1)+' '+units[index];}
function statusBadge(healthy){const badge=document.createElement('span');badge.className='health-badge '+(healthy?'is-healthy':'is-attention');badge.textContent=healthy?'Healthy':'Attention';return badge;}
function healthCard(title,rows,healthy,className=''){const card=document.createElement('article');card.className='health-card'+(className?' '+className:'');const heading=document.createElement('div');heading.className='health-card-heading';const h=document.createElement('h2');h.textContent=title;heading.append(h);if(healthy!==null)heading.append(statusBadge(healthy));card.append(heading);const list=document.createElement('dl');for(const [label,value] of rows){const row=document.createElement('div');const term=document.createElement('dt');term.textContent=label;const detail=document.createElement('dd');detail.textContent=value||'Unavailable';row.append(term,detail);list.append(row);}card.append(list);return card;}
function updateGlobalHealth(status){const rows=status.services||[];const ready=rows.filter(row=>row.ready).length;const storage=status.storage||{};const storageOk=!storage.total||storage.used/storage.total<.85;const healthy=rows.length===6&&ready===6&&status.dnsHealthy&&status.ntpHealthy&&status.firewallActive&&storageOk&&!(status.alerts||[]).length;const label=healthy?ready+' of '+rows.length+' services ready':'Attention required';const badge=el('globalHealth');badge.className='global-health '+(healthy?'is-healthy':'is-attention');badge.textContent=label+' · Checked '+new Date().toLocaleTimeString();badge.title='Open Health Status';}
async function operationsStatus(){
 const r=await api('operations/status');const panel=el('operationsStatus');panel.replaceChildren();
 updateGlobalHealth(r);
 const services=(r.services||[]).map(row=>(serviceNames[row.service]||row.service)+': '+(row.state==='disabled'?'disabled':row.ready?'ready':row.state)).join(', ');
 const storage=r.storage||{};const usedPercent=storage.total?((storage.used/storage.total)*100).toFixed(1):null;
 const currentNtp=[r.currentNtp&&r.currentNtp.address,r.currentNtp&&r.currentNtp.name].filter(Boolean);const currentNtpText=currentNtp.length>1?currentNtp[0]+' ('+currentNtp[1]+')':(currentNtp[0]||'Unavailable');
 const certificate=r.certificate||{};const firewallRules=(r.firewallSummary||[]).filter(line=>line&&line.trim()&&!line.startsWith('Status:')).join(' · ');
 panel.append(
  healthCard('Identity',[['Hostname',r.identity&&r.identity.hostname],['FQDN',r.identity&&r.identity.fqdn]],null),
  healthCard('Management network',[['Interface',r.network&&r.network.interface],['Active address',(r.network&&r.network.addresses||[]).join(', ')],['Default gateway',r.network&&r.network.gateway],['Address source',r.network&&r.network.source]],null),
  healthCard('DNS',[['Configured servers',(r.configuredDns||[]).join(', ')],['Active resolvers',(r.activeResolvers||[]).join(', ')]],Boolean(r.dnsHealthy)),
  healthCard('Time synchronization',[['Configured NTP',(r.configuredNtp||[]).join(', ')],['Current server',currentNtpText],['Service',r.timesyncService],['Timezone',r.timezone]],Boolean(r.ntpHealthy)),
  healthCard('Services and storage',[['Services',services],['Data storage',usedPercent===null?'Unavailable':usedPercent+'% used ('+formatBytes(storage.free)+' free of '+formatBytes(storage.total)+')']],Boolean(r.servicesHealthy&&storage.healthy)),
  healthCard('HTTPS and firewall',[['Certificate expires',certificate.expires],['Certificate days remaining',certificate.daysRemaining===null||certificate.daysRemaining===undefined?'Unavailable':String(certificate.daysRemaining)],['Firewall',(r.firewallActive?'Active':'Inactive')+(firewallRules?'; '+firewallRules:'')]],Boolean(r.firewallActive&&certificate.enrolled&&certificate.daysRemaining>=30)),
  healthCard('Active alerts',[['Status',(r.alerts||[]).length?(r.alerts||[]).join(' '):'No active appliance alerts.']],!(r.alerts||[]).length,'health-alerts-card')
 );
}
el('operationsRefresh').onclick=()=>Promise.all([operationsStatus(),storageStatus()]).then(()=>message('Appliance status refreshed.')).catch(e=>message(e.message));
setInterval(()=>{if(!document.body.classList.contains('signed-out'))operationsStatus().catch(()=>{el('globalHealth').textContent='Health check unavailable';el('globalHealth').className='global-health is-attention';});},60000);
async function storageStatus(){const r=await api('storage');el('storageSummary').textContent=r.usedPercent+'% used · '+formatBytes(r.free)+' free of '+formatBytes(r.total)+' · '+r.status.toUpperCase()+' · Warning at '+r.warningAtPercent+'%, critical at '+r.criticalAtPercent+'% · Checked '+new Date(r.checkedAt*1000).toLocaleString();const list=el('storageCategories');list.replaceChildren();for(const row of r.categories){const item=document.createElement('div');item.className='storage-category';const title=document.createElement('strong');title.textContent=row.name;const detail=document.createElement('span');detail.textContent=formatBytes(row.bytes)+(row.growth24h===null?' · 24-hour growth pending':' · 24-hour growth '+(row.growth24h>=0?'+':'')+formatBytes(row.growth24h))+(row.note?' · '+row.note:'');item.append(title,detail);list.append(item);}}
async function runDiagnostics(){el('diagnosticsSummary').textContent='Running fixed checks...';const r=await api('diagnostics');el('diagnosticsSummary').textContent=r.attention+' need attention · Checked '+new Date(r.checkedAt*1000).toLocaleString();const list=el('diagnosticsChecks');list.replaceChildren();for(const check of r.checks){const row=document.createElement('div');row.className='diagnostic-row';const badge=document.createElement('strong');badge.className='service-status '+(check.state==='pass'?'is-ready':'is-attention');badge.textContent=check.state==='pass'?'Pass':'Attention';const text=document.createElement('span');text.textContent=check.label+' · '+check.detail;row.append(badge,text);list.append(row);}}
el('runDiagnostics').onclick=()=>runDiagnostics().catch(e=>{el('diagnosticsSummary').textContent='Diagnostics unavailable.';message(e.message);});
async function powerAction(operation){const verb=operation==='shutdown'?'shut down':'restart';if(!confirm((verb==='restart'?'Restart':'Shut down')+' the appliance now? Management and hosted services will be unavailable.'))return;const password=requestAdminPassword(verb+' the appliance');if(!password)return;try{await api('operations/'+operation,{confirmed:true,password});message('Appliance '+(operation==='shutdown'?'shutdown':'restart')+' queued.');}catch(e){message(e.message);}}
el('applianceReboot').onclick=()=>powerAction('reboot');
el('applianceShutdown').onclick=()=>powerAction('shutdown');
const serviceNames={management:'Management API',proxy:'Shared reverse proxy','forward-proxy':'Outbound forward proxy',postgres:'PostgreSQL',keycloak:'Keycloak',kmip:'KMIP'};
const serviceDescriptions={management:'Appliance administration and configuration',proxy:'Public HTTPS entry point and private routing','forward-proxy':'Explicit HTTP and HTTPS egress for approved client networks',postgres:'Persistent identity database',keycloak:'OIDC identity and access service',kmip:'Key management interoperability service'};
function updateServicePageIdentity(config){const fqdn=config.hostname+'.'+config.domain;const sso=config.sso_fqdn||('sso.'+config.domain);const kmip=config.kmip_fqdn||('kmip.'+config.domain);el('kmipEndpoint').textContent=kmip+':5696';el('keycloakAdminValue').textContent='https://'+sso+'/identity/admin/';el('oidcIssuerValue').textContent='https://'+sso+'/identity/realms/lab';el('oidcCallbackValue').textContent='https://'+fqdn+'/oidc-test/callback';el('oidcRpValue').textContent=sso;el('proxyEndpointValue').textContent='https://'+fqdn+'/';el('proxyIdentityValue').textContent=sso;}
function updateServicePageStatus(id,rows){const badge=el(id);const ready=rows.length>0&&rows.every(row=>row.ready);badge.className='labis-page-status '+(ready?'is-running':'is-attention');badge.textContent=ready?'running':'attention required';}
function serviceCard(row){
 const card=document.createElement('article');card.className='service';
 const header=document.createElement('div');header.className='service-heading';
 const identity=document.createElement('div');const title=document.createElement('h3');title.textContent=serviceNames[row.service]||row.service;const description=document.createElement('p');description.className='service-description';description.textContent=serviceDescriptions[row.service]||'Appliance service';identity.append(title,description);
 const badge=document.createElement('span');badge.className='service-status '+(row.ready?'is-ready':'is-attention');badge.textContent=row.ready?'Ready':'Attention required';header.append(identity,badge);card.append(header);
 const details=document.createElement('div');details.className='service-details';const state=document.createElement('span');state.textContent='State';const value=document.createElement('strong');value.textContent=row.state;details.append(state,value);card.append(details);
 const actions=document.createElement('div');actions.className='service-actions';let operations=['management','proxy','forward-proxy'].includes(row.service)?['restart','test']:(row.state==='running'?['stop','restart','test']:['start','test']);
 for(const operation of operations){const b=document.createElement('button');b.type='button';b.textContent=operation==='test'?'Run test':operation[0].toUpperCase()+operation.slice(1);b.className=operation==='stop'?'service-danger':'secondary';b.dataset.service=row.service;b.dataset.operation=operation;b.onclick=async()=>{const password=requestAdminPassword(operation+' '+(serviceNames[row.service]||row.service));if(!password)return;try{await api('services',{service:row.service,operation,password});message((serviceNames[row.service]||row.service)+' '+operation+' queued. Status refreshes automatically.');setTimeout(()=>services().catch(()=>message('Management is reconnecting. Refresh status shortly.')),5000);}catch(e){message(e.message);}};actions.append(b);}card.append(actions);return card;
}
function renderServiceJobs(job){for(const panel of document.querySelectorAll('[data-service-job-services]')){panel.replaceChildren();const allowed=panel.dataset.serviceJobServices.split(',');const relevant=job&&allowed.includes(job.service);const heading=document.createElement('div');heading.className='service-job-heading';const title=document.createElement('h3');title.textContent='Latest operation';heading.append(title);if(!relevant){const empty=document.createElement('p');empty.className='service-job-empty';empty.textContent='No operation for this service has been requested in this session.';panel.append(heading,empty);continue;}const badge=document.createElement('span');badge.className='service-status '+(job.state==='success'?'is-ready':'is-attention');badge.textContent=job.state||'Unknown';heading.append(badge);const summary=document.createElement('p');summary.className='service-job-summary';summary.textContent=(serviceNames[job.service]||job.service||'Service')+' · '+(job.operation||'operation');const result=document.createElement('p');result.className='service-job-result';result.textContent=job.result||'The operation is still in progress.';panel.append(heading,summary,result);}}
function renderTestHistory(history){for(const panel of document.querySelectorAll('[data-service-job-services]')){const allowed=panel.dataset.serviceJobServices.split(',');const rows=(history||[]).filter(row=>allowed.includes(row.service)).slice(-4).reverse();const heading=document.createElement('h4');heading.className='service-test-history-heading';heading.textContent='Recent functional tests';panel.append(heading);if(!rows.length){const empty=document.createElement('p');empty.className='service-job-empty';empty.textContent='No functional test history for these services yet.';panel.append(empty);continue;}for(const row of rows){const line=document.createElement('p');line.className='service-test-history-row';line.textContent=(serviceNames[row.service]||row.service)+' · '+row.result+' · '+new Date(row.testedAt*1000).toLocaleString()+' · '+row.version+' · '+row.reason;panel.append(line);}}}
async function services(){const [r,certificate]=await Promise.all([api('services'),api('certificates')]);renderSetupCards(r,certificate);['managementservices','keycloakservices','kmipservices','proxyservices','forwardproxyservices'].forEach(id=>el(id).replaceChildren());for(const row of r.services){const target={management:'managementservices',keycloak:'keycloakservices',postgres:'keycloakservices',kmip:'kmipservices',proxy:'proxyservices','forward-proxy':'forwardproxyservices'}[row.service];if(target)el(target).append(serviceCard(row));}const rowsFor=(...names)=>r.services.filter(row=>names.includes(row.service));updateServicePageStatus('keycloakPageStatus',rowsFor('keycloak','postgres'));updateServicePageStatus('kmipPageStatus',rowsFor('kmip'));updateServicePageStatus('proxyPageStatus',rowsFor('proxy','forward-proxy'));renderServiceJobs(r.job);renderTestHistory(r.testHistory);if(r.endpoints.identityAdmin){el('identitypagelink').href=r.endpoints.identityAdmin;el('identitypagelink').hidden=false;}if(r.job&&['queued','running'].includes(r.job.state))setTimeout(()=>services().catch(()=>{}),5000);}

const pages={
 'first-deployment-setup':['first-deployment-setup'],
 'first-deployment-complete':['first-deployment-complete'],
 'overview-panel':['overview-panel'],
 'kmip-panel':['kmip-panel'],
 'keycloak-panel':['keycloak-panel'],
 'proxy-panel':['proxy-panel'],
 'review-complete':['review-complete'],
 'configform':['configform','management-service-panel','review-complete'],
 'certificate-panel':['certificate-panel'],
 'account-panel':['account-panel'],
 'change-password-panel':['change-password-panel'],
 'activity-history-panel':['activity-history-panel'],
 'updates-panel':['updates-panel'],
 'help-panel':['help-panel']
};
const serviceWorkspacePages=['kmip-panel','keycloak-panel','proxy-panel'];
const pageTitles={'first-deployment-setup':'Prepare Appliance','first-deployment-complete':'Complete Setup','overview-panel':'Appliance Status','kmip-panel':'KMIP','keycloak-panel':'Keycloak / OIDC','proxy-panel':'Proxy Services','review-complete':'Complete Setup','configform':'Appliance management','certificate-panel':'HTTPS certificate','account-panel':'Admin user management','change-password-panel':'Change password','activity-history-panel':'Activity history','updates-panel':'Appliance updates','help-panel':'Help and runbooks'};
function setActiveNavigation(page){
 const primaryPage=page==='first-deployment-complete'?'first-deployment-setup':page;
 document.querySelectorAll('.top-navigation a').forEach(a=>{a.removeAttribute('aria-current');if(a.hash==='#'+primaryPage)a.setAttribute('aria-current','page');});
 document.querySelectorAll('.workflow-nav a').forEach(a=>{a.removeAttribute('aria-current');if(a.hash==='#'+page)a.setAttribute('aria-current','page');});
 document.querySelectorAll('.admin-menu-panel a').forEach(a=>{a.removeAttribute('aria-current');if(a.hash==='#'+page)a.setAttribute('aria-current','page');});
}
function showPage(){
 if(el('setupDialog').open)return;
 const key=location.hash.slice(1);const requested=Object.hasOwn(pages,key)?key:'overview-panel';const page=setupCompleted&&['first-deployment-setup','first-deployment-complete'].includes(requested)?'overview-panel':requested;
 for(const id of new Set(Object.values(pages).flat())){const node=el(id);node.hidden=!pages[page].includes(id)||(id==='review-complete'&&!sessionStorage.getItem('networkToken'));}

 document.querySelector('#content > .notice').hidden=true;
 document.body.classList.toggle('service-page-active',serviceWorkspacePages.includes(page));
 document.querySelector('.page-header h1').textContent=pageTitles[page];
 setActiveNavigation(page);
 el('adminMenu').open=false;
 for(const id of pages[page]){const activity=el(id).querySelector('.service-activity');if(activity)loadServiceActivity(activity).catch(e=>message(e.message));}
 if(page==='updates-panel')updateStatus().catch(e=>message(e.message));if(page==='activity-history-panel')auditHistory();if(page==='certificate-panel')trustInventory().catch(e=>message(e.message));if(page==='first-deployment-complete')preflight().catch(e=>message(e.message));if(page==='overview-panel'){alertDeliveryStatus().catch(e=>message(e.message));storageStatus().catch(e=>message(e.message));}if(page==='help-panel')api('updates').then(r=>el('helpVersion').textContent='Installed release: '+r.version).catch(e=>message(e.message));
}
function updateSetupNavigation(){document.body.classList.toggle('setup-completed',setupCompleted);document.querySelectorAll('a[href="#first-deployment-setup"],a[href="#first-deployment-complete"]').forEach(link=>{link.hidden=setupCompleted;});}
window.addEventListener('hashchange',showPage);
document.querySelectorAll('.admin-menu-panel a').forEach(a=>a.addEventListener('click',()=>{el('adminMenu').open=false;}));
document.addEventListener('click',e=>{if(!el('adminMenu').contains(e.target))el('adminMenu').open=false;});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&el('adminMenu').open){el('adminMenu').open=false;el('adminMenu').querySelector('summary').focus();}});

const setupItems=[
 {code:'TLS',activePage:'first-deployment-setup',title:'Management HTTPS certificate',copy:'Trusted certificate for secure appliance administration',tasks:['Generate or retrieve the certificate signing request.','Submit it to your certificate authority.','Import the signed certificate and CA chain.'],targets:['certificate-panel']},
 {code:'OIDC',activePage:'keycloak-panel',title:'Keycloak / OIDC',service:'keycloak',copy:'Identity provider for appliance and application authentication',tasks:['Verify PostgreSQL and Keycloak readiness.','Run the functional test using your administrator password.','Enroll the final issuer name, trusted certificate and actual clients before integration.'],targets:['keycloak-panel'],note:'The lab administrator is already initialized. This view does not recreate credentials. Final realm/client enrollment remains pending.'},
 {code:'KMIP',activePage:'kmip-panel',title:'KMIP key management',service:'kmip',copy:'Key management service with mutual TLS client trust',tasks:['Check the container and run the mutual-TLS functional test.','Retain existing persistent keys.','Sign the client CSR, trust the issuing chain and enroll the client network before exposing TCP 5696.'],targets:['kmip-panel'],note:'Signing a client CSR leaves the issuing CA key on this appliance. Open the listener only after client trust is verified.'},
 {code:'PROXY',activePage:'proxy-panel',title:'Shared reverse proxy',service:'proxy',copy:'Trusted HTTPS entry point for approved appliance routes',tasks:['Test the proxy configuration and service health.','Enroll the management HTTPS certificate.','Configure final upstream routes after their names and TLS trust are known.'],targets:['proxy-panel'],note:'Current routes serve management and the lab identity service. External upstream route configuration remains pending.'},
 {code:'EGRESS',activePage:'proxy-panel',title:'Outbound forward proxy',service:'forward-proxy',copy:'Optional controlled HTTP and HTTPS internet egress',tasks:['Keep the listener disabled until client networks are approved.','Enter explicit client CIDRs and any destination suffix allowlist.','Apply the policy, run the functional test and confirm unauthorized sources remain denied.'],targets:['proxy-panel'],note:'The listener is disabled by default. Enabling it publishes TCP 3128 only for the approved source networks.'}
];
function renderSetupCards(result,certificate){
 const ready=result.services.filter(s=>s.ready).length;
 el('firstSetupSummary').textContent=ready+' of '+result.services.length+' running';
 el('firstSetupCards').replaceChildren();
 for(const item of setupItems){
 const state=result.services.find(s=>s.service===item.service);
  const card=document.createElement('article');card.className='first-setup-card';
  const status=document.createElement('div');status.className='first-setup-status';
  const code=document.createElement('span');code.className='first-setup-code';code.textContent=item.code;
  const badge=document.createElement('span');const running=item.code==='TLS'?Boolean(certificate&&certificate.enrolled):Boolean(state&&state.ready);badge.className='setup-status-badge '+(running?'is-running':'is-required');badge.textContent=running?'Running':'Setup Required';status.append(code,badge);
  const title=document.createElement('h3');title.textContent=item.title;
  const copy=document.createElement('p');copy.textContent=item.copy;
  const actions=document.createElement('div');actions.className='first-setup-actions';const button=document.createElement('button');button.type='button';button.textContent='Configure';button.onclick=()=>openSetup(item);actions.append(button);
  card.append(status,title,copy,actions);el('firstSetupCards').append(card);
 }
}
let setupMoved=[];
function openSetup(item){
 setActiveNavigation(item.activePage||'first-deployment-setup');
 const dialog=el('setupDialog');el('setupDialogTitle').textContent=item.title;el('setupDialogDescription').textContent=item.note||item.copy;
 const tasks=document.createElement('ol');tasks.className='setup-dialog-tasks';for(const task of item.tasks){const row=document.createElement('li');row.textContent=task;tasks.append(row);}el('setupDialogBody').append(tasks);
 const nodes=item.targets.map(el);
 for(const node of nodes){const marker=document.createComment('wizard-return');node.before(marker);setupMoved.push({node,marker});el('setupDialogBody').append(node);node.hidden=node.id==='review'&&!node.textContent;}
 const msg=el('message');const marker=document.createComment('message-return');msg.before(marker);setupMoved.push({node:msg,marker});el('setupDialogBody').append(msg);
 dialog.showModal();el('closeSetupDialog').focus();
}
el('closeSetupDialog').onclick=()=>el('setupDialog').close();
el('setupDialog').addEventListener('close',()=>{for(const {node,marker} of setupMoved){marker.replaceWith(node);}setupMoved=[];el('setupDialogBody').querySelectorAll('.setup-dialog-tasks').forEach(node=>node.remove());showPage();});
el('wizardRefresh').onclick=()=>services().catch(e=>message(e.message));


async function loadServiceActivity(section){
 const select=section.querySelector('.service-activity-select');const output=section.querySelector('.service-activity-lines');const service=select.value;
 output.textContent='Loading '+(serviceNames[service]||service)+' activity...';
 const r=await api('connections?service='+encodeURIComponent(service));
 output.textContent=r.lines.join('\n')||'No recent connection or service activity is recorded for '+(serviceNames[service]||service)+'.';
}
document.querySelectorAll('.service-activity').forEach(section=>{
 const select=section.querySelector('.service-activity-select');const services=section.dataset.activityServices.split(',');
 for(const service of services){const option=document.createElement('option');option.value=service;option.textContent=serviceNames[service]||service;select.append(option);}
 select.disabled=services.length===1;select.onchange=()=>loadServiceActivity(section).catch(e=>message(e.message));
 section.querySelector('.service-activity-refresh').onclick=()=>loadServiceActivity(section).catch(e=>message(e.message));
});

async function forwardProxyStatus(){try{const r=await api('forward-proxy');el('forwardProxyEnabled').checked=r.enabled;el('forwardProxyCidrs').value=(r.client_cidrs||[]).join(', ');el('forwardProxyDomains').value=(r.allowed_domains||[]).join(', ');el('forwardProxyState').textContent=r.enabled?'Enabled on TCP 3128 for the listed client networks.':'Disabled. TCP 3128 is not published.';}catch(e){message(e.message);}}
el('forwardProxyForm').onsubmit=async e=>{e.preventDefault();const password=requestAdminPassword('apply the forward proxy policy');if(!password)return;try{const list=id=>el(id).value.split(',').map(x=>x.trim()).filter(Boolean);const r=await api('forward-proxy',{enabled:el('forwardProxyEnabled').checked,client_cidrs:list('forwardProxyCidrs'),allowed_domains:list('forwardProxyDomains'),password});el('forwardProxyState').textContent=r.enabled?'Enabled on TCP 3128 for the listed client networks.':'Disabled. TCP 3128 is not published.';message(r.notice);await services();}catch(e){message(e.message);}};
window.addEventListener('hashchange',()=>{if(location.hash==='#proxy-panel')forwardProxyStatus();});

let pendingKmipAccessToken=null;
async function loadKmipAccess(){const r=await api('config');const cidrs=r.config.kmip_client_cidrs||[];el('kmipAccessCidrs').value=cidrs.join(', ');el('kmipAccessStatus').textContent=cidrs.length?'TCP 5696 is restricted to '+cidrs.join(', ')+'.':'TCP 5696 is closed to external clients.';}
el('kmipAccessForm').onsubmit=async e=>{e.preventDefault();const password=requestAdminPassword('apply the KMIP client-network policy');if(!password)return;try{const current=await api('config');const cidrs=el('kmipAccessCidrs').value.split(',').map(x=>x.trim()).filter(Boolean);const config={...current.config,kmip_client_cidrs:cidrs};await api('setup/preview',{config});const saved=await api('setup/save',{config,revision:current.revision});const pending=await api('setup/apply',{revision:saved.revision,password});pendingKmipAccessToken=pending.token;el('kmipAccessConfirm').hidden=false;el('kmipAccessStatus').textContent='Applying the policy. After the management connection returns, confirm it within two minutes or the previous policy is restored.';message('KMIP access change pending confirmation.');}catch(e){message(e.message);}};
el('kmipAccessConfirm').onclick=async()=>{const password=requestAdminPassword('confirm management access');if(!password||!pendingKmipAccessToken)return;try{const r=await api('setup/confirm',{token:pendingKmipAccessToken,password});if(!r.confirmed)throw Error('The policy was not confirmed.');pendingKmipAccessToken=null;el('kmipAccessConfirm').hidden=true;await loadKmipAccess();message('KMIP access policy confirmed.');}catch(e){message(e.message);}};
window.addEventListener('hashchange',()=>{if(location.hash==='#kmip-panel')loadKmipAccess().catch(e=>message(e.message));});

el('kmipTrustRefresh').onclick=async()=>{try{const r=await api('kmip/trust');el('kmipRootCa').value=r.rootCa;el('kmipIssuingCa').value=r.issuingCa;el('kmipEnrollmentStatus').textContent='Appliance KMIP root and issuing certificates are ready. The private CA key remains on the appliance.';}catch(e){message(e.message);}};
el('kmipSignClient').onclick=async()=>{const password=requestAdminPassword('sign the KMIP client request');if(!password)return;try{const r=await api('kmip/sign-client',{clientName:el('kmipClientName').value.trim().toLowerCase(),csr:el('kmipClientCsr').value.trim(),password});el('kmipSignedClient').value=r.certificate;el('kmipRootCa').value=r.rootCa;el('kmipIssuingCa').value=r.issuingCa;el('kmipEnrollmentStatus').textContent='Client certificate signed for '+r.clientName+'. Install it in the client, trust the appliance KMIP CA, and then approve its source network. Expires '+r.expires+'.';message('KMIP client CSR signed; no private key left the client.');}catch(e){message(e.message);}};

let preflightReady=false;
async function preflight(){
 const r=await api('setup/preflight');preflightReady=r.readyToComplete;const list=el('preflightChecks');list.replaceChildren();
 for(const check of r.checks){const row=document.createElement('div');row.className='preflight-item state-'+check.state;const badge=document.createElement('strong');badge.textContent=check.state.toUpperCase();const label=document.createElement('span');label.textContent=check.label+' — '+check.detail;const link=document.createElement('a');link.href='#'+check.page;link.textContent='Open page';row.append(badge,label,link);list.append(row);}
 el('preflightSummary').textContent=r.blocked+' blocked · '+r.warnings+' warnings · Checked '+new Date(r.checkedAt*1000).toLocaleString();el('complete').disabled=!preflightReady||!el('setupAcknowledged').checked;
}
el('preflightRefresh').onclick=()=>preflight().catch(e=>message(e.message));
async function trustInventory(){
 const r=await api('trust-inventory');const list=el('trustInventory');list.replaceChildren();
 for(const cert of r.certificates){const card=document.createElement('article');card.className='trust-item';const title=document.createElement('h4');title.textContent=cert.role;card.append(title);const line=document.createElement('p');line.textContent=cert.available?('Subject: '+cert.subject+' · Issuer: '+cert.issuer+' · DNS: '+(cert.dnsNames||[]).join(', ')+' · SHA-256: '+cert.sha256+' · Expires: '+cert.expires+' · Trust: '+cert.trustStatus):'Unavailable';card.append(line);list.append(card);}
 el('trustRevocationNote').textContent=r.revocationNote+(r.clientInventoryTruncated?' Only the first 20 enrolled client certificates are shown.':'');
}
el('trustRefresh').onclick=()=>trustInventory().catch(e=>message(e.message));
async function alertDeliveryStatus(){const r=await api('alert-delivery');el('alertEnabled').checked=r.config.enabled;el('alertKind').value=['syslog','https','mattermost'].includes(r.config.kind)?r.config.kind:'syslog';el('alertDestination').value=r.config.destination||'';el('alertDestination').placeholder=r.config.destinationDisplay||'logs.example.local:514 or https://chat.example.local/hooks/...';el('alertTest').disabled=!r.config.enabled||!r.config.configured;el('alertDeliveryResult').textContent='Last delivery: '+(r.delivery.lastResult||'not sent')+(r.delivery.lastAttemptAt?' at '+new Date(r.delivery.lastAttemptAt*1000).toLocaleString():'')+'.';}
el('alertSave').onclick=async()=>{const password=requestAdminPassword('save alert delivery settings');if(!password)return;try{await api('alert-delivery',{config:{enabled:el('alertEnabled').checked,kind:el('alertKind').value,destination:el('alertDestination').value.trim()},password});await alertDeliveryStatus();message('Alert delivery settings saved.');}catch(e){message(e.message);}};
el('alertTest').onclick=async()=>{const password=requestAdminPassword('send a test alert');if(!password)return;try{await api('alert-delivery',{operation:'test',password});await alertDeliveryStatus();message('Test alert delivered.');}catch(e){message(e.message);}};
