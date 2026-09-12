import {
  isSecretHeader,
  loadCredentialRules,
  previewCredentialMatch,
  saveCredentialRules,
  validateCredentialRuleInput,
  type CredentialKV,
  type CredentialRule,
  type CredentialRuleInput,
} from "./credentials";

export interface AdminEnv {
  ADMIN_PATH?: string;
  CREDENTIALS?: CredentialKV;
}

const ADMIN_COOKIE = "mcp_admin";
const ADMIN_PREFIX = "/admin";
const MAX_ADMIN_BODY = 256 * 1024;

function normalizeAdminSecret(secret?: string): string | null {
  const value = (secret ?? "").trim().replace(/^\/+|\/+$/g, "");
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(value)) return null;
  return value;
}

function parseCookies(header: string | null): Record<string, string> {
  const result: Record<string, string> = {};
  if (!header) return result;
  for (const chunk of header.split(";")) {
    const index = chunk.indexOf("=");
    if (index < 0) continue;
    const name = chunk.slice(0, index).trim();
    const value = chunk.slice(index + 1).trim();
    if (name) result[name] = value;
  }
  return result;
}

function adminAuthorized(request: Request, secret: string): boolean {
  return parseCookies(request.headers.get("cookie"))[ADMIN_COOKIE] === secret;
}

function noStore(headers: HeadersInit = {}): Headers {
  const result = new Headers(headers);
  result.set("cache-control", "no-store, private");
  result.set("pragma", "no-cache");
  result.set("x-content-type-options", "nosniff");
  result.set("referrer-policy", "no-referrer");
  return result;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: noStore({ "content-type": "application/json; charset=utf-8" }),
  });
}

function notFound(): Response {
  return new Response("Not found", { status: 404, headers: noStore() });
}

async function readJson(request: Request): Promise<unknown> {
  const length = Number(request.headers.get("content-length") ?? "0");
  if (Number.isFinite(length) && length > MAX_ADMIN_BODY) {
    throw new Error("Request body is too large");
  }
  const text = await request.text();
  if (new TextEncoder().encode(text).byteLength > MAX_ADMIN_BODY) {
    throw new Error("Request body is too large");
  }
  return text ? JSON.parse(text) : {};
}

type AdminHeaderInput = {
  name?: unknown;
  value?: unknown;
  secret?: unknown;
  keep_existing?: unknown;
};

type AdminRuleInput = {
  name?: unknown;
  host_pattern?: unknown;
  path_prefix?: unknown;
  headers?: unknown;
  mode?: unknown;
  priority?: unknown;
  https_only?: unknown;
  enabled?: unknown;
};

function adminRuleView(rule: CredentialRule) {
  const headers = Object.entries(rule.headers).map(([name, value]) => {
    const secret = isSecretHeader(rule, name);
    return secret
      ? { name, secret: true, has_value: true }
      : { name, secret: false, has_value: true, value };
  });

  return {
    id: rule.id,
    name: rule.name,
    host_pattern: rule.host_pattern,
    path_prefix: rule.path_prefix,
    headers,
    header_names: headers.map((header) => header.name),
    secret_header_count: headers.filter((header) => header.secret).length,
    mode: rule.mode,
    priority: rule.priority,
    https_only: rule.https_only,
    enabled: rule.enabled,
    created_at: rule.created_at,
    updated_at: rule.updated_at,
  };
}

function adminRulesView(rules: CredentialRule[]) {
  return rules.map(adminRuleView);
}

function normalizeAdminRuleInput(input: AdminRuleInput, existing?: CredentialRule): CredentialRuleInput {
  if (!Array.isArray(input.headers)) throw new Error("Headers must be a list");

  const headers: Record<string, string> = {};
  const secretHeaders: string[] = [];
  const existingByName = new Map(
    Object.entries(existing?.headers ?? {}).map(([name, value]) => [
      name.toLowerCase(),
      { name, value, secret: existing ? isSecretHeader(existing, name) : false },
    ]),
  );

  for (const raw of input.headers as AdminHeaderInput[]) {
    if (!raw || typeof raw !== "object") throw new Error("Invalid header entry");
    const name = String(raw.name ?? "").trim();
    if (!name) throw new Error("Header names cannot be empty");
    const secret = raw.secret === true;
    const keepExisting = raw.keep_existing === true;
    const old = existingByName.get(name.toLowerCase());

    let value: string;
    if (keepExisting) {
      if (!secret || !old || !old.secret) {
        throw new Error(`Cannot preserve ${name}; enter a replacement value`);
      }
      value = old.value;
    } else {
      if (typeof raw.value !== "string") {
        throw new Error(`Header ${name} needs a value`);
      }
      value = raw.value;
      if (secret && !value && !old) {
        throw new Error(`Secret header ${name} needs a value`);
      }
    }

    headers[name] = value;
    if (secret) secretHeaders.push(name.toLowerCase());
  }

  return {
    name: input.name,
    host_pattern: input.host_pattern,
    path_prefix: input.path_prefix,
    headers,
    secret_headers: secretHeaders,
    mode: input.mode,
    priority: input.priority,
    https_only: input.https_only,
    enabled: input.enabled,
  };
}

function adminHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Proxy Credentials</title>
<style nonce="${nonce}">
:root{color-scheme:dark;--bg:#0b0d10;--panel:#13171c;--panel2:#191f26;--border:#2a323c;--text:#e9eef5;--muted:#94a0ae;--accent:#7dd3fc;--danger:#f87171;--ok:#86efac;--warn:#fbbf24;--shadow:0 18px 50px rgba(0,0,0,.28)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1450px;margin:0 auto;padding:26px 24px 56px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px;margin-bottom:24px}.brand h1{font-size:24px;margin:0 0 3px}.brand p{margin:0;color:var(--muted)}button,.btn{border:1px solid var(--border);background:var(--panel2);color:var(--text);padding:9px 12px;border-radius:9px;cursor:pointer;font-weight:650}button:hover{border-color:#45515f}.primary{background:#0e7490;border-color:#0891b2}.danger{color:#fecaca;border-color:#7f1d1d;background:#2a1114}.ghost{background:transparent}.grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(470px,.95fr);gap:20px;align-items:start}.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow);min-width:0}.editor{position:sticky;top:18px;max-height:calc(100vh - 36px);overflow:auto}.panel-h{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}.panel-b{padding:18px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.search{flex:1;min-width:220px}.input,select,textarea{width:100%;background:#0d1116;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:10px 11px;outline:none}.input:focus,select:focus,textarea:focus{border-color:#3b82f6}.input:disabled{opacity:.8;color:#94a3b8;cursor:not-allowed}.rules{display:flex;flex-direction:column;gap:10px}.rule{border:1px solid var(--border);background:#0f1318;border-radius:11px;padding:14px}.rule-head{display:flex;justify-content:space-between;gap:12px}.rule-title{font-weight:750;font-size:15px}.badges{display:flex;gap:6px;flex-wrap:wrap;margin-top:8px}.badge{font-size:12px;color:#cbd5e1;border:1px solid #334155;background:#111827;padding:2px 7px;border-radius:999px}.badge.on{color:#bbf7d0;border-color:#166534}.badge.off{color:#fecaca;border-color:#7f1d1d}.badge.secret{color:#fde68a;border-color:#854d0e}.meta{margin-top:9px;color:var(--muted);font-size:12px;word-break:break-word}.rule-actions{display:flex;gap:7px;align-items:flex-start}.empty{padding:34px;text-align:center;color:var(--muted)}.field{margin-bottom:14px}.field>label{display:block;color:#cbd5e1;font-weight:650;margin-bottom:6px}.row{display:grid;grid-template-columns:1fr 1fr;gap:12px}.checkrow{display:flex;gap:18px;align-items:center;margin:12px 0 16px}.checkrow label,.secret-toggle{display:flex;gap:7px;align-items:center;color:#cbd5e1;white-space:nowrap}.headers{display:flex;flex-direction:column;gap:10px}.header-card{border:1px solid var(--border);background:#0f1318;border-radius:10px;padding:10px}.header-main{display:grid;grid-template-columns:minmax(135px,.8fr) minmax(190px,1.2fr);gap:8px}.header-controls{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;min-height:34px}.header-left,.header-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.header-state{font-size:12px;color:var(--muted)}.header-state.secret{color:#fde68a}.header-state.warn{color:var(--warn)}.mini{padding:8px 9px}.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:18px}.hint{font-size:12px;color:var(--muted);margin-top:5px}.status{min-height:20px;color:var(--muted);font-size:12px;margin-top:10px}.status.ok{color:var(--ok)}.status.err{color:#fca5a5}.section-divider{border:0;border-top:1px solid var(--border);margin:22px 0}.testbox{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px}.test-result{margin-top:9px;padding:10px;border:1px dashed var(--border);border-radius:8px;color:var(--muted);min-height:40px;word-break:break-word}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#bae6fd}@media(max-width:1050px){.grid{grid-template-columns:1fr}.editor{position:static;max-height:none}}@media(max-width:680px){.wrap{padding:18px 12px 40px}.top{align-items:flex-start}.row,.header-main{grid-template-columns:1fr}.panel-h{align-items:flex-start;flex-direction:column}.search{width:100%;min-width:0}.rule-head{flex-direction:column}.rule-actions{align-self:flex-end}.header-controls{align-items:flex-start;flex-direction:column}.testbox{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand"><h1>Credential rules</h1><p>Inject headers by destination domain/path. Secret values never round-trip to the browser after save.</p></div>
    <div class="toolbar"><button id="newRule" class="primary">+ New rule</button><button id="logout" class="ghost">Logout</button></div>
  </div>
  <div class="grid">
    <section class="panel">
      <div class="panel-h"><strong>Rules</strong><input id="filter" class="input search" placeholder="Filter domain, name, header…"></div>
      <div class="panel-b"><div id="rules" class="rules"></div></div>
    </section>
    <aside class="panel editor">
      <div class="panel-h"><strong id="formTitle">New rule</strong><button id="reset" class="ghost mini">Reset</button></div>
      <div class="panel-b">
        <input id="ruleId" type="hidden">
        <div class="field"><label>Name</label><input id="name" class="input" placeholder="NocoBase dev"></div>
        <div class="field"><label>Domain</label><input id="host" class="input" placeholder="portal.example.com or *.example.com"><div class="hint">Exact host or one leading wildcard.</div></div>
        <div class="field"><label>Path prefix</label><input id="path" class="input" value="/" placeholder="/api"><div class="hint">Optional scope inside the domain. <code>/</code> matches all paths.</div></div>
        <div class="row">
          <div class="field"><label>Mode</label><select id="mode"><option value="override">Override caller header</option><option value="if_missing">Only if missing</option></select></div>
          <div class="field"><label>Priority</label><input id="priority" class="input" type="number" value="100" min="-10000" max="10000"></div>
        </div>
        <div class="checkrow"><label><input id="httpsOnly" type="checkbox" checked> HTTPS only</label><label><input id="enabled" type="checkbox" checked> Enabled</label></div>
        <div class="field"><label>Headers</label><div id="headers" class="headers"></div><button id="addHeader" class="ghost mini" type="button">+ Add header</button><div class="hint">Mark credentials as Secret. Once saved, their values are never returned by the admin API.</div></div>
        <div class="form-actions"><button id="deleteRule" class="danger" hidden>Delete</button><button id="saveRule" class="primary">Save rule</button></div>
        <div id="status" class="status"></div>
        <hr class="section-divider">
        <div class="field"><label>Test matching URL</label><div class="testbox"><input id="testUrl" class="input" placeholder="https://portal.example.com/api/foo"><button id="testMatch">Test</button></div><div id="testResult" class="test-result">No test yet.</div></div>
      </div>
    </aside>
  </div>
</div>
<script nonce="${nonce}">
(function(){
  var rules=[];
  var el=function(id){return document.getElementById(id)};
  async function api(path,opts){
    var base={headers:{'content-type':'application/json'}};
    var r=await fetch(path,Object.assign(base,opts||{}));
    var data={};try{data=await r.json()}catch(e){}
    if(!r.ok)throw new Error(data.error||('HTTP '+r.status));
    return data;
  }
  function setStatus(msg,ok){var s=el('status');s.textContent=msg||'';s.className='status '+(msg?(ok?'ok':'err'):'')}
  function setStoredState(row,on){
    row.dataset.keepExisting=on?'1':'0';
    var v=row.querySelector('.h-value');var state=row.querySelector('.header-state');var replace=row.querySelector('.replace-secret');var secret=row.querySelector('.h-secret');
    if(on&&secret.checked){v.value='';v.disabled=true;v.type='password';v.placeholder='Stored secret';state.textContent='Stored server-side';state.className='header-state secret';replace.hidden=false}
    else{v.disabled=false;replace.hidden=true;if(secret.checked){v.type='password';v.placeholder='Enter secret value';state.textContent='Will be hidden after save';state.className='header-state secret'}else{v.type='text';v.placeholder='Header value';state.textContent='';state.className='header-state'}}
  }
  function headerRow(header){
    header=header||{};
    var stored=Boolean(header.secret&&header.has_value&&header.value===undefined);
    var row=document.createElement('div');row.className='header-card';row.dataset.originalName=header.name||'';
    var main=document.createElement('div');main.className='header-main';
    var n=document.createElement('input');n.className='input h-name';n.placeholder='Authorization';n.value=header.name||'';
    var v=document.createElement('input');v.className='input h-value';v.value=header.value||'';
    main.append(n,v);
    var controls=document.createElement('div');controls.className='header-controls';
    var left=document.createElement('div');left.className='header-left';
    var secretLabel=document.createElement('label');secretLabel.className='secret-toggle';var secret=document.createElement('input');secret.type='checkbox';secret.className='h-secret';secret.checked=Boolean(header.secret);secretLabel.append(secret,document.createTextNode(' Secret'));
    var state=document.createElement('span');state.className='header-state';left.append(secretLabel,state);
    var actions=document.createElement('div');actions.className='header-actions';
    var replace=document.createElement('button');replace.type='button';replace.className='ghost mini replace-secret';replace.textContent='Replace';replace.hidden=true;
    var del=document.createElement('button');del.type='button';del.className='ghost mini';del.textContent='Remove';
    actions.append(replace,del);controls.append(left,actions);row.append(main,controls);el('headers').appendChild(row);
    setStoredState(row,stored);
    replace.onclick=function(){setStoredState(row,false);v.value='';v.focus();state.textContent='Enter replacement secret';state.className='header-state warn'};
    del.onclick=function(){row.remove()};
    secret.onchange=function(){
      if(!secret.checked&&row.dataset.keepExisting==='1'){setStoredState(row,false);v.value='';state.textContent='Enter a replacement value before saving';state.className='header-state warn';v.focus();return}
      setStoredState(row,row.dataset.keepExisting==='1');
    };
    n.oninput=function(){
      if(row.dataset.keepExisting==='1'&&n.value.trim().toLowerCase()!==String(row.dataset.originalName||'').trim().toLowerCase()){
        setStoredState(row,false);v.value='';state.textContent='Header renamed — enter replacement secret';state.className='header-state warn';
      }
    };
  }
  function resetForm(){
    el('ruleId').value='';el('name').value='';el('host').value='';el('path').value='/';el('mode').value='override';el('priority').value='100';el('httpsOnly').checked=true;el('enabled').checked=true;el('headers').innerHTML='';headerRow({name:'Authorization',secret:true,has_value:false,value:''});el('formTitle').textContent='New rule';el('deleteRule').hidden=true;setStatus('');
  }
  function editRule(id){
    var r=rules.find(function(x){return x.id===id});if(!r)return;
    el('ruleId').value=r.id;el('name').value=r.name;el('host').value=r.host_pattern;el('path').value=r.path_prefix;el('mode').value=r.mode;el('priority').value=String(r.priority);el('httpsOnly').checked=r.https_only;el('enabled').checked=r.enabled;el('headers').innerHTML='';(r.headers||[]).forEach(headerRow);el('formTitle').textContent='Edit rule';el('deleteRule').hidden=false;setStatus('');
    if(window.innerWidth<1050)window.scrollTo({top:0,behavior:'smooth'});
  }
  function headerNames(r){return (r.headers||[]).map(function(h){return h.name})}
  function render(){
    var q=el('filter').value.trim().toLowerCase();var root=el('rules');root.innerHTML='';
    var shown=rules.filter(function(r){return !q||(r.name+' '+r.host_pattern+' '+r.path_prefix+' '+headerNames(r).join(' ')).toLowerCase().includes(q)});
    if(!shown.length){var e=document.createElement('div');e.className='empty';e.textContent=rules.length?'No matching rules.':'No credential rules yet.';root.appendChild(e);return}
    shown.slice().sort(function(a,b){return b.priority-a.priority||a.name.localeCompare(b.name)}).forEach(function(r){
      var card=document.createElement('div');card.className='rule';var head=document.createElement('div');head.className='rule-head';
      var left=document.createElement('div');var title=document.createElement('div');title.className='rule-title';title.textContent=r.name;left.appendChild(title);
      var badges=document.createElement('div');badges.className='badges';
      [r.enabled?'enabled':'disabled',r.https_only?'HTTPS only':'HTTP + HTTPS',r.mode,r.host_pattern+r.path_prefix].forEach(function(t,i){var b=document.createElement('span');b.className='badge '+(i===0?(r.enabled?'on':'off'):'');b.textContent=t;badges.appendChild(b)});
      if(r.secret_header_count){var sb=document.createElement('span');sb.className='badge secret';sb.textContent=r.secret_header_count+' secret';badges.appendChild(sb)}left.appendChild(badges);
      var names=headerNames(r);var meta=document.createElement('div');meta.className='meta';meta.textContent='Headers: '+names.join(', ')+' · '+names.length+' total · priority '+r.priority;left.appendChild(meta);
      var actions=document.createElement('div');actions.className='rule-actions';var edit=document.createElement('button');edit.className='ghost mini';edit.textContent='Edit';edit.onclick=function(){editRule(r.id)};actions.appendChild(edit);head.append(left,actions);card.appendChild(head);root.appendChild(card);
    })
  }
  async function load(){try{var data=await api('/admin/api/rules');rules=data.rules||[];render()}catch(e){setStatus(e.message,false)}}
  function collect(){
    var headers=[];document.querySelectorAll('.header-card').forEach(function(row){
      var n=row.querySelector('.h-name').value.trim();var v=row.querySelector('.h-value');var secret=row.querySelector('.h-secret').checked;var keep=row.dataset.keepExisting==='1';
      if(!n&&!v.value&&!keep)return;
      var item={name:n,secret:secret};if(keep)item.keep_existing=true;else item.value=v.value;headers.push(item)
    });
    return {name:el('name').value.trim(),host_pattern:el('host').value.trim(),path_prefix:el('path').value.trim()||'/',mode:el('mode').value,priority:Number(el('priority').value||100),https_only:el('httpsOnly').checked,enabled:el('enabled').checked,headers:headers};
  }
  el('saveRule').onclick=async function(){try{setStatus('Saving…',true);var id=el('ruleId').value;var data=await api(id?('/admin/api/rules/'+encodeURIComponent(id)):'/admin/api/rules',{method:id?'PUT':'POST',body:JSON.stringify(collect())});rules=data.rules||[];render();if(id)editRule(id);else resetForm();setStatus('Saved.',true)}catch(e){setStatus(e.message,false)}};
  el('deleteRule').onclick=async function(){var id=el('ruleId').value;if(!id||!confirm('Delete this credential rule?'))return;try{var data=await api('/admin/api/rules/'+encodeURIComponent(id),{method:'DELETE'});rules=data.rules||[];render();resetForm();setStatus('Deleted.',true)}catch(e){setStatus(e.message,false)}};
  el('testMatch').onclick=async function(){try{var data=await api('/admin/api/match',{method:'POST',body:JSON.stringify({url:el('testUrl').value.trim()})});var m=data.match;el('testResult').textContent=m.matched_rule_names.length?('Rules: '+m.matched_rule_names.join(' → ')+' | Headers: '+m.injected_header_names.join(', ')):'No credential rule matches.'}catch(e){el('testResult').textContent=e.message}};
  el('addHeader').onclick=function(){headerRow({name:'',secret:false,has_value:false,value:''})};el('newRule').onclick=resetForm;el('reset').onclick=resetForm;el('filter').oninput=render;
  el('logout').onclick=async function(){await fetch('/admin/logout',{method:'POST'});location.href='/admin'};
  resetForm();load();
})();
</script>
</body>
</html>`;
}

function htmlResponse(): Response {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const headers = noStore({ "content-type": "text/html; charset=utf-8" });
  headers.set(
    "content-security-policy",
    `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`,
  );
  headers.set("x-frame-options", "DENY");
  return new Response(adminHtml(nonce), { headers });
}

async function handleApi(request: Request, env: AdminEnv, url: URL): Promise<Response> {
  const kv = env.CREDENTIALS;
  if (!kv) return json({ error: "CREDENTIALS KV binding is not configured" }, 503);

  try {
    const rules = await loadCredentialRules(kv);

    if (url.pathname === "/admin/api/rules" && request.method === "GET") {
      return json({ rules: adminRulesView(rules) });
    }

    if (url.pathname === "/admin/api/rules" && request.method === "POST") {
      const raw = (await readJson(request)) as AdminRuleInput;
      const rule = validateCredentialRuleInput(normalizeAdminRuleInput(raw));
      const next = [...rules, rule];
      await saveCredentialRules(kv, next);
      return json({ rule: adminRuleView(rule), rules: adminRulesView(next) }, 201);
    }

    const match = url.pathname.match(/^\/admin\/api\/rules\/([A-Za-z0-9_-]+)$/);
    if (match && request.method === "PUT") {
      const id = match[1];
      const existing = rules.find((rule) => rule.id === id);
      if (!existing) return json({ error: "Rule not found" }, 404);
      const raw = (await readJson(request)) as AdminRuleInput;
      const updated = validateCredentialRuleInput(normalizeAdminRuleInput(raw, existing), existing);
      const next = rules.map((rule) => (rule.id === id ? updated : rule));
      await saveCredentialRules(kv, next);
      return json({ rule: adminRuleView(updated), rules: adminRulesView(next) });
    }

    if (match && request.method === "DELETE") {
      const id = match[1];
      if (!rules.some((rule) => rule.id === id)) return json({ error: "Rule not found" }, 404);
      const next = rules.filter((rule) => rule.id !== id);
      await saveCredentialRules(kv, next);
      return json({ rules: adminRulesView(next) });
    }

    if (url.pathname === "/admin/api/match" && request.method === "POST") {
      const input = (await readJson(request)) as { url?: unknown };
      const rawUrl = String(input.url ?? "");
      let target: URL;
      try {
        target = new URL(rawUrl);
      } catch {
        return json({ error: "Invalid URL" }, 400);
      }
      if (target.protocol !== "http:" && target.protocol !== "https:") {
        return json({ error: "Only HTTP(S) URLs can be tested" }, 400);
      }
      return json({ match: previewCredentialMatch(target, rules) });
    }

    return json({ error: "Not found" }, 404);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return json({ error: message }, 400);
  }
}

export async function handleAdminRequest(
  request: Request,
  env: AdminEnv,
): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith(ADMIN_PREFIX)) return null;

  const secret = normalizeAdminSecret(env.ADMIN_PATH);
  if (!secret) return new Response("Admin UI is not configured", { status: 503, headers: noStore() });

  const bootstrapPath = `${ADMIN_PREFIX}/${secret}`;
  if (url.pathname === bootstrapPath && request.method === "GET") {
    const headers = noStore({ location: ADMIN_PREFIX });
    headers.append(
      "set-cookie",
      `${ADMIN_COOKIE}=${secret}; Path=${ADMIN_PREFIX}; Max-Age=28800; HttpOnly; Secure; SameSite=Strict`,
    );
    return new Response(null, { status: 303, headers });
  }

  if (!adminAuthorized(request, secret)) return notFound();

  if (url.pathname === "/admin/logout" && request.method === "POST") {
    const headers = noStore();
    headers.append(
      "set-cookie",
      `${ADMIN_COOKIE}=; Path=${ADMIN_PREFIX}; Max-Age=0; HttpOnly; Secure; SameSite=Strict`,
    );
    return new Response(null, { status: 204, headers });
  }

  if (url.pathname === ADMIN_PREFIX && request.method === "GET") return htmlResponse();
  if (url.pathname.startsWith("/admin/api/")) return handleApi(request, env, url);
  return notFound();
}
