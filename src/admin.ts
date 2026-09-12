import {
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

function adminHtml(nonce: string): string {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Proxy Credentials</title>
<style nonce="${nonce}">
:root{color-scheme:dark;--bg:#0b0d10;--panel:#13171c;--panel2:#191f26;--border:#2a323c;--text:#e9eef5;--muted:#94a0ae;--accent:#7dd3fc;--danger:#f87171;--ok:#86efac;--shadow:0 18px 50px rgba(0,0,0,.35)}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{max-width:1180px;margin:0 auto;padding:28px 18px 60px}.top{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:24px}.brand h1{font-size:22px;margin:0 0 3px}.brand p{margin:0;color:var(--muted)}button,.btn{border:1px solid var(--border);background:var(--panel2);color:var(--text);padding:9px 12px;border-radius:9px;cursor:pointer;font-weight:600}button:hover{border-color:#45515f}.primary{background:#0e7490;border-color:#0891b2}.danger{color:#fecaca;border-color:#7f1d1d;background:#2a1114}.ghost{background:transparent}.grid{display:grid;grid-template-columns:minmax(0,1.55fr) minmax(320px,.8fr);gap:18px}.panel{background:var(--panel);border:1px solid var(--border);border-radius:14px;box-shadow:var(--shadow)}.panel-h{padding:16px 18px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between;gap:10px}.panel-b{padding:18px}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.search{flex:1;min-width:220px}.input,select,textarea{width:100%;background:#0d1116;color:var(--text);border:1px solid var(--border);border-radius:8px;padding:9px 10px;outline:none}.input:focus,select:focus,textarea:focus{border-color:#3b82f6}.rules{display:flex;flex-direction:column;gap:10px}.rule{border:1px solid var(--border);background:#0f1318;border-radius:11px;padding:13px}.rule-head{display:flex;justify-content:space-between;gap:10px}.rule-title{font-weight:750}.badges{display:flex;gap:6px;flex-wrap:wrap;margin-top:7px}.badge{font-size:12px;color:#cbd5e1;border:1px solid #334155;background:#111827;padding:2px 7px;border-radius:999px}.badge.on{color:#bbf7d0;border-color:#166534}.badge.off{color:#fecaca;border-color:#7f1d1d}.meta{margin-top:8px;color:var(--muted);font-size:12px;word-break:break-word}.rule-actions{display:flex;gap:7px;align-items:flex-start}.empty{padding:28px;text-align:center;color:var(--muted)}.field{margin-bottom:13px}.field label{display:block;color:#cbd5e1;font-weight:650;margin-bottom:6px}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.checkrow{display:flex;gap:14px;align-items:center;margin:12px 0}.checkrow label{display:flex;gap:7px;align-items:center;color:#cbd5e1}.headers{display:flex;flex-direction:column;gap:8px}.header-row{display:grid;grid-template-columns:minmax(120px,.8fr) minmax(180px,1.4fr) auto auto;gap:7px}.header-row input{min-width:0}.mini{padding:8px 9px}.form-actions{display:flex;gap:8px;justify-content:flex-end;margin-top:16px}.hint{font-size:12px;color:var(--muted);margin-top:5px}.status{min-height:20px;color:var(--muted);font-size:12px;margin-top:10px}.status.ok{color:var(--ok)}.status.err{color:#fca5a5}.testbox{display:flex;gap:8px}.test-result{margin-top:9px;padding:9px;border:1px dashed var(--border);border-radius:8px;color:var(--muted);min-height:38px;word-break:break-word}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#bae6fd}@media(max-width:850px){.grid{grid-template-columns:1fr}.top{align-items:flex-start}.row{grid-template-columns:1fr}.header-row{grid-template-columns:1fr}.rule-head{flex-direction:column}.rule-actions{align-self:flex-end}}
</style>
</head>
<body>
<div class="wrap">
  <div class="top">
    <div class="brand"><h1>Credential rules</h1><p>Inject headers by destination domain/path. Values stay server-side in Cloudflare KV.</p></div>
    <div class="toolbar"><button id="newRule" class="primary">+ New rule</button><button id="logout" class="ghost">Logout</button></div>
  </div>
  <div class="grid">
    <section class="panel">
      <div class="panel-h"><strong>Rules</strong><input id="filter" class="input search" placeholder="Filter domain, name, header…"></div>
      <div class="panel-b"><div id="rules" class="rules"></div></div>
    </section>
    <aside class="panel">
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
        <div class="field"><label>Headers</label><div id="headers" class="headers"></div><button id="addHeader" class="ghost mini" type="button">+ Add header</button></div>
        <div class="form-actions"><button id="deleteRule" class="danger" hidden>Delete</button><button id="saveRule" class="primary">Save rule</button></div>
        <div id="status" class="status"></div>
        <hr style="border:0;border-top:1px solid var(--border);margin:20px 0">
        <div class="field"><label>Test matching URL</label><div class="testbox"><input id="testUrl" class="input" placeholder="https://portal.example.com/api/foo"><button id="testMatch">Test</button></div><div id="testResult" class="test-result">No test yet.</div></div>
      </div>
    </aside>
  </div>
</div>
<script nonce="${nonce}">
(function(){
  var rules=[];
  var el=function(id){return document.getElementById(id)};
  function esc(s){return String(s)}
  async function api(path,opts){
    var r=await fetch(path,Object.assign({headers:{'content-type':'application/json'}},opts||{}));
    var data={}; try{data=await r.json()}catch(e){}
    if(!r.ok) throw new Error(data.error||('HTTP '+r.status));
    return data;
  }
  function setStatus(msg,ok){var s=el('status');s.textContent=msg||'';s.className='status '+(msg?(ok?'ok':'err'):'')}
  function headerRow(name,value){
    var row=document.createElement('div'); row.className='header-row';
    var n=document.createElement('input');n.className='input h-name';n.placeholder='Authorization';n.value=name||'';
    var v=document.createElement('input');v.className='input h-value';v.placeholder='Bearer …';v.type='password';v.value=value||'';
    var show=document.createElement('button');show.type='button';show.className='ghost mini';show.textContent='Show';show.onclick=function(){var hidden=v.type==='password';v.type=hidden?'text':'password';show.textContent=hidden?'Hide':'Show'};
    var del=document.createElement('button');del.type='button';del.className='ghost mini';del.textContent='×';del.onclick=function(){row.remove()};
    row.append(n,v,show,del);el('headers').appendChild(row);
  }
  function resetForm(){
    el('ruleId').value='';el('name').value='';el('host').value='';el('path').value='/';el('mode').value='override';el('priority').value='100';el('httpsOnly').checked=true;el('enabled').checked=true;el('headers').innerHTML='';headerRow('Authorization','');el('formTitle').textContent='New rule';el('deleteRule').hidden=true;setStatus('');
  }
  function editRule(id){
    var r=rules.find(function(x){return x.id===id});if(!r)return;
    el('ruleId').value=r.id;el('name').value=r.name;el('host').value=r.host_pattern;el('path').value=r.path_prefix;el('mode').value=r.mode;el('priority').value=String(r.priority);el('httpsOnly').checked=r.https_only;el('enabled').checked=r.enabled;el('headers').innerHTML='';Object.keys(r.headers).forEach(function(k){headerRow(k,r.headers[k])});el('formTitle').textContent='Edit rule';el('deleteRule').hidden=false;setStatus('');window.scrollTo({top:0,behavior:'smooth'});
  }
  function render(){
    var q=el('filter').value.trim().toLowerCase();var root=el('rules');root.innerHTML='';
    var shown=rules.filter(function(r){return !q||(r.name+' '+r.host_pattern+' '+r.path_prefix+' '+Object.keys(r.headers).join(' ')).toLowerCase().includes(q)});
    if(!shown.length){var e=document.createElement('div');e.className='empty';e.textContent=rules.length?'No matching rules.':'No credential rules yet.';root.appendChild(e);return}
    shown.slice().sort(function(a,b){return b.priority-a.priority||a.name.localeCompare(b.name)}).forEach(function(r){
      var card=document.createElement('div');card.className='rule';var head=document.createElement('div');head.className='rule-head';
      var left=document.createElement('div');var title=document.createElement('div');title.className='rule-title';title.textContent=r.name;left.appendChild(title);
      var badges=document.createElement('div');badges.className='badges';
      [r.enabled?'enabled':'disabled',r.https_only?'HTTPS only':'HTTP + HTTPS',r.mode,r.host_pattern+r.path_prefix].forEach(function(t,i){var b=document.createElement('span');b.className='badge '+(i===0?(r.enabled?'on':'off'):'');b.textContent=t;badges.appendChild(b)});left.appendChild(badges);
      var meta=document.createElement('div');meta.className='meta';meta.textContent='Headers: '+Object.keys(r.headers).join(', ')+' · priority '+r.priority;left.appendChild(meta);
      var actions=document.createElement('div');actions.className='rule-actions';var edit=document.createElement('button');edit.className='ghost mini';edit.textContent='Edit';edit.onclick=function(){editRule(r.id)};actions.appendChild(edit);head.append(left,actions);card.appendChild(head);root.appendChild(card);
    })
  }
  async function load(){try{var data=await api('/admin/api/rules');rules=data.rules||[];render()}catch(e){setStatus(e.message,false)}}
  function collect(){
    var headers={};document.querySelectorAll('.header-row').forEach(function(row){var n=row.querySelector('.h-name').value.trim();var v=row.querySelector('.h-value').value;if(n)headers[n]=v});
    return {name:el('name').value.trim(),host_pattern:el('host').value.trim(),path_prefix:el('path').value.trim()||'/',mode:el('mode').value,priority:Number(el('priority').value||100),https_only:el('httpsOnly').checked,enabled:el('enabled').checked,headers:headers};
  }
  el('saveRule').onclick=async function(){try{setStatus('Saving…',true);var id=el('ruleId').value;var data=await api(id?('/admin/api/rules/'+encodeURIComponent(id)):'/admin/api/rules',{method:id?'PUT':'POST',body:JSON.stringify(collect())});rules=data.rules;render();if(id)editRule(id);else resetForm();setStatus('Saved.',true)}catch(e){setStatus(e.message,false)}};
  el('deleteRule').onclick=async function(){var id=el('ruleId').value;if(!id||!confirm('Delete this credential rule?'))return;try{var data=await api('/admin/api/rules/'+encodeURIComponent(id),{method:'DELETE'});rules=data.rules;render();resetForm();setStatus('Deleted.',true)}catch(e){setStatus(e.message,false)}};
  el('testMatch').onclick=async function(){try{var data=await api('/admin/api/match',{method:'POST',body:JSON.stringify({url:el('testUrl').value.trim()})});var m=data.match;el('testResult').textContent=m.matched_rule_names.length?('Rules: '+m.matched_rule_names.join(' → ')+' | Headers: '+m.injected_header_names.join(', ')):'No credential rule matches.'}catch(e){el('testResult').textContent=e.message}};
  el('addHeader').onclick=function(){headerRow('','')};el('newRule').onclick=resetForm;el('reset').onclick=resetForm;el('filter').oninput=render;
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

function rulesWithMaskedMetadata(rules: CredentialRule[]) {
  return rules.map((rule) => ({
    ...rule,
    header_names: Object.keys(rule.headers),
  }));
}

async function handleApi(request: Request, env: AdminEnv, url: URL): Promise<Response> {
  const kv = env.CREDENTIALS;
  if (!kv) return json({ error: "CREDENTIALS KV binding is not configured" }, 503);

  try {
    const rules = await loadCredentialRules(kv);

    if (url.pathname === "/admin/api/rules" && request.method === "GET") {
      // Admin UI is already authenticated. Return values so rules can be edited;
      // responses are no-store and never exposed through the MCP tool.
      return json({ rules: rulesWithMaskedMetadata(rules) });
    }

    if (url.pathname === "/admin/api/rules" && request.method === "POST") {
      const input = (await readJson(request)) as CredentialRuleInput;
      const rule = validateCredentialRuleInput(input);
      const next = [...rules, rule];
      await saveCredentialRules(kv, next);
      return json({ rule, rules: next }, 201);
    }

    const match = url.pathname.match(/^\/admin\/api\/rules\/([A-Za-z0-9_-]+)$/);
    if (match && request.method === "PUT") {
      const id = match[1];
      const existing = rules.find((rule) => rule.id === id);
      if (!existing) return json({ error: "Rule not found" }, 404);
      const input = (await readJson(request)) as CredentialRuleInput;
      const updated = validateCredentialRuleInput(input, existing);
      const next = rules.map((rule) => (rule.id === id ? updated : rule));
      await saveCredentialRules(kv, next);
      return json({ rule: updated, rules: next });
    }

    if (match && request.method === "DELETE") {
      const id = match[1];
      if (!rules.some((rule) => rule.id === id)) return json({ error: "Rule not found" }, 404);
      const next = rules.filter((rule) => rule.id !== id);
      await saveCredentialRules(kv, next);
      return json({ rules: next });
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
