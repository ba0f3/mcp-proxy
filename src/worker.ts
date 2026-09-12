import app from "./index";

interface Env {
  MCP_PATH: string;
  ADMIN_PASSWORD: string;
}

const ADMIN_PREFIX = "/admin";
const ADMIN_COOKIE = "mcp_admin";
const ADMIN_SESSION_SECONDS = 8 * 60 * 60;

function validOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;

  try {
    const requestUrl = new URL(request.url);
    const originUrl = new URL(origin);
    return originUrl.origin === requestUrl.origin;
  } catch {
    return false;
  }
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

function bytesToHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (value) => value.toString(16).padStart(2, "0")).join("");
}

async function adminSessionSecret(password: string): Promise<string> {
  const input = new TextEncoder().encode(`mcp-proxy-admin-session:v1:${password}`);
  return bytesToHex(await crypto.subtle.digest("SHA-256", input));
}

async function passwordMatches(candidate: string, expected: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [candidateHash, expectedHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(candidate)),
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
  ]);
  const a = new Uint8Array(candidateHash);
  const b = new Uint8Array(expectedHash);
  let diff = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

function adminHeaders(headers: HeadersInit = {}): Headers {
  const result = new Headers(headers);
  result.set("cache-control", "no-store, private");
  result.set("pragma", "no-cache");
  result.set("x-content-type-options", "nosniff");
  result.set("referrer-policy", "no-referrer");
  result.set("x-frame-options", "DENY");
  return result;
}

function loginPage(message = "", status = 200): Response {
  const nonce = crypto.randomUUID().replace(/-/g, "");
  const safeMessage = message
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;");
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>MCP Proxy Admin</title>
<style nonce="${nonce}">
:root{color-scheme:dark;--bg:#0b0d10;--panel:#13171c;--border:#2a323c;--text:#e9eef5;--muted:#94a0ae;--danger:#fca5a5}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.card{width:min(420px,calc(100vw - 32px));background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:24px;box-shadow:0 18px 50px rgba(0,0,0,.35)}h1{font-size:21px;margin:0 0 5px}p{margin:0 0 20px;color:var(--muted)}label{display:block;font-weight:650;margin-bottom:7px}input{width:100%;background:#0d1116;color:var(--text);border:1px solid var(--border);border-radius:9px;padding:11px 12px;outline:none}input:focus{border-color:#3b82f6}button{width:100%;margin-top:14px;border:1px solid #0891b2;background:#0e7490;color:white;padding:10px 12px;border-radius:9px;cursor:pointer;font-weight:700}.error{min-height:20px;margin-top:12px;color:var(--danger);font-size:12px}
</style>
</head>
<body>
<form class="card" method="post" action="/admin/login" autocomplete="on">
<h1>MCP Proxy Admin</h1>
<p>Sign in to manage domain credential headers.</p>
<label for="password">Admin password</label>
<input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
<button type="submit">Sign in</button>
<div class="error">${safeMessage}</div>
</form>
</body>
</html>`;
  const headers = adminHeaders({ "content-type": "text/html; charset=utf-8" });
  headers.set(
    "content-security-policy",
    `default-src 'none'; style-src 'nonce-${nonce}'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'`,
  );
  return new Response(html, { status, headers });
}

function adminCookie(secret: string): string {
  return `${ADMIN_COOKIE}=${secret}; Path=${ADMIN_PREFIX}; Max-Age=${ADMIN_SESSION_SECONDS}; HttpOnly; Secure; SameSite=Strict`;
}

async function handleAdminLogin(request: Request, env: Env, sessionSecret: string): Promise<Response | null> {
  const url = new URL(request.url);
  if (!url.pathname.startsWith(ADMIN_PREFIX)) return null;

  if (!env.ADMIN_PASSWORD) {
    return new Response("Admin UI is not configured", { status: 503, headers: adminHeaders() });
  }

  const authorized = parseCookies(request.headers.get("cookie"))[ADMIN_COOKIE] === sessionSecret;

  if (url.pathname === "/admin/login") {
    if (request.method === "GET") {
      if (authorized) return new Response(null, { status: 303, headers: adminHeaders({ location: ADMIN_PREFIX }) });
      return loginPage();
    }

    if (request.method === "POST") {
      const length = Number(request.headers.get("content-length") ?? "0");
      if (Number.isFinite(length) && length > 16 * 1024) return loginPage("Request too large.", 413);

      let candidate = "";
      try {
        const form = await request.formData();
        candidate = String(form.get("password") ?? "");
      } catch {
        return loginPage("Invalid login request.", 400);
      }

      if (!(await passwordMatches(candidate, env.ADMIN_PASSWORD))) {
        return loginPage("Invalid password.", 401);
      }

      const headers = adminHeaders({ location: ADMIN_PREFIX });
      headers.append("set-cookie", adminCookie(sessionSecret));
      return new Response(null, { status: 303, headers });
    }

    return new Response("Method not allowed", { status: 405, headers: adminHeaders({ allow: "GET, POST" }) });
  }

  if (url.pathname === ADMIN_PREFIX && request.method === "GET" && !authorized) {
    return loginPage();
  }

  if (url.pathname.startsWith("/admin/api/") && !authorized) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: adminHeaders({ "content-type": "application/json; charset=utf-8" }),
    });
  }

  // The old URL-secret bootstrap route must never be exposed now that admin
  // authentication is password based. Only the fixed UI/API/logout paths pass.
  if (!authorized && url.pathname.startsWith(`${ADMIN_PREFIX}/`)) {
    return new Response("Not found", { status: 404, headers: adminHeaders() });
  }

  return null;
}

function withSyntheticAdminPath<T extends object>(env: T, secret: string): T & { ADMIN_PATH: string } {
  return new Proxy(env, {
    get(target, property, receiver) {
      if (property === "ADMIN_PATH") return secret;
      return Reflect.get(target, property, receiver);
    },
    has(target, property) {
      if (property === "ADMIN_PATH") return true;
      return Reflect.has(target, property);
    },
  }) as T & { ADMIN_PATH: string };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const requestUrl = new URL(request.url);
    const isAdminRequest =
      requestUrl.pathname === ADMIN_PREFIX || requestUrl.pathname.startsWith(`${ADMIN_PREFIX}/`);

    // Admin is a normal password-authenticated web UI. Do not run MCP's
    // Streamable HTTP Origin gate on browser form/API requests. The admin
    // session cookie is Secure + HttpOnly + SameSite=Strict and the UI CSP
    // restricts forms/connects to self.
    if (isAdminRequest) {
      const sessionSecret = await adminSessionSecret(env.ADMIN_PASSWORD ?? "");
      const loginResponse = await handleAdminLogin(request, env, sessionSecret);
      if (loginResponse) return loginResponse;

      // Keep the existing admin implementation/session cookie, but provide its
      // secret internally instead of exposing it as a URL path or Worker secret.
      return app.fetch(request, withSyntheticAdminPath(env, sessionSecret));
    }

    // MCP Streamable HTTP requires Origin validation. Non-browser/server-side
    // clients normally omit Origin; if present, only same-origin is accepted.
    if (!validOrigin(request)) {
      console.warn(
        JSON.stringify({
          ts: new Date().toISOString(),
          service: "mcp-proxy",
          level: "warn",
          event: "mcp.origin_rejected",
          mcp_ray: request.headers.get("cf-ray") ?? undefined,
          method: request.method,
          host: requestUrl.host,
          origin: request.headers.get("origin"),
        }),
      );
      return new Response("Forbidden", { status: 403 });
    }

    return app.fetch(request, env);
  },
};
