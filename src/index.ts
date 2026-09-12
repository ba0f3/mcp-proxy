import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

interface Env {
  MCP_PATH: string;
  NC_API_KEY: string;
}

const VERSION = "0.3.0";
const DEFAULT_TIMEOUT_MS = 20_000;
const MAX_TIMEOUT_MS = 60_000;
const DEFAULT_MAX_BYTES = 1024 * 1024;
const HARD_MAX_BYTES = 4 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES = 8 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;

// Server-side upstream credential injection. Keep this deliberately narrow:
// exact HTTPS host + NocoBase MCP path only. The credential never appears in
// MCP tool arguments, logs, responses, or redirects to other hosts.
const NOCOBASE_AUTH_HOST = "portal-dev1az5avn.vozer.org";
const NOCOBASE_MCP_PATH_PREFIX = "/api/mcp";

const ALLOWED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

// These headers are controlled by the HTTP transport / Cloudflare and are not
// useful as arbitrary curl inputs. Authentication headers are intentionally
// NOT on this list: Authorization, X-Api-Key, Cookie, etc. are forwarded.
const FORBIDDEN_REQUEST_HEADERS = new Set([
  "host",
  "content-length",
  "transfer-encoding",
  "connection",
  "upgrade",
  "proxy-authorization",
  "proxy-authenticate",
  "forwarded",
  "via",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "cf-connecting-ip",
  "cf-ray",
  "cf-visitor",
]);

const BLOCKED_HOST_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
];

const TEXT_CONTENT_TYPES = [
  "text/",
  "application/json",
  "application/ld+json",
  "application/xml",
  "application/xhtml+xml",
  "application/javascript",
  "application/x-javascript",
  "application/graphql",
  "application/x-www-form-urlencoded",
  "application/problem+json",
  "application/problem+xml",
  "image/svg+xml",
];

type CurlArgs = {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  body_base64?: string;
  json?: unknown;
  form?: Record<string, string>;
  timeout_ms?: number;
  max_bytes?: number;
  follow_redirects?: boolean;
  max_redirects?: number;
};

type CurlResult = {
  request_id: string;
  status: number;
  status_text: string;
  final_url: string;
  headers: Record<string, string>;
  body: string;
  body_encoding: "utf-8" | "base64";
  request_bytes: number;
  response_bytes: number;
  elapsed_ms: number;
  redirects: number;
  server_auth_injected: boolean;
  truncated: boolean;
};

type PreparedBody = {
  body: string | ArrayBuffer | undefined;
  bytes: number;
  kind: "none" | "raw" | "base64" | "json" | "form";
};

function logEvent(
  level: "info" | "warn" | "error",
  event: string,
  fields: Record<string, unknown> = {},
): void {
  const line = JSON.stringify({
    ts: new Date().toISOString(),
    service: "mcp-proxy",
    version: VERSION,
    level,
    event,
    ...fields,
  });

  if (level === "error") console.error(line);
  else if (level === "warn") console.warn(line);
  else console.log(line);
}

function normalizeSecretPath(secret: string): string {
  const value = secret.trim().replace(/^\/+|\/+$/g, "");
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(value)) {
    throw new Error(
      "MCP_PATH must be a single URL-safe random segment, 24-128 characters long",
    );
  }
  return `/${value}`;
}

function isIpLiteral(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (host.includes(":")) return true;
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host);
}

function safeTarget(url: URL): string {
  // Deliberately exclude query values and fragments from logs because API keys
  // are sometimes passed in query strings. Keep the path for troubleshooting.
  return `${url.protocol}//${url.host}${url.pathname}`;
}

function queryKeys(url: URL): string[] {
  return [...new Set(Array.from(url.searchParams.keys()))].sort();
}

function sanitizeErrorForLog(error: unknown): { name: string; message: string } {
  const name = error instanceof Error ? error.name : "Error";
  const raw = error instanceof Error ? error.message : String(error);
  const message = raw.replace(/https?:\/\/[^\s"'<>]+/gi, (value) => {
    try {
      return safeTarget(new URL(value));
    } catch {
      return "[url]";
    }
  });
  return { name, message: message.slice(0, 500) };
}

function validateTargetUrl(rawUrl: string, selfHost: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("Invalid URL");
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    throw new Error("Only http:// and https:// URLs are allowed");
  }

  if (url.username || url.password) {
    throw new Error(
      "Credentials embedded in URLs are not supported; use Authorization or another request header",
    );
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const ownHost = selfHost.toLowerCase().replace(/\.$/, "");

  if (!hostname) throw new Error("URL hostname is required");
  if (hostname === ownHost) throw new Error("Requests back to this MCP host are blocked");
  if (hostname === "localhost") throw new Error("localhost is blocked");
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error("Local/internal hostnames are blocked");
  }

  // Workers global fetch does not support direct IP-address URLs. Reject them
  // explicitly so failures are deterministic and cannot be used to probe
  // link-local/private address space.
  if (isIpLiteral(hostname)) {
    throw new Error("IP-literal targets are blocked; use a public DNS hostname");
  }

  return url;
}

function sanitizeHeaders(input?: Record<string, string>): Headers {
  const headers = new Headers();
  if (!input) return headers;

  for (const [rawName, rawValue] of Object.entries(input)) {
    const name = rawName.trim().toLowerCase();
    if (!name || FORBIDDEN_REQUEST_HEADERS.has(name) || name.startsWith("cf-")) {
      continue;
    }
    headers.set(name, String(rawValue));
  }

  return headers;
}

function authSummary(headers: Headers): Record<string, boolean> {
  return {
    authorization: headers.has("authorization"),
    x_api_key: headers.has("x-api-key"),
    cookie: headers.has("cookie"),
  };
}

function isNocoBaseMcpTarget(url: URL): boolean {
  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const pathMatches =
    url.pathname === NOCOBASE_MCP_PATH_PREFIX ||
    url.pathname.startsWith(`${NOCOBASE_MCP_PATH_PREFIX}/`);

  return url.protocol === "https:" && hostname === NOCOBASE_AUTH_HOST && pathMatches;
}

function buildRequestHeaders(
  callerHeaders: Headers,
  url: URL,
  env: Env,
): { headers: Headers; serverAuthInjected: boolean } {
  const headers = new Headers(callerHeaders);
  if (!isNocoBaseMcpTarget(url)) {
    return { headers, serverAuthInjected: false };
  }

  const rawToken = (env.NC_API_KEY ?? "").trim();
  if (!rawToken) {
    throw new Error("NC_API_KEY is not configured for NocoBase server authentication");
  }

  // Accept either a raw NocoBase token or a pre-prefixed Bearer value in the
  // Worker secret, but never expose it back to the MCP client.
  const authorization = /^Bearer\s+/i.test(rawToken) ? rawToken : `Bearer ${rawToken}`;
  headers.set("authorization", authorization);

  return { headers, serverAuthInjected: true };
}

function headersToObject(headers: Headers): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [name, value] of headers.entries()) result[name] = value;
  return result;
}

function isTextual(contentType: string | null): boolean {
  if (!contentType) return true;
  const normalized = contentType.toLowerCase().split(";", 1)[0].trim();
  return TEXT_CONTENT_TYPES.some((prefix) => normalized.startsWith(prefix));
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(input: string): ArrayBuffer {
  const compact = input.replace(/\s+/g, "");
  if (compact.length > Math.ceil((MAX_REQUEST_BODY_BYTES * 4) / 3) + 8) {
    throw new Error(`Decoded request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
  }

  let binary: string;
  try {
    binary = atob(compact);
  } catch {
    throw new Error("body_base64 is not valid base64");
  }

  if (binary.length > MAX_REQUEST_BODY_BYTES) {
    throw new Error(`Decoded request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
  }

  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function prepareBody(args: CurlArgs, headers: Headers): PreparedBody {
  const supplied = [
    args.body !== undefined,
    args.body_base64 !== undefined,
    args.json !== undefined,
    args.form !== undefined,
  ].filter(Boolean).length;

  if (supplied > 1) {
    throw new Error("Use only one of body, body_base64, json, or form");
  }

  if (args.body !== undefined) {
    const bytes = new TextEncoder().encode(args.body).byteLength;
    if (bytes > MAX_REQUEST_BODY_BYTES) {
      throw new Error(`Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
    }
    return { body: args.body, bytes, kind: "raw" };
  }

  if (args.body_base64 !== undefined) {
    const body = base64ToArrayBuffer(args.body_base64);
    return { body, bytes: body.byteLength, kind: "base64" };
  }

  if (args.json !== undefined) {
    let body: string;
    try {
      body = JSON.stringify(args.json);
    } catch {
      throw new Error("json body is not serializable");
    }
    const bytes = new TextEncoder().encode(body).byteLength;
    if (bytes > MAX_REQUEST_BODY_BYTES) {
      throw new Error(`Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
    }
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
    return { body, bytes, kind: "json" };
  }

  if (args.form !== undefined) {
    const body = new URLSearchParams(args.form).toString();
    const bytes = new TextEncoder().encode(body).byteLength;
    if (bytes > MAX_REQUEST_BODY_BYTES) {
      throw new Error(`Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
    }
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/x-www-form-urlencoded");
    }
    return { body, bytes, kind: "form" };
  }

  return { body: undefined, bytes: 0, kind: "none" };
}

async function readLimitedBody(
  response: Response,
  maxBytes: number,
): Promise<{ bytes: Uint8Array; truncated: boolean }> {
  if (!response.body) return { bytes: new Uint8Array(), truncated: false };

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let truncated = false;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value?.byteLength) continue;

      const remaining = maxBytes - total;
      if (remaining <= 0) {
        truncated = true;
        await reader.cancel("response limit reached");
        break;
      }

      if (value.byteLength > remaining) {
        chunks.push(value.subarray(0, remaining));
        total += remaining;
        truncated = true;
        await reader.cancel("response limit reached");
        break;
      }

      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }

  const combined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { bytes: combined, truncated };
}

function redirectRequest(
  status: number,
  method: string,
  body: string | ArrayBuffer | undefined,
  headers: Headers,
): { method: string; body: string | ArrayBuffer | undefined; headers: Headers } {
  if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
    const nextHeaders = new Headers(headers);
    nextHeaders.delete("content-type");
    return { method: "GET", body: undefined, headers: nextHeaders };
  }
  return { method, body, headers };
}

async function performCurl(
  args: CurlArgs,
  selfHost: string,
  env: Env,
  mcpRay?: string,
): Promise<CurlResult> {
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();
  let currentUrl = validateTargetUrl(args.url, selfHost);
  let method = (args.method ?? "GET").toUpperCase();
  let callerHeaders = sanitizeHeaders(args.headers);
  const prepared = prepareBody(args, callerHeaders);
  let body = prepared.body;

  if (!ALLOWED_METHODS.has(method)) {
    throw new Error(`Method ${method} is not allowed`);
  }
  if ((method === "GET" || method === "HEAD") && body !== undefined) {
    throw new Error(`${method} requests cannot include a body`);
  }

  const timeoutMs = Math.min(args.timeout_ms ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const maxBytes = Math.min(args.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
  const followRedirects = args.follow_redirects ?? true;
  const maxRedirects = Math.min(args.max_redirects ?? DEFAULT_MAX_REDIRECTS, 10);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("request timeout"), timeoutMs);
  let redirectCount = 0;
  let serverAuthUsed = false;

  logEvent("info", "curl.start", {
    request_id: requestId,
    mcp_ray: mcpRay,
    method,
    target: safeTarget(currentUrl),
    query_keys: queryKeys(currentUrl),
    body_kind: prepared.kind,
    request_bytes: prepared.bytes,
    timeout_ms: timeoutMs,
    max_response_bytes: maxBytes,
    follow_redirects: followRedirects,
    server_auth_target: isNocoBaseMcpTarget(currentUrl),
    ...authSummary(callerHeaders),
  });

  try {
    for (;;) {
      // Derive effective headers for every hop. Server-side credentials are
      // never stored in callerHeaders, so they cannot accidentally survive a
      // redirect to another hostname.
      const requestHeaders = buildRequestHeaders(callerHeaders, currentUrl, env);
      if (requestHeaders.serverAuthInjected) {
        serverAuthUsed = true;
        logEvent("info", "curl.auth_injected", {
          request_id: requestId,
          mcp_ray: mcpRay,
          target: safeTarget(currentUrl),
          auth_source: "NC_API_KEY",
          auth_scheme: "Bearer",
        });
      }

      const response = await fetch(currentUrl.toString(), {
        method,
        headers: requestHeaders.headers,
        body,
        redirect: "manual",
        signal: controller.signal,
      });

      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      const location = response.headers.get("location");

      if (followRedirects && isRedirect && location) {
        if (redirectCount >= maxRedirects) {
          await response.body?.cancel();
          throw new Error(`Too many redirects (>${maxRedirects})`);
        }

        const nextUrl = validateTargetUrl(new URL(location, currentUrl).toString(), selfHost);
        const crossOrigin = nextUrl.origin !== currentUrl.origin;
        const nextServerAuth = isNocoBaseMcpTarget(nextUrl);
        redirectCount += 1;

        // Caller-supplied credentials keep curl-like redirect semantics. The
        // server-side NocoBase token is different: it is derived per-hop and is
        // only ever attached to the exact allowlisted HTTPS MCP endpoint.
        logEvent(crossOrigin ? "warn" : "info", "curl.redirect", {
          request_id: requestId,
          mcp_ray: mcpRay,
          hop: redirectCount,
          status: response.status,
          from: safeTarget(currentUrl),
          to: safeTarget(nextUrl),
          cross_origin: crossOrigin,
          caller_credentials_forwarded:
            crossOrigin && Object.values(authSummary(callerHeaders)).some(Boolean),
          server_auth_current: requestHeaders.serverAuthInjected,
          server_auth_next: nextServerAuth,
          server_auth_leaked_cross_origin: false,
        });

        const next = redirectRequest(response.status, method, body, callerHeaders);
        await response.body?.cancel();
        currentUrl = nextUrl;
        method = next.method;
        body = next.body;
        callerHeaders = next.headers;
        continue;
      }

      const { bytes, truncated } = await readLimitedBody(response, maxBytes);
      const textual = isTextual(response.headers.get("content-type"));
      const elapsedMs = Date.now() - startedAt;
      const result: CurlResult = {
        request_id: requestId,
        status: response.status,
        status_text: response.statusText,
        final_url: currentUrl.toString(),
        headers: headersToObject(response.headers),
        body: textual
          ? new TextDecoder("utf-8", { fatal: false }).decode(bytes)
          : bytesToBase64(bytes),
        body_encoding: textual ? "utf-8" : "base64",
        request_bytes: prepared.bytes,
        response_bytes: bytes.byteLength,
        elapsed_ms: elapsedMs,
        redirects: redirectCount,
        server_auth_injected: serverAuthUsed,
        truncated,
      };

      logEvent("info", "curl.complete", {
        request_id: requestId,
        mcp_ray: mcpRay,
        method,
        target: safeTarget(currentUrl),
        status: response.status,
        content_type: response.headers.get("content-type"),
        request_bytes: prepared.bytes,
        response_bytes: bytes.byteLength,
        elapsed_ms: elapsedMs,
        redirects: redirectCount,
        server_auth_injected: serverAuthUsed,
        truncated,
      });

      return result;
    }
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    if (controller.signal.aborted) {
      logEvent("error", "curl.error", {
        request_id: requestId,
        mcp_ray: mcpRay,
        method,
        target: safeTarget(currentUrl),
        elapsed_ms: elapsedMs,
        server_auth_injected: serverAuthUsed,
        error_name: "TimeoutError",
        error_message: `Request timed out after ${timeoutMs} ms`,
      });
      throw new Error(`Request timed out after ${timeoutMs} ms`);
    }

    const safeError = sanitizeErrorForLog(error);
    logEvent("error", "curl.error", {
      request_id: requestId,
      mcp_ray: mcpRay,
      method,
      target: safeTarget(currentUrl),
      elapsed_ms: elapsedMs,
      server_auth_injected: serverAuthUsed,
      error_name: safeError.name,
      error_message: safeError.message,
    });
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function createServer(selfHost: string, env: Env, mcpRay?: string): McpServer {
  const server = new McpServer(
    { name: "internet-curl", version: VERSION },
    {
      instructions:
        "General-purpose read/write curl for the public Internet. State-changing POST/PUT/PATCH/DELETE requests are allowed. Caller-provided Authorization, X-Api-Key, Cookie, and other application headers are forwarded. For https://portal-dev1az5avn.vozer.org/api/mcp, the Worker injects NocoBase Authorization server-side from NC_API_KEY, so callers should omit credentials for that endpoint. Only SSRF/private-network classes, self-recursion, invalid transport headers, and bounded resource limits are restricted.",
    },
  );

  server.registerTool(
    "curl",
    {
      title: "Internet Curl (read/write)",
      description:
        "General-purpose HTTP/HTTPS curl for agents. Supports authenticated and state-changing API calls, including POST, PUT, PATCH, DELETE, JSON, form bodies, raw bodies, and base64 binary bodies. Custom application headers are forwarded. For portal-dev1az5avn.vozer.org/api/mcp, do not send Authorization or API keys: the gateway injects the NocoBase Bearer token server-side. Public Internet only; SSRF/private/internal targets and this MCP host are blocked.",
      inputSchema: z.object({
        url: z.string().url().describe("Public http:// or https:// URL"),
        method: z
          .enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
          .optional()
          .describe("HTTP method; defaults to GET. Write methods are allowed"),
        headers: z
          .record(z.string(), z.string())
          .optional()
          .describe(
            "Request headers. Custom application headers are allowed. Authorization/X-Api-Key/Cookie are forwarded for normal targets, but credentials should be omitted for portal-dev1az5avn.vozer.org/api/mcp because server-side NocoBase auth is injected there",
          ),
        body: z.string().optional().describe("Raw UTF-8 request body"),
        body_base64: z
          .string()
          .optional()
          .describe("Base64-encoded binary request body. Mutually exclusive with body/json/form"),
        json: z
          .unknown()
          .optional()
          .describe("JSON value to serialize as the request body; automatically sets application/json unless Content-Type is provided"),
        form: z
          .record(z.string(), z.string())
          .optional()
          .describe("URL-encoded form fields; automatically sets application/x-www-form-urlencoded unless Content-Type is provided"),
        timeout_ms: z
          .number()
          .int()
          .min(500)
          .max(MAX_TIMEOUT_MS)
          .optional()
          .describe("Overall request timeout in milliseconds; default 20000, max 60000"),
        max_bytes: z
          .number()
          .int()
          .min(1)
          .max(HARD_MAX_BYTES)
          .optional()
          .describe("Maximum response body bytes returned; default 1 MiB, max 4 MiB"),
        follow_redirects: z.boolean().optional().describe("Follow redirects; default true"),
        max_redirects: z
          .number()
          .int()
          .min(0)
          .max(10)
          .optional()
          .describe("Maximum redirects when following; default 5"),
      }),
      outputSchema: z.object({
        request_id: z.string(),
        status: z.number().int(),
        status_text: z.string(),
        final_url: z.string(),
        headers: z.record(z.string(), z.string()),
        body: z.string(),
        body_encoding: z.enum(["utf-8", "base64"]),
        request_bytes: z.number().int(),
        response_bytes: z.number().int(),
        elapsed_ms: z.number().int(),
        redirects: z.number().int(),
        server_auth_injected: z.boolean(),
        truncated: z.boolean(),
      }),
      annotations: {
        readOnlyHint: false,
        openWorldHint: true,
      },
    },
    async (args) => {
      try {
        const result = await performCurl(args, selfHost, env, mcpRay);
        return {
          content: [{ type: "text", text: JSON.stringify(result) }],
          structuredContent: result,
        };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: "text", text: message }],
          isError: true,
        };
      }
    },
  );

  return server;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const mcpRay = request.headers.get("cf-ray") ?? undefined;
    let expectedPath: string;
    try {
      expectedPath = normalizeSecretPath(env.MCP_PATH ?? "");
    } catch (error) {
      logEvent("error", "mcp.misconfigured", {
        mcp_ray: mcpRay,
        host: new URL(request.url).host,
        error: sanitizeErrorForLog(error).message,
      });
      return new Response("Worker is not configured", { status: 503 });
    }

    const requestUrl = new URL(request.url);

    // The path itself is the bearer secret. Never log requestUrl.pathname here.
    // Return 404 rather than 401 so MCP clients do not start OAuth discovery.
    if (requestUrl.pathname !== expectedPath) {
      logEvent("warn", "mcp.auth_rejected", {
        mcp_ray: mcpRay,
        method: request.method,
        host: requestUrl.host,
      });
      return new Response("Not found", { status: 404 });
    }

    const handler = createMcpHandler(() => createServer(requestUrl.hostname, env, mcpRay));
    return handler.fetch(request);
  },
};
