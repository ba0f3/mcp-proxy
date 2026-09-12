import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";
import { handleAdminRequest } from "./admin";
import {
  applyCredentialRules,
  loadCredentialRules,
  type CredentialKV,
} from "./credentials";

interface Env {
  MCP_PATH: string;
  ADMIN_PATH?: string;
  CREDENTIALS?: CredentialKV;
}

const VERSION = "0.4.0";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 10;

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
  credential_rules_applied: number;
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

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const ownHost = selfHost.toLowerCase().replace(/\.$/, "");

  if (!hostname) throw new Error("URL hostname is required");
  if (hostname === ownHost) throw new Error("Requests back to this MCP host are blocked");
  if (hostname === "localhost") throw new Error("localhost is blocked");
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error("Local/internal hostnames are blocked");
  }

  if (isIpLiteral(hostname)) {
    throw new Error("IP-literal targets are blocked; use a public DNS hostname");
  }

  return url;
}

function buildHeaders(input?: Record<string, string>): Headers {
  // Transparent pass-through: caller headers remain untouched. Managed
  // credential rules are layered onto a per-hop copy immediately before fetch.
  return new Headers(input ?? {});
}

function headerSummary(headers: Headers): Record<string, unknown> {
  const names = Array.from(headers.keys()).sort();
  return {
    header_names: names,
    authorization: headers.has("authorization"),
    x_api_key: headers.has("x-api-key"),
    cookie: headers.has("cookie"),
  };
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
  const binary = atob(compact);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function prepareBody(args: CurlArgs, headers: Headers): PreparedBody {
  if (args.body !== undefined) {
    return {
      body: args.body,
      bytes: new TextEncoder().encode(args.body).byteLength,
      kind: "raw",
    };
  }

  if (args.body_base64 !== undefined) {
    const body = base64ToArrayBuffer(args.body_base64);
    return { body, bytes: body.byteLength, kind: "base64" };
  }

  if (args.json !== undefined) {
    const body = JSON.stringify(args.json);
    if (!headers.has("content-type")) headers.set("content-type", "application/json");
    return {
      body,
      bytes: new TextEncoder().encode(body).byteLength,
      kind: "json",
    };
  }

  if (args.form !== undefined) {
    const body = new URLSearchParams(args.form).toString();
    if (!headers.has("content-type")) {
      headers.set("content-type", "application/x-www-form-urlencoded");
    }
    return {
      body,
      bytes: new TextEncoder().encode(body).byteLength,
      kind: "form",
    };
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
  const upperMethod = method.toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && upperMethod === "POST")) {
    return { method: "GET", body: undefined, headers };
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
  let method = args.method ?? "GET";
  let callerHeaders = buildHeaders(args.headers);
  const prepared = prepareBody(args, callerHeaders);
  let body = prepared.body;

  const timeoutMs = args.timeout_ms ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = args.max_bytes ?? DEFAULT_MAX_BYTES;
  const followRedirects = args.follow_redirects ?? true;
  const maxRedirects = args.max_redirects ?? DEFAULT_MAX_REDIRECTS;
  const credentialRules = await loadCredentialRules(env.CREDENTIALS);

  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs > 0) {
    timer = setTimeout(() => controller.abort("request timeout"), timeoutMs);
  }

  let redirectCount = 0;
  const usedRuleIds = new Set<string>();

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
    credential_rules_loaded: credentialRules.length,
    ...headerSummary(callerHeaders),
  });

  try {
    for (;;) {
      // Managed headers are computed independently for every outbound hop.
      // They never become part of callerHeaders, so a credential for one domain
      // cannot accidentally follow a redirect to another domain.
      const applied = applyCredentialRules(callerHeaders, currentUrl, credentialRules);
      for (const id of applied.matched_rule_ids) usedRuleIds.add(id);

      if (applied.matched_rule_ids.length > 0) {
        logEvent("info", "curl.credentials_applied", {
          request_id: requestId,
          mcp_ray: mcpRay,
          target: safeTarget(currentUrl),
          rule_ids: applied.matched_rule_ids,
          rule_names: applied.matched_rule_names,
          injected_header_names: applied.injected_header_names,
        });
      }

      const response = await fetch(currentUrl.toString(), {
        method,
        headers: applied.headers,
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
        redirectCount += 1;

        logEvent(crossOrigin ? "warn" : "info", "curl.redirect", {
          request_id: requestId,
          mcp_ray: mcpRay,
          hop: redirectCount,
          status: response.status,
          from: safeTarget(currentUrl),
          to: safeTarget(nextUrl),
          cross_origin: crossOrigin,
          caller_headers_forwarded_unchanged: true,
          credential_headers_recomputed_per_hop: true,
          current_credential_rule_ids: applied.matched_rule_ids,
          ...headerSummary(callerHeaders),
        });

        const next = redirectRequest(response.status, method, body, callerHeaders);
        await response.body?.cancel();
        currentUrl = nextUrl;
        method = next.method;
        body = next.body;
        callerHeaders = next.headers;
        continue;
      }

      const boundedMaxBytes = Number.isFinite(maxBytes) && maxBytes > 0
        ? Math.floor(maxBytes)
        : DEFAULT_MAX_BYTES;
      const { bytes, truncated } = await readLimitedBody(response, boundedMaxBytes);
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
        credential_rules_applied: usedRuleIds.size,
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
        credential_rules_applied: usedRuleIds.size,
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
        credential_rules_applied: usedRuleIds.size,
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
      credential_rules_applied: usedRuleIds.size,
      error_name: safeError.name,
      error_message: safeError.message,
    });
    throw error;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

function createServer(selfHost: string, env: Env, mcpRay?: string): McpServer {
  const server = new McpServer(
    { name: "internet-curl", version: VERSION },
    {
      instructions:
        "Transparent HTTP/HTTPS curl for the public Internet. Forward caller method, headers, credentials, cookies, and body without application-level filtering or auth/write policy. Server-managed credential rules may add or override request headers based on destination domain/path. Only the public-network/SSRF boundary and Cloudflare runtime limitations apply.",
    },
  );

  server.registerTool(
    "curl",
    {
      title: "Internet Curl",
      description:
        "Transparent HTTP/HTTPS request tool. Caller-supplied method, headers, Authorization, X-Api-Key, Cookie, custom credentials, query string, and body are forwarded as supplied. In addition, server-managed credential rules can inject headers for matching domains/path prefixes, allowing authenticated API calls without putting secrets in the tool arguments. POST/PUT/PATCH/DELETE and arbitrary HTTP methods are not blocked by this MCP server. The server only validates the destination against the public-network/SSRF boundary and manually validates redirect targets.",
      inputSchema: z.object({
        url: z.string().url().describe("Public http:// or https:// URL, including any query string"),
        method: z
          .string()
          .optional()
          .describe("HTTP method forwarded to fetch as supplied; defaults to GET"),
        headers: z
          .record(z.string(), z.string())
          .optional()
          .describe("HTTP request headers forwarded without MCP-side filtering. Matching server credential rules may add/override headers per domain"),
        body: z
          .string()
          .optional()
          .describe("Raw UTF-8 request body forwarded exactly as supplied; takes precedence over convenience body fields"),
        body_base64: z
          .string()
          .optional()
          .describe("Convenience: base64-encoded binary request body, used when body is absent"),
        json: z
          .unknown()
          .optional()
          .describe("Convenience: JSON request body, used when body/body_base64 are absent"),
        form: z
          .record(z.string(), z.string())
          .optional()
          .describe("Convenience: URL-encoded form body, used when body/body_base64/json are absent"),
        timeout_ms: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe("Overall timeout in milliseconds. 0 disables the MCP-side timeout; default 30000"),
        max_bytes: z
          .number()
          .int()
          .positive()
          .optional()
          .describe("Maximum response bytes returned to the agent; default 2 MiB"),
        follow_redirects: z
          .boolean()
          .optional()
          .describe("Follow redirects after revalidating every target; default true"),
        max_redirects: z
          .number()
          .int()
          .nonnegative()
          .optional()
          .describe("Maximum manually followed redirects; default 10"),
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
        credential_rules_applied: z.number().int(),
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
    const adminResponse = await handleAdminRequest(request, env);
    if (adminResponse) return adminResponse;

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
