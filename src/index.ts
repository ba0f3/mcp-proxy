import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

interface Env {
  MCP_PATH: string;
}

const VERSION = "0.1.0";
const DEFAULT_TIMEOUT_MS = 15_000;
const MAX_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_BYTES = 512 * 1024;
const HARD_MAX_BYTES = 2 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES = 1024 * 1024;
const DEFAULT_MAX_REDIRECTS = 5;

const ALLOWED_METHODS = new Set([
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
]);

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

const CROSS_ORIGIN_SENSITIVE_HEADERS = [
  "authorization",
  "cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
];

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

type CurlResult = {
  status: number;
  status_text: string;
  final_url: string;
  headers: Record<string, string>;
  body: string;
  body_encoding: "utf-8" | "base64";
  truncated: boolean;
};

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
    throw new Error("Credentials embedded in URLs are not allowed; use headers instead");
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, "");
  const ownHost = selfHost.toLowerCase().replace(/\.$/, "");

  if (!hostname) throw new Error("URL hostname is required");
  if (hostname === ownHost) throw new Error("Requests back to this MCP host are blocked");
  if (hostname === "localhost") throw new Error("localhost is blocked");
  if (isIpLiteral(hostname)) {
    throw new Error("IP-literal targets are blocked; use a public DNS hostname");
  }
  if (BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))) {
    throw new Error("Local/internal hostnames are blocked");
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

function stripCrossOriginSecrets(headers: Headers): Headers {
  const safe = new Headers(headers);
  for (const name of CROSS_ORIGIN_SENSITIVE_HEADERS) safe.delete(name);
  return safe;
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

function redirectMethod(
  status: number,
  method: string,
  body: string | undefined,
  headers: Headers,
): { method: string; body: string | undefined; headers: Headers } {
  if (status === 303 || ((status === 301 || status === 302) && method === "POST")) {
    const nextHeaders = new Headers(headers);
    nextHeaders.delete("content-type");
    return { method: "GET", body: undefined, headers: nextHeaders };
  }
  return { method, body, headers };
}

async function performCurl(
  args: {
    url: string;
    method?: string;
    headers?: Record<string, string>;
    body?: string;
    timeout_ms?: number;
    max_bytes?: number;
    follow_redirects?: boolean;
    max_redirects?: number;
  },
  selfHost: string,
): Promise<CurlResult> {
  let currentUrl = validateTargetUrl(args.url, selfHost);
  let method = (args.method ?? "GET").toUpperCase();
  let body = args.body;
  let headers = sanitizeHeaders(args.headers);

  if (!ALLOWED_METHODS.has(method)) {
    throw new Error(`Method ${method} is not allowed`);
  }
  if ((method === "GET" || method === "HEAD") && body !== undefined) {
    throw new Error(`${method} requests cannot include a body`);
  }
  if (body !== undefined && new TextEncoder().encode(body).byteLength > MAX_REQUEST_BODY_BYTES) {
    throw new Error(`Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes`);
  }

  const timeoutMs = Math.min(args.timeout_ms ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const maxBytes = Math.min(args.max_bytes ?? DEFAULT_MAX_BYTES, HARD_MAX_BYTES);
  const followRedirects = args.follow_redirects ?? true;
  const maxRedirects = Math.min(args.max_redirects ?? DEFAULT_MAX_REDIRECTS, 10);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("request timeout"), timeoutMs);

  try {
    for (let redirects = 0; ; redirects++) {
      const response = await fetch(currentUrl.toString(), {
        method,
        headers,
        body,
        redirect: "manual",
        signal: controller.signal,
      });

      const isRedirect = [301, 302, 303, 307, 308].includes(response.status);
      const location = response.headers.get("location");

      if (followRedirects && isRedirect && location) {
        if (redirects >= maxRedirects) {
          await response.body?.cancel();
          throw new Error(`Too many redirects (>${maxRedirects})`);
        }

        const nextUrl = validateTargetUrl(new URL(location, currentUrl).toString(), selfHost);
        let nextHeaders = headers;
        if (nextUrl.origin !== currentUrl.origin) {
          nextHeaders = stripCrossOriginSecrets(nextHeaders);
        }

        const next = redirectMethod(response.status, method, body, nextHeaders);
        await response.body?.cancel();
        currentUrl = nextUrl;
        method = next.method;
        body = next.body;
        headers = next.headers;
        continue;
      }

      const { bytes, truncated } = await readLimitedBody(response, maxBytes);
      const textual = isTextual(response.headers.get("content-type"));
      const result: CurlResult = {
        status: response.status,
        status_text: response.statusText,
        final_url: currentUrl.toString(),
        headers: headersToObject(response.headers),
        body: textual
          ? new TextDecoder("utf-8", { fatal: false }).decode(bytes)
          : bytesToBase64(bytes),
        body_encoding: textual ? "utf-8" : "base64",
        truncated,
      };

      return result;
    }
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`Request timed out after ${timeoutMs} ms`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

function createServer(selfHost: string): McpServer {
  const server = new McpServer(
    { name: "safe-curl", version: VERSION },
    {
      instructions:
        "Use curl to access public HTTP/HTTPS resources. IP literals, local/internal names, this MCP host, unsafe hop-by-hop headers, oversized bodies/responses, and excessive redirects are blocked. Sensitive credentials are stripped on cross-origin redirects.",
    },
  );

  server.registerTool(
    "curl",
    {
      title: "Safe Internet Curl",
      description:
        "Make an HTTP/HTTPS request to the public Internet. Similar to curl: supports standard methods, custom headers, request bodies, redirects, timeouts, and bounded responses. Does not expose OAuth and does not forward the MCP secret path.",
      inputSchema: z.object({
        url: z.string().url().describe("Public http:// or https:// URL"),
        method: z
          .enum(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])
          .optional()
          .describe("HTTP method; defaults to GET"),
        headers: z
          .record(z.string(), z.string())
          .optional()
          .describe("Request headers. Hop-by-hop, Host, forwarding, proxy, and Cloudflare headers are stripped"),
        body: z.string().optional().describe("Raw request body, up to 1 MiB"),
        timeout_ms: z
          .number()
          .int()
          .min(500)
          .max(MAX_TIMEOUT_MS)
          .optional()
          .describe("Overall request timeout in milliseconds; default 15000, max 30000"),
        max_bytes: z
          .number()
          .int()
          .min(1)
          .max(HARD_MAX_BYTES)
          .optional()
          .describe("Maximum response body bytes returned; default 524288, max 2097152"),
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
        status: z.number().int(),
        status_text: z.string(),
        final_url: z.string(),
        headers: z.record(z.string(), z.string()),
        body: z.string(),
        body_encoding: z.enum(["utf-8", "base64"]),
        truncated: z.boolean(),
      }),
      annotations: {
        readOnlyHint: false,
        openWorldHint: true,
      },
    },
    async (args) => {
      try {
        const result = await performCurl(args, selfHost);
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
    let expectedPath: string;
    try {
      expectedPath = normalizeSecretPath(env.MCP_PATH ?? "");
    } catch {
      return new Response("Worker is not configured", { status: 503 });
    }

    const requestUrl = new URL(request.url);

    // The path itself is the bearer secret. Return 404 rather than 401 so MCP
    // clients do not attempt OAuth discovery when the configured URL is wrong.
    if (requestUrl.pathname !== expectedPath) {
      return new Response("Not found", { status: 404 });
    }

    const handler = createMcpHandler(() => createServer(requestUrl.hostname));
    return handler.fetch(request);
  },
};
