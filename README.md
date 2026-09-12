# mcp-proxy

A small **curl-over-MCP** gateway for AI agents, designed for Cloudflare Workers.

The Worker exposes one MCP tool, `curl`, so an agent can call public Internet APIs with normal HTTP semantics: reads, authenticated writes, custom headers, redirects, JSON/form/raw/binary bodies, and bounded responses.

There is deliberately **no OAuth flow** for the MCP server itself. Authentication is a high-entropy random URL path:

```text
https://mcp-proxy.<account>.workers.dev/<random-secret>
```

`<random-secret>` replaces the usual `/mcp` path. Requests to any other path return `404` rather than `401`, so MCP clients do not start OAuth discovery.

## Tool: `curl`

The tool is intentionally **read/write**. `POST`, `PUT`, `PATCH`, and `DELETE` are allowed, and application credentials supplied by the agent are forwarded.

Inputs:

- `url` — public `http://` or `https://` URL
- `method` — `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS`; default `GET`
- `headers` — arbitrary application headers; `Authorization`, `X-Api-Key`, `Cookie`, etc. are allowed
- `body` — raw UTF-8 body
- `body_base64` — base64 binary body
- `json` — JSON value; automatically serialized and defaults `Content-Type: application/json`
- `form` — URL-encoded form object
- `timeout_ms` — default 20 s, maximum 60 s
- `max_bytes` — default 1 MiB response, maximum 4 MiB
- `follow_redirects` — default `true`
- `max_redirects` — default 5, maximum 10

Only one of `body`, `body_base64`, `json`, or `form` may be supplied. Request bodies are capped at 8 MiB.

Example authenticated write:

```json
{
  "url": "https://portal.example.com/api/orders:create",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer <token>",
    "X-Api-Key": "<key>"
  },
  "json": {
    "name": "example",
    "enabled": true
  }
}
```

This is suitable for APIs such as NocoBase: the gateway does not downgrade the tool to read-only and does not remove `Authorization` or `X-Api-Key` headers.

Output contains a `request_id` that can be correlated with Worker logs:

```json
{
  "request_id": "0dd64f9a-...",
  "status": 200,
  "status_text": "OK",
  "final_url": "https://example.com/",
  "headers": {},
  "body": "...",
  "body_encoding": "utf-8",
  "request_bytes": 123,
  "response_bytes": 456,
  "elapsed_ms": 92,
  "redirects": 0,
  "truncated": false
}
```

Text-like responses are returned as UTF-8. Binary responses are returned as base64.

## Security model

The gateway is designed to give an agent normal HTTP power while keeping the network boundary public-only.

- Cloudflare `global_fetch_strictly_public` forces global `fetch()` to route as public Internet traffic rather than directly to a same-zone private origin.
- Only HTTP and HTTPS are supported. No raw TCP, `CONNECT`, WebSocket tunneling, `file:`, or other URL schemes.
- Direct IP-literal targets are rejected. Cloudflare Workers global `fetch()` does not support direct IP URL subrequests anyway; requiring DNS names also gives a deterministic SSRF boundary.
- `localhost`, `*.localhost`, `*.local`, `*.internal`, and `*.home.arpa` are rejected.
- Requests back to the MCP Worker's own hostname are rejected.
- Every redirect target is revalidated before it is fetched.
- `Host`, hop-by-hop, proxy, forwarding, and Cloudflare-internal spoofing headers are stripped. Application/authentication headers are not stripped.
- Caller credentials are deliberately preserved across manually followed redirects so the gateway behaves as a trusted agent-side curl. Cross-origin credential forwarding is logged as a warning without logging credential values.
- Request body, response body, redirect count, and total request time are bounded to prevent accidental resource abuse.
- The MCP secret path is never inserted into outbound requests or logs.

The important SSRF/DNS-rebinding control is that the Worker has no VPC/private-network binding and outbound global fetch uses `global_fetch_strictly_public`. Do not add a Workers VPC binding to this gateway unless you intentionally want agents to reach private infrastructure.

## Troubleshooting / logs

Structured JSON logs are emitted for:

- `curl.start`
- `curl.redirect`
- `curl.complete`
- `curl.error`
- `mcp.auth_rejected`
- `mcp.origin_rejected`
- `mcp.misconfigured`

Logs include `request_id`, Cloudflare Ray ID when available, method, target host/path, status, timings, byte counts, redirect count, and booleans indicating whether common auth headers were present.

Logs **do not include** request/response bodies, auth header values, MCP secret paths, or query-string values. Query parameter names may be logged for debugging.

Tail live logs:

```bash
npx wrangler tail
```

Then correlate a failed MCP response with its `request_id`.

## Deploy

Requirements: Node.js/npm and a Cloudflare account authenticated with Wrangler.

```bash
npm install

# Generate and keep this value; it is the MCP endpoint credential.
MCP_PATH="$(openssl rand -hex 32)"
printf '%s' "$MCP_PATH" | npx wrangler secret put MCP_PATH

npm run deploy

echo "MCP path: /$MCP_PATH"
```

`wrangler.jsonc` declares `MCP_PATH` as a required runtime secret, so deployment fails when it is missing.

Configure the agent's **Streamable HTTP MCP URL** with the exact deployed Worker URL plus that secret path:

```text
https://mcp-proxy.example.workers.dev/7f9a...64-random-hex-chars...
```

Do not append `/mcp`.

### Path-secret caveat

The URL path is effectively a bearer token. URLs can appear in client/proxy logs, so use at least 32 random bytes, protect those logs, and rotate `MCP_PATH` if it leaks:

```bash
MCP_PATH="$(openssl rand -hex 32)"
printf '%s' "$MCP_PATH" | npx wrangler secret put MCP_PATH
```

## Development

```bash
npm install
npm run check
npm run dev
```

For local development, create `.dev.vars` (never commit it):

```text
MCP_PATH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Then point an MCP Streamable HTTP client at the local Worker URL using that path.
