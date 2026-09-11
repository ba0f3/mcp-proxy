# mcp-proxy

A small **curl-over-MCP** gateway for AI agents, designed for Cloudflare Workers.

The Worker exposes one MCP tool, `curl`, so an agent can make bounded HTTP/HTTPS requests to the public Internet without giving the agent a general-purpose network socket or access to private infrastructure.

There is deliberately **no OAuth flow**. Authentication is a high-entropy random URL path:

```text
https://mcp-proxy.<account>.workers.dev/<random-secret>
```

`<random-secret>` replaces the usual `/mcp` path. Requests to any other path return `404` rather than `401`, so MCP clients do not start OAuth discovery.

## Tool

### `curl`

Inputs:

- `url` — public `http://` or `https://` URL
- `method` — `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, or `OPTIONS`; default `GET`
- `headers` — optional request headers
- `body` — optional raw body, maximum 1 MiB
- `timeout_ms` — default 15 s, maximum 30 s
- `max_bytes` — default 512 KiB, maximum 2 MiB
- `follow_redirects` — default `true`
- `max_redirects` — default 5, maximum 10

Output contains:

```json
{
  "status": 200,
  "status_text": "OK",
  "final_url": "https://example.com/",
  "headers": {},
  "body": "...",
  "body_encoding": "utf-8",
  "truncated": false
}
```

Text-like responses are returned as UTF-8. Binary responses are returned as base64.

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

Configure the agent's **Streamable HTTP MCP URL** with the exact deployed Worker URL plus that secret path, for example:

```text
https://mcp-proxy.example.workers.dev/7f9a...64-random-hex-chars...
```

Do not append `/mcp`.

## Security model

This is intentionally safer than exposing an unrestricted proxy:

- Cloudflare `global_fetch_strictly_public` forces global `fetch()` through the public Internet path instead of allowing same-zone private-origin routing.
- Only HTTP and HTTPS are supported. No raw TCP, `CONNECT`, WebSocket tunneling, `file:`, or other URL schemes.
- IP-literal destinations are rejected; use a public DNS hostname.
- `localhost`, `*.localhost`, `*.local`, `*.internal`, and `*.home.arpa` are rejected.
- Requests back to the MCP Worker's own hostname are rejected to reduce accidental recursion.
- `Host`, hop-by-hop, proxy, forwarding, and Cloudflare-internal request headers are stripped.
- `Authorization`, `Cookie`, `X-API-Key`, and common token headers are stripped when a redirect crosses origins.
- Redirects are followed manually and every hop is revalidated.
- Request bodies, response bodies, redirects, and total request time are bounded.
- The MCP secret path is used only for inbound routing and is never inserted into outbound requests.

### Path-secret caveat

The URL path is effectively a bearer token. It is intentionally simple, but URLs may appear in client, proxy, or Cloudflare logs. Use at least 32 random bytes, restrict access to those logs, and rotate `MCP_PATH` if it leaks:

```bash
MCP_PATH="$(openssl rand -hex 32)"
printf '%s' "$MCP_PATH" | npx wrangler secret put MCP_PATH
npm run deploy
```

## Development

```bash
npm install
npm run typecheck
npm run dev
```

For local development, create `.dev.vars` (never commit it):

```text
MCP_PATH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Then point an MCP Streamable HTTP client at the local Worker URL using that path.
