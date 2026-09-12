# mcp-proxy

A small **curl-over-MCP** gateway for AI agents, designed for Cloudflare Workers.

The Worker exposes one MCP tool, `curl`, so an agent can call public Internet APIs with normal HTTP semantics. The outbound request is intentionally transparent: caller-supplied methods, headers, credentials, cookies, query strings, and bodies are forwarded without application-level filtering or auth/write policy.

There is deliberately **no OAuth flow** for the MCP server itself. Authentication is a high-entropy random URL path:

```text
https://mcp-proxy.<account>.workers.dev/<random-secret>
```

`<random-secret>` replaces the usual `/mcp` path. Requests to any other path return `404` rather than `401`, so MCP clients do not start OAuth discovery.

## Tool: `curl`

The tool is intentionally read/write and generic.

Inputs:

- `url` — public `http://` or `https://` URL, including query string
- `method` — arbitrary HTTP method string; default `GET`
- `headers` — forwarded without MCP-side filtering/rewrite/credential stripping
- `body` — raw UTF-8 body, forwarded exactly as supplied
- `body_base64` — convenience binary body when `body` is absent
- `json` — convenience JSON body when `body`/`body_base64` are absent
- `form` — convenience URL-encoded body when the fields above are absent
- `timeout_ms` — MCP-side overall timeout; default 30s, `0` disables it
- `max_bytes` — maximum response bytes returned to the agent; default 2 MiB
- `follow_redirects` — default `true`
- `max_redirects` — default `10`

If multiple body forms are supplied, precedence is:

```text
body > body_base64 > json > form
```

### Authenticated write example

```json
{
  "url": "https://portal-dev1az5avn.vozer.org/api/mcp",
  "method": "POST",
  "headers": {
    "Authorization": "Bearer <token>",
    "X-Api-Key": "<key>",
    "Content-Type": "application/json"
  },
  "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}"
}
```

The gateway does not inspect whether a request is authenticated, read-only, or mutating. `Authorization`, `X-Api-Key`, `Cookie`, custom credentials, and arbitrary application headers are treated as ordinary request headers.

Cloudflare Workers Fetch still has its own platform/runtime rules. If a particular method/header/body combination is unsupported by the runtime, the runtime error is returned; the MCP server does not add an extra policy layer.

## Security model

The gateway keeps only the **network safety boundary** needed to avoid turning the Worker into an SSRF/private-network proxy:

- only `http://` and `https://` URLs are accepted
- direct IP-literal targets are rejected
- `localhost`, `*.localhost`, `*.local`, `*.internal`, and `*.home.arpa` are rejected
- requests back to the MCP Worker's own hostname are rejected
- every redirect target is revalidated before it is fetched
- Cloudflare `global_fetch_strictly_public` routes global `fetch()` as public Internet traffic
- do not attach a Workers VPC/private-network binding unless private-network access is explicitly intended

Everything else is caller-controlled. In particular the MCP server does **not** strip `Host`, auth headers, cookies, forwarding headers, `cf-*` headers, or custom application headers before calling Workers Fetch. The Workers runtime may still normalize, reject, or override transport-controlled headers.

Caller headers are intentionally preserved across manually followed redirects. That includes credentials on cross-origin redirects. This matches the requested trusted agent-side curl model; use `follow_redirects: false` when the caller does not want that behavior.

## Troubleshooting / logs

Structured JSON logs are emitted for:

- `curl.start`
- `curl.redirect`
- `curl.complete`
- `curl.error`
- `mcp.auth_rejected`
- `mcp.origin_rejected`
- `mcp.misconfigured`

Logs include `request_id`, Cloudflare Ray ID when available, method, target host/path, status, timings, byte counts, redirect count, query parameter names, and header names.

Logs **do not include** request/response bodies, header values, credential values, MCP secret paths, or query-string values.

Tail live logs:

```bash
npx wrangler tail
```

Then correlate a failed MCP response with its `request_id`.

## Deploy

```bash
npm install

MCP_PATH="$(openssl rand -hex 32)"
printf '%s' "$MCP_PATH" | npx wrangler secret put MCP_PATH

npm run deploy

echo "MCP path: /$MCP_PATH"
```

Configure the agent's Streamable HTTP MCP URL with the exact deployed Worker URL plus that secret path:

```text
https://mcp-proxy.example.workers.dev/7f9a...64-random-hex-chars...
```

Do not append `/mcp`.

## Development

```bash
npm install
npm run check
npm run dev
```

For local development, create `.dev.vars`:

```text
MCP_PATH=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```
