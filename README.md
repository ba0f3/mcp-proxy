# mcp-proxy

A small **curl-over-MCP** gateway for AI agents, designed for Cloudflare Workers.

The Worker exposes one MCP tool, `curl`, so an agent can call public Internet APIs with normal HTTP semantics. The outbound request is intentionally transparent: caller-supplied methods, headers, credentials, cookies, query strings, and bodies are forwarded without application-level filtering or auth/write policy.

It also supports **server-managed credential rules**. A rule matches a destination domain/path and injects configured headers immediately before the outbound request. This lets agents call authenticated APIs without putting API keys/tokens in the MCP tool arguments.

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

Cloudflare Workers Fetch still has its own platform/runtime rules. If a particular method/header/body combination is unsupported by the runtime, the runtime error is returned; the MCP server does not add an extra policy layer.

## Credential rules

Credential rules are stored in the `CREDENTIALS` Workers KV binding and managed through the built-in admin UI.

Each rule contains:

- `domain` — exact hostname such as `portal.example.com`, or one leading wildcard such as `*.example.com`
- `path prefix` — optional path scope such as `/api`; `/` matches the whole domain
- `headers` — any header/value pairs, for example `Authorization`, `X-Api-Key`, `Cookie`, or vendor-specific headers
- `mode`
  - `override` — configured value replaces a same-name caller header
  - `if_missing` — configured value is only added when the request does not already contain the header
- `priority` — lower-priority/general rules apply first; higher-priority/more-specific rules can override them
- `HTTPS only` — enabled by default
- `enabled` — temporarily disable a rule without deleting it

Example:

```text
Domain:       portal-dev1az5avn.vozer.org
Path prefix:  /api
Mode:         override
HTTPS only:   yes
Headers:
  Authorization: Bearer <NC_API_KEY>
```

The agent can then call:

```json
{
  "url": "https://portal-dev1az5avn.vozer.org/api/mcp",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{}}"
}
```

The Worker adds the matching credential headers server-side before `fetch()`.

Rules are evaluated **per outbound hop**. Injected credentials are never copied into the caller header set, so a credential for one domain does not accidentally follow a redirect to another domain. If the redirect target has its own matching rule, that rule is applied instead. Caller-supplied headers retain the normal transparent redirect behavior.

### Admin UI

Set one additional random secret to enable the credential UI:

```bash
ADMIN_PATH="$(openssl rand -hex 32)"
printf '%s' "$ADMIN_PATH" | npx wrangler secret put ADMIN_PATH
npm run deploy
```

Open the bootstrap URL once:

```text
https://mcp-proxy.example.workers.dev/admin/<ADMIN_PATH>
```

The Worker stores the secret in an `HttpOnly; Secure; SameSite=Strict` admin cookie and redirects to:

```text
https://mcp-proxy.example.workers.dev/admin
```

The UI supports create/edit/delete, header rows, wildcard domains, path prefixes, priority/mode, enable/disable, and a URL matcher test.

`ADMIN_PATH` is intentionally **not** declared as a required deploy secret. If it is absent, the normal MCP proxy keeps working and `/admin` returns `503`.

The credential rules are stored as application data in Workers KV. The MCP tool never returns stored header values and logs never include credential values.

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

Managed credential rules are separate from caller headers. They are applied immediately before each outbound fetch and recalculated after every redirect.

## Troubleshooting / logs

Structured JSON logs are emitted for:

- `curl.start`
- `curl.credentials_applied`
- `curl.redirect`
- `curl.complete`
- `curl.error`
- `mcp.auth_rejected`
- `mcp.origin_rejected`
- `mcp.misconfigured`

Logs include `request_id`, Cloudflare Ray ID when available, method, target host/path, status, timings, byte counts, redirect count, query parameter names, header names, and matched credential rule IDs/names.

Logs **do not include** request/response bodies, header values, credential values, MCP secret paths, admin secret paths, or query-string values.

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

# Optional but required for the credential admin UI.
ADMIN_PATH="$(openssl rand -hex 32)"
printf '%s' "$ADMIN_PATH" | npx wrangler secret put ADMIN_PATH

npm run deploy

echo "MCP path: /$MCP_PATH"
echo "Admin bootstrap: /admin/$ADMIN_PATH"
```

`wrangler.jsonc` declares a `CREDENTIALS` KV binding without an account-specific namespace ID. Modern Wrangler automatically provisions and links the KV namespace on deploy; when deploying through a dashboard/Git integration, the generated resource ID remains visible in the Cloudflare dashboard rather than being written back to the repository.

Configure the agent's Streamable HTTP MCP URL with the exact deployed Worker URL plus the MCP secret path:

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
ADMIN_PATH=abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789
```
