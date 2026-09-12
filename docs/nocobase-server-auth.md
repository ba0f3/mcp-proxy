# NocoBase server-side authentication

The gateway injects NocoBase authentication server-side for exactly:

```text
https://portal-dev1az5avn.vozer.org/api/mcp
```

and subpaths below `/api/mcp/`.

The MCP caller should **not** send `Authorization`, `X-Api-Key`, or the NocoBase token for this endpoint. The Worker reads the `NC_API_KEY` runtime secret and sets:

```http
Authorization: Bearer <NC_API_KEY>
```

The caller-provided `Authorization` header is overwritten for this allowlisted endpoint. The server-side credential is derived independently for each outbound hop, so it is never forwarded if a redirect leaves the allowlisted HTTPS host/path.

## Configure

```bash
printf '%s' "$NC_API_KEY" | npx wrangler secret put NC_API_KEY
npm run deploy
```

`wrangler.jsonc` marks `NC_API_KEY` as a required runtime secret.

## Troubleshooting

Tail Worker logs:

```bash
npx wrangler tail
```

For an injected request you should see `curl.auth_injected`, and the tool result contains:

```json
{
  "server_auth_injected": true
}
```

The token value is never logged or returned.
