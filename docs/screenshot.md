# Screenshot tool

The `screenshot` MCP tool uses Cloudflare Browser Run Quick Actions to render a public webpage in headless Chrome and return the rendered image directly to the MCP client.

## Runtime configuration

Set these on the **Worker runtime**, not only in the build environment:

- `CLOUDFLARE_ACCOUNT_ID` — Cloudflare account ID (runtime variable)
- `CLOUDFLARE_API_TOKEN` — API token with **Browser Rendering / Browser Run - Edit** permission (runtime secret)

Example with Wrangler:

```bash
npx wrangler secret put CLOUDFLARE_API_TOKEN
```

Set `CLOUDFLARE_ACCOUNT_ID` in Worker **Settings → Variables and Secrets** as a normal runtime variable. With `keep_vars: true`, dashboard-managed runtime variables are preserved across Wrangler deploys.

For local development, place both values in `.dev.vars`:

```text
CLOUDFLARE_ACCOUNT_ID=0123456789abcdef0123456789abcdef
CLOUDFLARE_API_TOKEN=...
```

The Worker does not fail startup when these values are absent. Only `screenshot` calls fail with a configuration error, so the existing `curl` tool remains usable.

## Tool

Minimal call:

```json
{
  "url": "https://example.com"
}
```

Optional controls:

```json
{
  "url": "https://example.com/app",
  "full_page": true,
  "viewport_width": 1440,
  "viewport_height": 900,
  "device_scale_factor": 1.5,
  "wait_until": "networkidle2",
  "timeout_ms": 45000,
  "format": "jpeg",
  "quality": 85
}
```

You can capture a specific element with `selector`:

```json
{
  "url": "https://example.com/dashboard",
  "selector": "#main-dashboard"
}
```

The result contains MCP `image` content followed by a small JSON metadata text item with request ID, URL, MIME type, byte size, and elapsed time.

## Security behavior

- the initial URL uses the same target validation as `curl`: only HTTP(S), no localhost/internal suffixes, no IP literals, and no request back to the MCP Worker host
- the Cloudflare API token never appears in MCP output or logs
- screenshot image bytes are not logged
- screenshots are capped at 12 MiB before base64 encoding to keep MCP responses bounded
- managed credential headers are intentionally **not** injected into Browser Run in this version because Browser Run's `setExtraHTTPHeaders` applies page-wide and could forward an Authorization-style header to cross-origin subresources

Cloudflare Browser Run performs the actual browser navigation and rendering. The Worker calls the REST endpoint:

```text
POST https://api.cloudflare.com/client/v4/accounts/<account-id>/browser-rendering/screenshot
```
