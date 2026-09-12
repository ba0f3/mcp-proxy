import app from "./index";

interface Env {
  MCP_PATH: string;
  ADMIN_PATH: string;
}

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

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // MCP Streamable HTTP requires Origin validation. Non-browser/server-side
    // clients normally omit Origin; if present, only same-origin is accepted.
    if (!validOrigin(request)) {
      const requestUrl = new URL(request.url);
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
