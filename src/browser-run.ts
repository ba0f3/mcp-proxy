import { McpServer } from "@modelcontextprotocol/server";
import * as z from "zod/v4";

export interface BrowserRunEnv {
  CLOUDFLARE_ACCOUNT_ID?: string;
  CLOUDFLARE_API_TOKEN?: string;
}

type LogFn = (
  level: "info" | "warn" | "error",
  event: string,
  fields?: Record<string, unknown>,
) => void;

type ScreenshotArgs = {
  url: string;
  full_page?: boolean;
  viewport_width?: number;
  viewport_height?: number;
  device_scale_factor?: number;
  selector?: string;
  wait_until?: "load" | "domcontentloaded" | "networkidle0" | "networkidle2";
  timeout_ms?: number;
  format?: "png" | "jpeg";
  quality?: number;
};

type ScreenshotContext = {
  selfHost: string;
  env: BrowserRunEnv;
  mcpRay?: string;
  validateTargetUrl: (rawUrl: string, selfHost: string) => URL;
  safeTarget: (url: URL) => string;
  logEvent: LogFn;
};

const DEFAULT_TIMEOUT_MS = 45_000;
const MAX_TIMEOUT_MS = 60_000;
const MAX_SCREENSHOT_BYTES = 12 * 1024 * 1024;

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, Math.min(i + chunkSize, bytes.length));
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary);
}

async function readLimited(
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

function configured(env: BrowserRunEnv): { accountId: string; apiToken: string } {
  const accountId = (env.CLOUDFLARE_ACCOUNT_ID ?? "").trim();
  const apiToken = (env.CLOUDFLARE_API_TOKEN ?? "").trim();

  if (!accountId || !apiToken) {
    throw new Error(
      "Screenshot tool is not configured: set CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_API_TOKEN as Worker runtime variables/secrets",
    );
  }

  return { accountId, apiToken };
}

function cloudflareError(status: number, bytes: Uint8Array): string {
  let detail = "";
  if (bytes.byteLength > 0) {
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    try {
      const parsed = JSON.parse(text) as {
        errors?: Array<{ message?: unknown }>;
        messages?: Array<{ message?: unknown }>;
      };
      const messages = [...(parsed.errors ?? []), ...(parsed.messages ?? [])]
        .map((entry) => (typeof entry.message === "string" ? entry.message : ""))
        .filter(Boolean);
      if (messages.length) detail = `: ${messages.join("; ").slice(0, 800)}`;
    } catch {
      // Do not reflect arbitrary upstream bodies into the tool response.
    }
  }
  return `Cloudflare Browser Run screenshot failed (HTTP ${status})${detail}`;
}

async function takeScreenshot(args: ScreenshotArgs, context: ScreenshotContext) {
  const target = context.validateTargetUrl(args.url, context.selfHost);
  const { accountId, apiToken } = configured(context.env);
  const requestId = crypto.randomUUID();
  const startedAt = Date.now();
  const timeoutMs = Math.min(args.timeout_ms ?? DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);
  const format = args.format ?? "png";

  if (args.quality !== undefined && format === "png") {
    throw new Error("quality is only valid when format is jpeg");
  }

  const screenshotOptions: Record<string, unknown> = {
    type: format,
  };
  if (args.full_page !== undefined) screenshotOptions.fullPage = args.full_page;
  if (args.quality !== undefined) screenshotOptions.quality = args.quality;

  const viewport: Record<string, unknown> = {};
  if (args.viewport_width !== undefined) viewport.width = args.viewport_width;
  if (args.viewport_height !== undefined) viewport.height = args.viewport_height;
  if (args.device_scale_factor !== undefined) {
    viewport.deviceScaleFactor = args.device_scale_factor;
  }

  const body: Record<string, unknown> = {
    url: target.toString(),
    screenshotOptions,
    gotoOptions: {
      waitUntil: args.wait_until ?? "networkidle2",
      timeout: timeoutMs,
    },
  };
  if (Object.keys(viewport).length > 0) body.viewport = viewport;
  if (args.selector) body.selector = args.selector;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort("Browser Run timeout"), timeoutMs + 10_000);

  context.logEvent("info", "screenshot.start", {
    request_id: requestId,
    mcp_ray: context.mcpRay,
    target: context.safeTarget(target),
    full_page: args.full_page ?? false,
    format,
    viewport_width: args.viewport_width,
    viewport_height: args.viewport_height,
    device_scale_factor: args.device_scale_factor,
    selector: Boolean(args.selector),
    wait_until: args.wait_until ?? "networkidle2",
    timeout_ms: timeoutMs,
  });

  try {
    const response = await fetch(
      `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/browser-rendering/screenshot`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${apiToken}`,
          "content-type": "application/json",
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      },
    );

    if (!response.ok) {
      const errorBody = await readLimited(response, 64 * 1024);
      throw new Error(cloudflareError(response.status, errorBody.bytes));
    }

    const contentLength = Number(response.headers.get("content-length") ?? "0");
    if (Number.isFinite(contentLength) && contentLength > MAX_SCREENSHOT_BYTES) {
      await response.body?.cancel();
      throw new Error(
        `Screenshot exceeds the ${Math.floor(MAX_SCREENSHOT_BYTES / 1024 / 1024)} MiB MCP response limit`,
      );
    }

    const { bytes, truncated } = await readLimited(response, MAX_SCREENSHOT_BYTES);
    if (truncated) {
      throw new Error(
        `Screenshot exceeds the ${Math.floor(MAX_SCREENSHOT_BYTES / 1024 / 1024)} MiB MCP response limit`,
      );
    }

    const contentTypeHeader = response.headers.get("content-type")?.split(";", 1)[0].trim();
    const mimeType = contentTypeHeader?.startsWith("image/")
      ? contentTypeHeader
      : format === "jpeg"
        ? "image/jpeg"
        : "image/png";
    const elapsedMs = Date.now() - startedAt;

    context.logEvent("info", "screenshot.complete", {
      request_id: requestId,
      mcp_ray: context.mcpRay,
      target: context.safeTarget(target),
      content_type: mimeType,
      response_bytes: bytes.byteLength,
      elapsed_ms: elapsedMs,
    });

    return {
      requestId,
      target,
      mimeType,
      bytes,
      elapsedMs,
    };
  } catch (error) {
    const elapsedMs = Date.now() - startedAt;
    const message = controller.signal.aborted
      ? `Browser Run screenshot timed out after ${timeoutMs} ms`
      : error instanceof Error
        ? error.message
        : String(error);

    context.logEvent("error", "screenshot.error", {
      request_id: requestId,
      mcp_ray: context.mcpRay,
      target: context.safeTarget(target),
      elapsed_ms: elapsedMs,
      error_message: message.slice(0, 500),
    });
    throw new Error(message);
  } finally {
    clearTimeout(timer);
  }
}

export function registerScreenshotTool(server: McpServer, context: ScreenshotContext): void {
  server.registerTool(
    "screenshot",
    {
      title: "Website Screenshot",
      description:
        "Render a public HTTP/HTTPS webpage with Cloudflare Browser Run and return a screenshot image. Useful for JavaScript-heavy sites, visual inspection, UI verification, and rendered page previews. Browser Run credentials stay server-side.",
      inputSchema: z.object({
        url: z.string().url().describe("Public http:// or https:// URL to render"),
        full_page: z
          .boolean()
          .optional()
          .describe("Capture the entire scrollable page instead of only the viewport"),
        viewport_width: z.number().int().min(320).max(3840).optional(),
        viewport_height: z.number().int().min(240).max(2160).optional(),
        device_scale_factor: z.number().min(0.5).max(3).optional(),
        selector: z
          .string()
          .min(1)
          .max(1000)
          .optional()
          .describe("Optional CSS selector to capture a specific element"),
        wait_until: z
          .enum(["load", "domcontentloaded", "networkidle0", "networkidle2"])
          .optional()
          .describe("Browser navigation readiness condition; default networkidle2"),
        timeout_ms: z
          .number()
          .int()
          .min(1000)
          .max(MAX_TIMEOUT_MS)
          .optional()
          .describe("Browser navigation timeout; default 45000, maximum 60000"),
        format: z.enum(["png", "jpeg"]).optional().describe("Image format; default png"),
        quality: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("JPEG quality 1-100; only valid with format=jpeg"),
      }),
      annotations: {
        readOnlyHint: true,
        openWorldHint: true,
      },
    },
    async (args) => {
      try {
        const result = await takeScreenshot(args, context);
        const metadata = {
          request_id: result.requestId,
          url: result.target.toString(),
          mime_type: result.mimeType,
          bytes: result.bytes.byteLength,
          elapsed_ms: result.elapsedMs,
        };

        return {
          content: [
            {
              type: "image",
              data: bytesToBase64(result.bytes),
              mimeType: result.mimeType,
            },
            {
              type: "text",
              text: JSON.stringify(metadata),
            },
          ],
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
}
