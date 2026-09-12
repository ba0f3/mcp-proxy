export interface CredentialKV {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

export type CredentialMergeMode = "override" | "if_missing";

export type CredentialRule = {
  id: string;
  name: string;
  host_pattern: string;
  path_prefix: string;
  headers: Record<string, string>;
  secret_headers: string[];
  mode: CredentialMergeMode;
  priority: number;
  https_only: boolean;
  enabled: boolean;
  created_at: string;
  updated_at: string;
};

export type CredentialRuleInput = Partial<Omit<CredentialRule, "id" | "created_at" | "updated_at">> & {
  name?: unknown;
  host_pattern?: unknown;
  path_prefix?: unknown;
  headers?: unknown;
  secret_headers?: unknown;
  mode?: unknown;
  priority?: unknown;
  https_only?: unknown;
  enabled?: unknown;
};

export type AppliedCredentialRules = {
  headers: Headers;
  matched_rule_ids: string[];
  matched_rule_names: string[];
  injected_header_names: string[];
};

const STORE_KEY = "credential_rules_v1";
const MAX_RULES = 200;
const MAX_HEADERS_PER_RULE = 64;
const MAX_HEADER_VALUE_LENGTH = 16 * 1024;

const LEGACY_SECRET_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "cookie",
  "set-cookie",
  "x-api-key",
  "api-key",
  "x-auth-token",
  "x-access-token",
  "x-secret-key",
  "x-signature",
  "private-token",
  "x-gitlab-token",
  "x-goog-api-key",
  "x-amz-security-token",
  "cf-access-client-secret",
]);

function normalizeHostPattern(input: string): string {
  let value = input.trim().toLowerCase().replace(/\.$/, "");
  if (!value) throw new Error("Domain is required");
  if (value.includes("://") || value.includes("/") || value.includes(":")) {
    throw new Error("Domain must be a hostname such as api.example.com or *.example.com");
  }

  const wildcard = value.startsWith("*.");
  const hostname = wildcard ? value.slice(2) : value;
  if (!hostname || hostname.startsWith(".") || hostname.endsWith(".")) {
    throw new Error("Invalid domain pattern");
  }

  if (!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(hostname)) {
    throw new Error("Invalid domain pattern");
  }
  for (const label of hostname.split(".")) {
    if (!label || label.length > 63 || label.startsWith("-") || label.endsWith("-")) {
      throw new Error("Invalid domain pattern");
    }
  }

  value = wildcard ? `*.${hostname}` : hostname;
  return value;
}

function normalizePathPrefix(input: string): string {
  const value = input.trim() || "/";
  if (!value.startsWith("/")) throw new Error("Path prefix must start with /");
  if (value.includes("#") || value.includes("?")) {
    throw new Error("Path prefix must not contain query strings or fragments");
  }
  if (value.length > 2048) throw new Error("Path prefix is too long");
  return value.length > 1 ? value.replace(/\/+$/, "") : "/";
}

function normalizeHeaders(input: unknown): Record<string, string> {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Headers must be an object of name/value strings");
  }

  const entries = Object.entries(input as Record<string, unknown>);
  if (entries.length === 0) throw new Error("At least one header is required");
  if (entries.length > MAX_HEADERS_PER_RULE) {
    throw new Error(`A rule can contain at most ${MAX_HEADERS_PER_RULE} headers`);
  }

  const result: Record<string, string> = {};
  for (const [rawName, rawValue] of entries) {
    const name = rawName.trim();
    if (!name) throw new Error("Header names cannot be empty");
    if (typeof rawValue !== "string") throw new Error(`Header ${name} must be a string`);
    if (rawValue.length > MAX_HEADER_VALUE_LENGTH) {
      throw new Error(`Header ${name} is too large`);
    }

    const probe = new Headers();
    probe.set(name, rawValue);
    result[name] = rawValue;
  }

  return result;
}

function inferLegacySecretHeaders(headers: Record<string, string>): string[] {
  return Object.keys(headers)
    .map((name) => name.toLowerCase())
    .filter((name) => LEGACY_SECRET_HEADER_NAMES.has(name));
}

function normalizeSecretHeaders(
  input: unknown,
  headers: Record<string, string>,
  fallback?: string[],
): string[] {
  const headerNames = new Set(Object.keys(headers).map((name) => name.toLowerCase()));
  const source = input === undefined ? fallback ?? inferLegacySecretHeaders(headers) : input;
  if (!Array.isArray(source)) throw new Error("secret_headers must be an array");

  const result = new Set<string>();
  for (const rawName of source) {
    if (typeof rawName !== "string") throw new Error("secret_headers entries must be strings");
    const name = rawName.trim().toLowerCase();
    if (!name) continue;
    if (!headerNames.has(name)) throw new Error(`Secret header ${rawName} does not exist in headers`);
    result.add(name);
  }
  return [...result].sort();
}

export function isSecretHeader(rule: CredentialRule, name: string): boolean {
  return rule.secret_headers.includes(name.toLowerCase());
}

export function validateCredentialRuleInput(
  input: CredentialRuleInput,
  existing?: CredentialRule,
): CredentialRule {
  const now = new Date().toISOString();
  const name = String(input.name ?? existing?.name ?? "").trim();
  if (!name) throw new Error("Name is required");
  if (name.length > 120) throw new Error("Name is too long");

  const hostPattern = normalizeHostPattern(
    String(input.host_pattern ?? existing?.host_pattern ?? ""),
  );
  const pathPrefix = normalizePathPrefix(
    String(input.path_prefix ?? existing?.path_prefix ?? "/"),
  );
  const headers = normalizeHeaders(input.headers ?? existing?.headers ?? {});
  const secretHeaders = normalizeSecretHeaders(
    input.secret_headers,
    headers,
    existing?.secret_headers,
  );

  const rawMode = input.mode ?? existing?.mode ?? "override";
  if (rawMode !== "override" && rawMode !== "if_missing") {
    throw new Error("Mode must be override or if_missing");
  }

  const rawPriority = input.priority ?? existing?.priority ?? 100;
  const priority = Number(rawPriority);
  if (!Number.isInteger(priority) || priority < -10_000 || priority > 10_000) {
    throw new Error("Priority must be an integer between -10000 and 10000");
  }

  const httpsOnly = input.https_only ?? existing?.https_only ?? true;
  const enabled = input.enabled ?? existing?.enabled ?? true;
  if (typeof httpsOnly !== "boolean") throw new Error("https_only must be boolean");
  if (typeof enabled !== "boolean") throw new Error("enabled must be boolean");

  return {
    id: existing?.id ?? crypto.randomUUID(),
    name,
    host_pattern: hostPattern,
    path_prefix: pathPrefix,
    headers,
    secret_headers: secretHeaders,
    mode: rawMode,
    priority,
    https_only: httpsOnly,
    enabled,
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

function normalizeStoredRule(value: unknown): CredentialRule | null {
  if (!value || typeof value !== "object") return null;
  const rule = value as Partial<CredentialRule>;
  if (
    typeof rule.id !== "string" ||
    typeof rule.name !== "string" ||
    typeof rule.host_pattern !== "string" ||
    typeof rule.path_prefix !== "string" ||
    !rule.headers ||
    typeof rule.headers !== "object" ||
    Array.isArray(rule.headers) ||
    (rule.mode !== "override" && rule.mode !== "if_missing") ||
    typeof rule.priority !== "number" ||
    typeof rule.https_only !== "boolean" ||
    typeof rule.enabled !== "boolean"
  ) {
    return null;
  }

  try {
    const headers = normalizeHeaders(rule.headers);
    const secretHeaders = normalizeSecretHeaders(
      rule.secret_headers,
      headers,
      inferLegacySecretHeaders(headers),
    );
    return {
      id: rule.id,
      name: rule.name,
      host_pattern: rule.host_pattern,
      path_prefix: rule.path_prefix,
      headers,
      secret_headers: secretHeaders,
      mode: rule.mode,
      priority: rule.priority,
      https_only: rule.https_only,
      enabled: rule.enabled,
      created_at: typeof rule.created_at === "string" ? rule.created_at : new Date(0).toISOString(),
      updated_at: typeof rule.updated_at === "string" ? rule.updated_at : new Date(0).toISOString(),
    };
  } catch {
    return null;
  }
}

export async function loadCredentialRules(kv?: CredentialKV): Promise<CredentialRule[]> {
  if (!kv) return [];
  const raw = await kv.get(STORE_KEY);
  if (!raw) return [];

  try {
    const decoded = JSON.parse(raw);
    if (!Array.isArray(decoded)) return [];
    return decoded
      .map(normalizeStoredRule)
      .filter((rule): rule is CredentialRule => Boolean(rule))
      .slice(0, MAX_RULES);
  } catch {
    return [];
  }
}

export async function saveCredentialRules(
  kv: CredentialKV,
  rules: CredentialRule[],
): Promise<void> {
  if (rules.length > MAX_RULES) throw new Error(`Maximum ${MAX_RULES} credential rules`);
  await kv.put(STORE_KEY, JSON.stringify(rules));
}

function hostMatches(pattern: string, hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (!pattern.startsWith("*.")) return host === pattern;
  const base = pattern.slice(2);
  return host !== base && host.endsWith(`.${base}`);
}

function pathMatches(prefix: string, pathname: string): boolean {
  if (prefix === "/") return true;
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

export function ruleMatchesUrl(rule: CredentialRule, url: URL): boolean {
  if (!rule.enabled) return false;
  if (rule.https_only && url.protocol !== "https:") return false;
  return hostMatches(rule.host_pattern, url.hostname) && pathMatches(rule.path_prefix, url.pathname);
}

function sortedMatchingRules(rules: CredentialRule[], url: URL): CredentialRule[] {
  return rules
    .filter((rule) => ruleMatchesUrl(rule, url))
    .sort((a, b) => {
      if (a.priority !== b.priority) return a.priority - b.priority;

      const aWildcard = a.host_pattern.startsWith("*.") ? 0 : 1;
      const bWildcard = b.host_pattern.startsWith("*.") ? 0 : 1;
      if (aWildcard !== bWildcard) return aWildcard - bWildcard;
      if (a.host_pattern.length !== b.host_pattern.length) {
        return a.host_pattern.length - b.host_pattern.length;
      }
      if (a.path_prefix.length !== b.path_prefix.length) {
        return a.path_prefix.length - b.path_prefix.length;
      }
      return a.id.localeCompare(b.id);
    });
}

export function applyCredentialRules(
  callerHeaders: Headers,
  url: URL,
  rules: CredentialRule[],
): AppliedCredentialRules {
  const headers = new Headers(callerHeaders);
  const matched = sortedMatchingRules(rules, url);
  const injected = new Set<string>();

  for (const rule of matched) {
    for (const [name, value] of Object.entries(rule.headers)) {
      if (rule.mode === "if_missing" && headers.has(name)) continue;
      headers.set(name, value);
      injected.add(name.toLowerCase());
    }
  }

  return {
    headers,
    matched_rule_ids: matched.map((rule) => rule.id),
    matched_rule_names: matched.map((rule) => rule.name),
    injected_header_names: [...injected].sort(),
  };
}

export function previewCredentialMatch(url: URL, rules: CredentialRule[]) {
  const applied = applyCredentialRules(new Headers(), url, rules);
  return {
    matched_rule_ids: applied.matched_rule_ids,
    matched_rule_names: applied.matched_rule_names,
    injected_header_names: applied.injected_header_names,
  };
}
