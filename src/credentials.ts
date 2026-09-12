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

  // DNS hostname / punycode labels. Deliberately keep the rule language small:
  // exact hostnames and a single leading wildcard only.
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

    // Let the platform Headers implementation validate syntax. We deliberately
    // do not maintain an application-level forbidden header list.
    const probe = new Headers();
    probe.set(name, rawValue);
    result[name] = rawValue;
  }

  return result;
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
    mode: rawMode,
    priority,
    https_only: httpsOnly,
    enabled,
    created_at: existing?.created_at ?? now,
    updated_at: now,
  };
}

function isCredentialRule(value: unknown): value is CredentialRule {
  if (!value || typeof value !== "object") return false;
  const rule = value as Partial<CredentialRule>;
  return Boolean(
    typeof rule.id === "string" &&
      typeof rule.name === "string" &&
      typeof rule.host_pattern === "string" &&
      typeof rule.path_prefix === "string" &&
      rule.headers &&
      typeof rule.headers === "object" &&
      (rule.mode === "override" || rule.mode === "if_missing") &&
      typeof rule.priority === "number" &&
      typeof rule.https_only === "boolean" &&
      typeof rule.enabled === "boolean",
  );
}

export async function loadCredentialRules(kv?: CredentialKV): Promise<CredentialRule[]> {
  if (!kv) return [];
  const raw = await kv.get(STORE_KEY);
  if (!raw) return [];

  try {
    const decoded = JSON.parse(raw);
    if (!Array.isArray(decoded)) return [];
    return decoded.filter(isCredentialRule).slice(0, MAX_RULES);
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

      // Less specific rules apply first. More specific rules therefore win when
      // they use override mode at the same priority.
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
