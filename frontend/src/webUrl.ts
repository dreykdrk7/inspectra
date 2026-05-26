const SENSITIVE_QUERY_PARAM_NAMES = new Set([
  "token",
  "access_token",
  "refresh_token",
  "id_token",
  "api_key",
  "apikey",
  "key",
  "secret",
  "client_secret",
  "password",
  "passwd",
  "pwd",
  "session",
  "sessionid",
  "sid",
  "auth",
  "authorization",
  "jwt",
  "bearer",
  "sig",
  "signature",
  "code",
  "state",
  "x-amz-signature",
  "x-amz-credential",
  "x-amz-security-token",
  "awsaccesskeyid"
]);

const SENSITIVE_QUERY_PARAM_FRAGMENTS = ["token", "secret", "password", "passwd", "session", "auth", "signature", "api_key", "apikey"];

export type WebQueryInspection = {
  hasQueryString: boolean;
  sensitiveParams: string[];
};

export function inspectWebUrlQuery(value: string): WebQueryInspection {
  try {
    const url = new URL(value);
    const names = Array.from(url.searchParams.keys());
    return {
      hasQueryString: url.search.length > 1,
      sensitiveParams: Array.from(new Set(names.filter(isSensitiveQueryParam))).sort((a, b) => a.localeCompare(b))
    };
  } catch {
    return { hasQueryString: value.includes("?"), sensitiveParams: [] };
  }
}

function isSensitiveQueryParam(name: string): boolean {
  const normalized = name.trim().toLowerCase();
  return SENSITIVE_QUERY_PARAM_NAMES.has(normalized) || SENSITIVE_QUERY_PARAM_FRAGMENTS.some((fragment) => normalized.includes(fragment));
}
