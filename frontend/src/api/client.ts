export class ApiError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
  }
}

let csrfToken: string | null = null;

export function getCsrfToken(): string | null {
  return csrfToken;
}

function captureCsrfToken(token: string | null): void {
  if (token) {
    csrfToken = token;
  }
}

export interface ApiFetchOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  body?: unknown;
  rawBody?: Blob;
  headers?: Record<string, string>;
}

export async function apiFetch<T>(path: string, options: ApiFetchOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers: Record<string, string> = { ...options.headers };

  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (options.rawBody) headers["Content-Type"] = "application/octet-stream";
  if (method !== "GET" && csrfToken !== null) {
    headers["X-CSRF-Token"] = csrfToken;
  }

  const response = await fetch(path, {
    method,
    headers,
    body: options.rawBody ?? (options.body !== undefined ? JSON.stringify(options.body) : undefined),
    credentials: "same-origin"
  });

  captureCsrfToken(response.headers.get("X-CSRF-Token"));

  if (response.status === 204) {
    return undefined as T;
  }

  const payload = (await response.json().catch(() => null)) as
    | (T & { error?: { code?: string; message?: string } })
    | null;

  if (!response.ok) {
    throw new ApiError(
      response.status,
      payload?.error?.code ?? "unknown",
      payload?.error?.message ?? response.statusText
    );
  }

  return payload as T;
}
