// Спільний клієнт для звернень до бекенду: підставляє Authorization: Bearer
// <token> з localStorage, щоб не дублювати цю логіку в кожному fetch.

const API_BASE = "http://127.0.0.1:8000";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return localStorage.getItem("token");
}

export function clearAuth() {
  if (typeof window !== "undefined") localStorage.clear();
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const token = getToken();
  const headers = new Headers(options.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  // FormData (напр. /api/scan/upload) — Content-Type з межею (boundary)
  // виставляє сам браузер; вручну ставити не можна.
  if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  return fetch(`${API_BASE}${path}`, { ...options, headers });
}
