import { useAuthStore } from "../store/auth";

let refreshing: Promise<string> | null = null;

async function refreshToken(): Promise<string> {
  const { refresh, accessToken } = useAuthStore.getState();
  if (!refresh) throw new Error("no refresh token");
  const res = await fetch("/api/auth/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: refresh }),
  });
  if (!res.ok) {
    useAuthStore.getState().logout();
    throw new Error("session expired");
  }
  const data = await res.json();
  useAuthStore.getState().setTokens(data.access_token, data.refresh_token);
  return data.access_token;
}

async function request<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const token = useAuthStore.getState().accessToken;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };
  if (token) headers.Authorization = `Bearer ${token}`;

  let res = await fetch(path, { ...options, headers });

  if (res.status === 401 && token && path !== "/api/auth/login") {
    refreshing = refreshing || refreshToken().catch((e) => {
      refreshing = null;
      throw e;
    });
    const newToken = await refreshing;
    refreshing = null;
    res = await fetch(path, { ...options, headers: { ...headers, Authorization: `Bearer ${newToken}` } });
  }

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch {
      /* ignore */
    }
    throw new Error(detail || `Request failed (${res.status})`);
  }
  return res.json();
}

export const api = {
  get: <T = any>(path: string) => request<T>(path),
  post: <T = any>(path: string, body?: any) => request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}) }),
  patch: <T = any>(path: string, body?: any) => request<T>(path, { method: "PATCH", body: JSON.stringify(body ?? {}) }),
  del: <T = any>(path: string) => request<T>(path, { method: "DELETE" }),
};
