import type { Env } from "../types";
import { DB_TIMEOUT_MS } from "./constants";

export interface DbClient {
  query<T = any>(path: string, options?: RequestInit): Promise<T[]>;
  queryOne<T = any>(path: string, options?: RequestInit): Promise<T | null>;
  mutate<T = any>(table: string, body: Record<string, unknown>, method?: string): Promise<T>;
  update(table: string, filter: Record<string, string>, body: Record<string, unknown>): Promise<void>;
  rpc<T = any>(fn: string, args?: Record<string, unknown>): Promise<T>;
}

/**
 * Lightweight Supabase REST (PostgREST) client.
 * Uses the service-role key — never expose to clients.
 * All calls have an AbortController timeout.
 */
export function db(env: Env): DbClient {
  const base = `${env.SUPABASE_URL}/rest/v1`;
  const rpcBase = `${env.SUPABASE_URL}/rest/v1/rpc`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    apikey: env.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  };

  function withTimeout(): { signal: AbortSignal; clear: () => void } {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), DB_TIMEOUT_MS);
    return { signal: controller.signal, clear: () => clearTimeout(timer) };
  }

  async function query<T = any>(path: string, options: RequestInit = {}): Promise<T[]> {
    const { signal, clear } = withTimeout();
    try {
      const res = await fetch(`${base}/${path}`, {
        ...options,
        signal,
        headers: { ...headers, ...(options.headers as Record<string, string>) },
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`DB query failed [${res.status}]: ${text}`);
      }
      // Handle empty responses (e.g. DELETE with Prefer: return=minimal)
      const text = await res.text();
      if (!text) return [] as unknown as T[];
      return JSON.parse(text) as T[];
    } finally {
      clear();
    }
  }

  async function queryOne<T = any>(path: string, options: RequestInit = {}): Promise<T | null> {
    const rows = await query<T>(path, options);
    return rows[0] ?? null;
  }

  async function mutate<T = any>(
    table: string,
    body: Record<string, unknown>,
    method = "POST",
  ): Promise<T> {
    const { signal, clear } = withTimeout();
    try {
      const res = await fetch(`${base}/${table}`, {
        method,
        signal,
        headers: { ...headers, Prefer: "return=representation" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`DB mutate failed [${res.status}]: ${text}`);
      }
      const rows = (await res.json()) as T[];
      return (rows as any)[0];
    } finally {
      clear();
    }
  }

  /**
   * PATCH with structured filter — prevents raw string injection.
   * filter: { "id": "eq.some-uuid", "user_id": "eq.some-uuid" }
   */
  async function update(
    table: string,
    filter: Record<string, string>,
    body: Record<string, unknown>,
  ): Promise<void> {
    const qs = Object.entries(filter)
      .map(([col, expr]) => `${encodeURIComponent(col)}=${encodeURIComponent(expr)}`)
      .join("&");

    const { signal, clear } = withTimeout();
    try {
      const res = await fetch(`${base}/${table}?${qs}`, {
        method: "PATCH",
        signal,
        headers: { ...headers, Prefer: "return=minimal" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`DB update failed [${res.status}]: ${text}`);
      }
    } finally {
      clear();
    }
  }

  /** Call a Supabase RPC (database function) */
  async function rpc<T = any>(fn: string, args: Record<string, unknown> = {}): Promise<T> {
    const { signal, clear } = withTimeout();
    try {
      const res = await fetch(`${rpcBase}/${fn}`, {
        method: "POST",
        signal,
        headers: { ...headers, Prefer: "return=representation" },
        body: JSON.stringify(args),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`DB rpc failed [${res.status}]: ${text}`);
      }
      return res.json() as Promise<T>;
    } finally {
      clear();
    }
  }

  return { query, queryOne, mutate, update, rpc };
}
