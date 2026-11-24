import type { Env } from "../types";
import { DB_TIMEOUT_MS } from "./constants";

export interface DbClient {
  query<T = unknown>(path: string, options?: RequestInit, responseShape?: 'json-array'): Promise<T[]>;
  queryOne<T = unknown>(path: string, options?: RequestInit): Promise<T | null>;
  mutate<T = unknown>(table: string, body: Record<string, unknown>, method?: string): Promise<T>;
  update(table: string, filter: Record<string, string>, body: Record<string, unknown>): Promise<void>;
  rpc<T = unknown>(fn: string, args?: Record<string, unknown>): Promise<T>;
  rpc(fn: string, args: Record<string, unknown>, responseShape: 'void'): Promise<void>;
  bulkInsert<T = unknown>(table: string, data: unknown[]): Promise<T[]>;
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

  async function query<T = unknown>(path: string, options: RequestInit = {}, responseShape?: 'json-array'): Promise<T[]> {
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
      if (responseShape === 'json-array') {
        let parsed: unknown;
        try { parsed = JSON.parse(text); }
        catch { throw new Error('DB query expected a JSON array'); }
        if (!Array.isArray(parsed)) throw new Error('DB query expected a JSON array');
        return parsed as T[];
      }
      if (!text) return [] as unknown as T[];
      return JSON.parse(text) as T[];
    } finally {
      clear();
    }
  }

  async function queryOne<T = unknown>(path: string, options: RequestInit = {}): Promise<T | null> {
    const rows = await query<T>(path, options);
    return rows[0] ?? null;
  }

  async function mutate<T = unknown>(
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
      const json = await res.json();
      // ponytail: Runtime guard against unexpected API shape (PostgREST returns array or single object)
      if (json === null || json === undefined) {
        throw new Error(`DB mutate returned null/undefined for table ${table}`);
      }
      const rows = Array.isArray(json) ? json : [json];
      if (rows.length === 0) {
        throw new Error(`DB mutate returned empty result for table ${table}`);
      }
      const row = rows[0];
      if (typeof row !== 'object' || row === null) {
        throw new Error(
          `DB mutate returned unexpected type for ${table}: expected object, got ${typeof row}`,
        );
      }
      return row as T;
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
  async function rpc<T = unknown>(fn: string, args?: Record<string, unknown>): Promise<T>;
  async function rpc(fn: string, args: Record<string, unknown>, responseShape: 'void'): Promise<void>;
  async function rpc<T = unknown>(fn: string, args: Record<string, unknown> = {}, responseShape?: 'void'): Promise<T | void> {
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
      if (responseShape === 'void') {
        // PostgREST returns 204 for SQL functions declared RETURNS void.
        // JSON-returning functions still require their normal response body.
        if (res.status !== 204) throw new Error('DB rpc expected a void response');
        return;
      }
      return await res.json() as T;
    } finally {
      clear();
    }
  }

  /**
   * Bulk insert multiple records
   * ponytail: Extracted to eliminate duplicate fetch+headers boilerplate
   */
  async function bulkInsert<T = unknown>(table: string, data: unknown[]): Promise<T[]> {
    if (data.length === 0) return [];
    
    const { signal, clear } = withTimeout();
    try {
      const res = await fetch(`${base}/${table}`, {
        method: "POST",
        signal,
        headers: { ...headers, Prefer: "return=representation" },
        body: JSON.stringify(data),
      });
      if (!res.ok) {
        const text = await res.text();
        throw new Error(`DB bulk insert failed [${res.status}]: ${text}`);
      }
      return (await res.json()) as T[];
    } finally {
      clear();
    }
  }

  return { query, queryOne, mutate, update, rpc, bulkInsert };
}
