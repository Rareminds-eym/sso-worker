import { isValidUUID } from '../validate';

export class CatalogValidationError extends Error {
  constructor(readonly path: string, reason: string) {
    super(`${path}: ${reason}`);
    this.name = 'CatalogValidationError';
  }
}

export function invalid(path: string, reason: string): never {
  throw new CatalogValidationError(path, reason);
}

export function record(value: unknown, path: string, keys: readonly string[]): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype) invalid(path, 'expected a plain object');
  const result = value as Record<string, unknown>;
  if (Object.keys(result).some(key => !keys.includes(key))) invalid(path, 'unsupported field');
  return result;
}

export function text(value: unknown, path: string): string {
  if (typeof value !== 'string' || !value.trim() || value !== value.trim()) invalid(path, 'expected non-empty trimmed text');
  return value;
}

/**
 * Canonical database identifier: any 8-4-4-4-12 hex value, as PostgreSQL `uuid` stores it. Use only for
 * identities issued by the identity owner, e.g. the seeded platform organization
 * `00000000-0000-0000-0000-000000000001` that individual learners belong to, which is not RFC 4122 versioned.
 */
export function databaseUuid(value: unknown, path: string): string {
  const result = text(value, path);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(result)) invalid(path, 'expected UUID');
  return result.toLowerCase();
}

export function uuid(value: unknown, path: string): string {
  const result = text(value, path);
  if (!isValidUUID(result)) invalid(path, 'expected UUID');
  return result.toLowerCase();
}

export function integer(value: unknown, path: string, minimum = 0): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < minimum) invalid(path, 'expected a safe integer within range');
  return value;
}

export function choice<T extends string>(value: unknown, path: string, values: readonly T[]): T {
  if (typeof value !== 'string' || !values.includes(value as T)) invalid(path, 'unsupported value');
  return value as T;
}

export function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) invalid(path, 'expected an array');
  // Array.map skips holes. Materialize them so every configured element is validated.
  return Array.from(value);
}

