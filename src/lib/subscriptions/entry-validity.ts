import { integer, invalid, record } from './validation';

/** Null is an explicit unbounded end, never a missing or invalid timestamp. */
export function earlierSubscriptionEnd(left: number | null, right: number | null): number | null {
  return left === null ? right : right === null ? left : Math.min(left, right);
}

export function subscriptionEntryEnd(value: unknown, startsAt: number): number | null {
  integer(startsAt, 'entry.startsAt');
  const terms = record(value, 'entry', ['schemaVersion', 'validity', 'durationDays']);
  if (terms.schemaVersion !== 1) invalid('entry.schemaVersion', 'unsupported version');
  if (terms.validity === 'perpetual') {
    if (Object.hasOwn(terms, 'durationDays')) invalid('entry.durationDays', 'perpetual entry has no duration');
    return null;
  }
  if (terms.validity !== 'fixed_duration') invalid('entry.validity', 'published free validity required');
  const days = integer(terms.durationDays, 'entry.durationDays', 1);
  // Milliseconds per elapsed day is a unit conversion; the duration belongs to the publication.
  return integer(startsAt + days * 24 * 60 * 60 * 1000, 'entry.endsAt', startsAt + 1);
}
