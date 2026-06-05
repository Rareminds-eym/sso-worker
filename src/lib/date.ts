/**
 * Add `months` to a Date, clamping to the last day of the target month
 * when the source day overflows (e.g. Jan 31 + 1 month → Feb 28/29).
 */
/**
 * Convert a billing-cycle label ("monthly", "annual", "lifetime", etc.)
 * to its month count.  Returns 0 for "lifetime" (no expiry) and
 * defaults to 1 month for unrecognised labels.
 */
export function parseDurationMonths(duration: string): number {
  const lower = duration.toLowerCase();
  if (lower === "lifetime") return 0;
  if (lower.includes("annual") || lower.includes("year")) return 12;
  if (lower.includes("quarter")) return 3;
  if (lower.includes("month")) return 1;
  return 1;
}

export function addMonths(date: Date, months: number): Date {
  const result = new Date(date);
  const targetDay = result.getDate();
  result.setMonth(result.getMonth() + months);
  if (result.getDate() !== targetDay) {
    result.setDate(0);
  }
  return result;
}
