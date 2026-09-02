/**
 * Universal Array Normalizer.
 * Safely extracts an array from direct array payloads or wrapped API response objects
 * (e.g. { data: [...] }, { items: [...] }, { investigations: [...] }, { threats: [...] }, etc.),
 * preventing runtime `TypeError: *.map is not a function` crashes.
 */
export function ensureArray<T = any>(payload: any, preferredKeys: string[] = []): T[] {
  if (Array.isArray(payload)) return payload;
  if (!payload || typeof payload !== 'object') return [];
  for (const key of [
    ...preferredKeys,
    'items',
    'data',
    'results',
    'investigations',
    'threats',
    'cases',
    'reports',
  ]) {
    if (Array.isArray(payload[key])) return payload[key];
  }
  return [];
}
