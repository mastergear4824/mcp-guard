/**
 * Zero-width / invisible character detection for steganographic content hiding.
 *
 * Uses expanded coverage beyond the original 7 characters (CSO Finding #3).
 * Covers 30+ invisible Unicode characters including mathematical operators,
 * Hangul fillers, bidirectional overrides, and TAG characters.
 */

import { countInvisibleChars } from "./normalize.js";

/** Check if text contains hidden invisible characters (expanded coverage) */
export function containsZeroWidth(text: string): { found: boolean; count: number } {
  const count = countInvisibleChars(text);
  return { found: count > 0, count };
}
