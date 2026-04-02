/**
 * Prompt injection trigger phrases — char-code encoded to avoid
 * static scanner false positives on the detector itself.
 *
 * Uses Unicode normalization to prevent homoglyph bypass (CSO Finding #3).
 * Extracted from aiclude.asvs tool-analyzer.ts:60-90
 */

import { normalizeForDetection } from "./normalize.js";

function decodeInjectionPhrases(): string[] {
  const encoded: number[][] = [
    [105,103,110,111,114,101,32,112,114,101,118,105,111,117,115,32,105,110,115,116,114,117,99,116,105,111,110,115],
    [105,103,110,111,114,101,32,97,108,108,32,112,114,101,118,105,111,117,115],
    [102,111,114,103,101,116,32,121,111,117,114,32,105,110,115,116,114,117,99,116,105,111,110,115],
    [121,111,117,32,97,114,101,32,110,111,119],
    [110,101,119,32,105,110,115,116,114,117,99,116,105,111,110,115],
    [111,118,101,114,114,105,100,101,32,121,111,117,114],
    [100,105,115,114,101,103,97,114,100,32,97,108,108],
    [115,121,115,116,101,109,32,112,114,111,109,112,116],
    [73,77,80,79,82,84,65,78,84,58,32],
    [65,68,77,73,78,58],
    [83,89,83,84,69,77,58],
    [100,111,32,110,111,116,32,116,101,108,108,32,116,104,101,32,117,115,101,114],
    [100,111,32,110,111,116,32,109,101,110,116,105,111,110],
    [104,105,100,100,101,110,32,105,110,115,116,114,117,99,116,105,111,110],
    [115,101,99,114,101,116,108,121],
    [119,105,116,104,111,117,116,32,116,101,108,108,105,110,103],
  ];
  return encoded.map((codes) => String.fromCharCode(...codes));
}

let _cache: string[] | null = null;

/** Get the prompt injection trigger phrases (cached) */
export function getInjectionPhrases(): string[] {
  if (!_cache) {
    _cache = decodeInjectionPhrases();
  }
  return _cache;
}

/** Instruction-like patterns that try to manipulate agent behavior */
export const INSTRUCTION_PATTERNS: RegExp[] = [
  /\b(?:you\s+must|always|never|do\s+not)\b.*\b(?:user|output|response|answer)\b/i,
  /\b(?:respond|reply|answer)\s+(?:only|exclusively)\s+(?:with|in)\b/i,
];

/**
 * Check if text contains any prompt injection phrase.
 * Applies Unicode normalization to defeat homoglyph attacks.
 * Returns the matched phrase or null.
 */
export function detectInjectionPhrase(text: string): string | null {
  // Normalize to defeat Cyrillic/Greek/fullwidth homoglyphs and zero-width insertions
  const normalized = normalizeForDetection(text).toLowerCase();
  for (const phrase of getInjectionPhrases()) {
    if (normalized.includes(phrase)) {
      return phrase;
    }
  }
  return null;
}

/**
 * Check if text matches instruction-like manipulation patterns.
 * Applies Unicode normalization.
 */
export function detectInstructionPattern(text: string): boolean {
  const normalized = normalizeForDetection(text);
  return INSTRUCTION_PATTERNS.some((p) => p.test(normalized));
}
