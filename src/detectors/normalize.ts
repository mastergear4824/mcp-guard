/**
 * Unicode normalization for security detection — prevents homoglyph,
 * zero-width insertion, and SQL comment bypasses (CSO Finding #3, #6).
 *
 * Applied as preprocessing before ALL detection functions.
 */

/**
 * Unicode confusable mappings (TR39 skeleton subset).
 * Maps common homoglyphs to their ASCII equivalents.
 */
const CONFUSABLE_MAP: Record<string, string> = {
  // Cyrillic → Latin
  "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
  "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
  "\u0458": "j", "\u04BB": "h", "\u0455": "s", "\u0491": "g",
  "\u0454": "e", "\u0442": "t", "\u043C": "m", "\u043D": "n",
  "\u0432": "b", "\u043A": "k", "\u0434": "d", "\u0437": "3",
  // Greek → Latin
  "\u03B1": "a", "\u03B5": "e", "\u03BF": "o", "\u03C1": "p",
  "\u03B9": "i", "\u03BA": "k", "\u03BD": "v", "\u03C4": "t",
  // Fullwidth → ASCII
  "\uFF21": "A", "\uFF22": "B", "\uFF23": "C", "\uFF24": "D",
  "\uFF25": "E", "\uFF26": "F", "\uFF27": "G", "\uFF28": "H",
  "\uFF29": "I", "\uFF2A": "J", "\uFF2B": "K", "\uFF2C": "L",
  "\uFF2D": "M", "\uFF2E": "N", "\uFF2F": "O", "\uFF30": "P",
  "\uFF31": "Q", "\uFF32": "R", "\uFF33": "S", "\uFF34": "T",
  "\uFF35": "U", "\uFF36": "V", "\uFF37": "W", "\uFF38": "X",
  "\uFF39": "Y", "\uFF3A": "Z",
  "\uFF41": "a", "\uFF42": "b", "\uFF43": "c", "\uFF44": "d",
  "\uFF45": "e", "\uFF46": "f", "\uFF47": "g", "\uFF48": "h",
  "\uFF49": "i", "\uFF4A": "j", "\uFF4B": "k", "\uFF4C": "l",
  "\uFF4D": "m", "\uFF4E": "n", "\uFF4F": "o", "\uFF50": "p",
  "\uFF51": "q", "\uFF52": "r", "\uFF53": "s", "\uFF54": "t",
  "\uFF55": "u", "\uFF56": "v", "\uFF57": "w", "\uFF58": "x",
  "\uFF59": "y", "\uFF5A": "z",
  // Common special chars
  "\uFF10": "0", "\uFF11": "1", "\uFF12": "2", "\uFF13": "3",
  "\uFF14": "4", "\uFF15": "5", "\uFF16": "6", "\uFF17": "7",
  "\uFF18": "8", "\uFF19": "9",
  "\u2018": "'", "\u2019": "'", "\u201C": "\"", "\u201D": "\"",
  "\uFF07": "'", "\uFF02": "\"",
};

/**
 * Regex matching ALL invisible/format Unicode characters, not just the 7
 * originally listed. Covers Unicode categories Cf (format), plus specific
 * zero-width and invisible characters.
 */
const INVISIBLE_CHARS_REGEX = new RegExp(
  "[" +
  // Original 7
  "\\u200B\\u200C\\u200D\\uFEFF\\u00AD\\u2060\\u180E" +
  // Mathematical invisible operators
  "\\u2061\\u2062\\u2063\\u2064" +
  // Combining grapheme joiner
  "\\u034F" +
  // Khmer invisible vowels
  "\\u17B4\\u17B5" +
  // Hangul fillers
  "\\u115F\\u1160\\u3164" +
  // Bidirectional overrides
  "\\u200E\\u200F\\u202A-\\u202E\\u2066-\\u2069" +
  // Variation selectors
  "\\uFE00-\\uFE0F" +
  // Interlinear annotation
  "\\uFFF9-\\uFFFB" +
  // Soft hyphen, line/paragraph separators
  "\\u2028\\u2029" +
  "]",
  "g",
);

/**
 * TAG characters (U+E0001-U+E007F) regex for supplementary plane detection.
 * These are used in tag injection attacks.
 */
const TAG_CHARS_REGEX = /[\u{E0001}-\u{E007F}]/gu;

/**
 * Normalize text for security detection:
 * 1. NFKD decomposition (normalizes fullwidth, compatibility chars)
 * 2. Strip all invisible/format characters
 * 3. Map remaining confusable characters to ASCII
 */
export function normalizeForDetection(text: string): string {
  // Step 1: NFKD normalization
  let result = text.normalize("NFKD");

  // Step 2: Strip invisible characters and TAG characters
  result = result.replace(INVISIBLE_CHARS_REGEX, "");
  result = result.replace(TAG_CHARS_REGEX, "");

  // Step 3: Strip combining marks (category Mn) left after NFKD
  // This handles combining accents added to evade detection
  result = result.replace(/[\u0300-\u036F\u0483-\u0489\u0591-\u05BD\u05BF\u05C1\u05C2\u05C4\u05C5\u05C7\u0610-\u061A\u064B-\u065F\u0670\u06D6-\u06DC\u06DF-\u06E4\u06E7\u06E8\u06EA-\u06ED]/g, "");

  // Step 4: Map confusable characters
  let mapped = "";
  for (const char of result) {
    mapped += CONFUSABLE_MAP[char] ?? char;
  }

  return mapped;
}

/**
 * Normalize for SQL detection: additionally strips SQL comments.
 */
export function normalizeForSql(text: string): string {
  let result = normalizeForDetection(text);

  // Strip SQL block comments
  result = result.replace(/\/\*[\s\S]*?\*\//g, " ");

  // Strip SQL line comments (-- and #) but only when followed by space or end
  result = result.replace(/--\s.*$/gm, "");
  result = result.replace(/#\s.*$/gm, "");

  // Collapse multiple spaces
  result = result.replace(/\s+/g, " ");

  return result;
}

/**
 * Check if text contains ANY invisible/zero-width character (expanded coverage).
 * Returns the count of invisible characters found.
 */
export function countInvisibleChars(text: string): number {
  const matches1 = text.match(INVISIBLE_CHARS_REGEX);
  const matches2 = text.match(TAG_CHARS_REGEX);
  return (matches1?.length ?? 0) + (matches2?.length ?? 0);
}
