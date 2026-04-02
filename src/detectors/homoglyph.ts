/**
 * Homoglyph Detection — detects visually similar Unicode characters
 * that can be used to disguise tool names or inject hidden content.
 *
 * Covers Cyrillic and Greek characters that look identical to ASCII letters.
 */

/** Map of homoglyph characters to their ASCII equivalents */
const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic → Latin
  "\u0430": "a", // а → a
  "\u0435": "e", // е → e
  "\u043E": "o", // о → o
  "\u0441": "c", // с → c
  "\u0440": "p", // р → p
  "\u0443": "y", // у → y
  "\u0445": "x", // х → x
  "\u043A": "k", // к → k
  "\u043C": "m", // м → m (lowercase)
  "\u0456": "i", // і → i (Ukrainian i)
  "\u0458": "j", // ј → j (Serbian je)
  "\u04BB": "h", // һ → h
  "\u0455": "s", // ѕ → s
  "\u0471": "ψ", // ѱ (rare)
  "\u0410": "A", // А → A
  "\u0412": "B", // В → B
  "\u0415": "E", // Е → E
  "\u041A": "K", // К → K
  "\u041C": "M", // М → M
  "\u041D": "H", // Н → H
  "\u041E": "O", // О → O
  "\u0420": "P", // Р → P
  "\u0421": "C", // С → C
  "\u0422": "T", // Т → T
  "\u0425": "X", // Х → X
  "\u04AE": "Y", // Ү → Y

  // Greek → Latin
  "\u03B1": "a", // α → a
  "\u03BF": "o", // ο → o
  "\u03B5": "e", // ε → e (visually similar in some fonts)
  "\u03BA": "k", // κ → k (visually similar in some fonts)
  "\u03BD": "v", // ν → v
  "\u03C1": "p", // ρ → p
  "\u03C4": "t", // τ → t (visually similar in some fonts)
  "\u0391": "A", // Α → A
  "\u0392": "B", // Β → B
  "\u0395": "E", // Ε → E
  "\u0396": "Z", // Ζ → Z
  "\u0397": "H", // Η → H
  "\u0399": "I", // Ι → I
  "\u039A": "K", // Κ → K
  "\u039C": "M", // Μ → M
  "\u039D": "N", // Ν → N
  "\u039F": "O", // Ο → O
  "\u03A1": "P", // Ρ → P
  "\u03A4": "T", // Τ → T
  "\u03A5": "Y", // Υ → Y
  "\u03A7": "X", // Χ → X
};

/** Build a regex that matches any homoglyph character */
const HOMOGLYPH_REGEX = new RegExp(`[${Object.keys(HOMOGLYPH_MAP).join("")}]`, "g");

/**
 * Replace all homoglyph characters with their ASCII equivalents.
 */
export function normalizeHomoglyphs(text: string): string {
  return text.replace(HOMOGLYPH_REGEX, (ch) => HOMOGLYPH_MAP[ch] ?? ch);
}

/**
 * Check if a string contains homoglyph characters.
 * Returns whether any were found, the count, and the normalized string.
 */
export function containsHomoglyphs(text: string): { found: boolean; count: number; normalized: string } {
  const matches = text.match(HOMOGLYPH_REGEX);
  const count = matches ? matches.length : 0;
  return {
    found: count > 0,
    count,
    normalized: count > 0 ? normalizeHomoglyphs(text) : text,
  };
}
