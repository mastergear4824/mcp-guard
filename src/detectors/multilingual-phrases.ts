/**
 * Multilingual Injection Phrase Detection — detects prompt injection
 * phrases in Korean, Chinese, and Japanese.
 */

/** Korean prompt injection phrases */
const KOREAN_PHRASES = [
  "이전 지시를 무시",
  "시스템 프롬프트",
  "새로운 지시",
  "모든 규칙 무시",
  "지금부터 너는",
  "관리자 모드",
];

/** Chinese prompt injection phrases */
const CHINESE_PHRASES = [
  "忽略之前的指令",
  "忽略所有指令",
  "系统提示",
  "新指令",
  "管理员模式",
  "你现在是",
];

/** Japanese prompt injection phrases */
const JAPANESE_PHRASES = [
  "前の指示を無視",
  "すべての指示を無視",
  "システムプロンプト",
  "新しい指示",
  "管理者モード",
];

/** All multilingual injection phrases combined */
const ALL_PHRASES = [...KOREAN_PHRASES, ...CHINESE_PHRASES, ...JAPANESE_PHRASES];

/**
 * Detect multilingual prompt injection phrases in a string.
 * Returns the matched phrase, or null if none found.
 */
export function detectMultilingualInjection(text: string): string | null {
  for (const phrase of ALL_PHRASES) {
    if (text.includes(phrase)) {
      return phrase;
    }
  }
  return null;
}
