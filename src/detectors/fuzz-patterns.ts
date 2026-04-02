/**
 * Injection detection patterns — used defensively to detect if tool call
 * arguments contain attack payloads.
 *
 * Security fixes (CSO Findings #4, #6, #8, #9):
 * - SQL patterns use normalizeForSql() to strip comments before matching
 * - Template injection ${} pattern removed (too many false positives)
 * - VULN_INDICATORS /49/ replaced with contextual pattern
 * - Sensitive data pattern requires assignment context
 *
 * Extracted from aiclude.asvs dast.ts:64-96
 */

import type { Severity } from "../types.js";
import { normalizeForSql, normalizeForDetection } from "./normalize.js";

export interface InjectionPattern {
  category: string;
  pattern: RegExp;
  severity: Severity;
  cwe: string;
}

/** Patterns derived from FUZZ_CATEGORIES payloads in dast.ts */
export const INJECTION_PATTERNS: InjectionPattern[] = [
  // SQL Injection
  { category: "SQL Injection", pattern: /'\s*OR\s+\d+=\d+/i, severity: "critical", cwe: "CWE-89" },
  { category: "SQL Injection", pattern: /;\s*DROP\s+TABLE\b/i, severity: "critical", cwe: "CWE-89" },
  { category: "SQL Injection", pattern: /UNION\s+SELECT\b/i, severity: "critical", cwe: "CWE-89" },
  { category: "SQL Injection", pattern: /;\s*DELETE\s+FROM\b/i, severity: "critical", cwe: "CWE-89" },

  // Command Injection
  { category: "Command Injection", pattern: /;\s*(?:ls|cat|rm|wget|curl|nc|bash|sh|id|whoami)\b/, severity: "critical", cwe: "CWE-78" },
  { category: "Command Injection", pattern: /\$\(\s*(?:[\w/]+\s+|;|&&|\|\|)/, severity: "critical", cwe: "CWE-78" },
  { category: "Command Injection", pattern: /`(?:[\w/]+\s+|;|&&|\|\|)[^`]+`/, severity: "critical", cwe: "CWE-78" },
  { category: "Command Injection", pattern: /\|\s*(?:cat|sh|bash|nc)\b/, severity: "critical", cwe: "CWE-78" },
  { category: "Command Injection", pattern: /&&\s*(?:echo|cat|rm|wget)\b/, severity: "critical", cwe: "CWE-78" },

  // Path Traversal
  { category: "Path Traversal", pattern: /(?:\.\.\/){2,}/, severity: "critical", cwe: "CWE-22" },
  { category: "Path Traversal", pattern: /(?:\.\.\\){2,}/, severity: "critical", cwe: "CWE-22" },
  { category: "Path Traversal", pattern: /\/proc\/self\//, severity: "critical", cwe: "CWE-22" },
  { category: "Path Traversal", pattern: /\/etc\/(?:passwd|shadow|hosts)/, severity: "critical", cwe: "CWE-22" },

  // XSS
  { category: "XSS", pattern: /<script\b[^>]*>.*<\/script>/i, severity: "critical", cwe: "CWE-79" },
  { category: "XSS", pattern: /\b(?:onclick|onerror|onload|onmouseover|onfocus|onblur)\s*=\s*["']?[^"']*["']?/i, severity: "critical", cwe: "CWE-79" },
  { category: "XSS", pattern: /javascript\s*:/i, severity: "critical", cwe: "CWE-79" },

  // Template Injection (server-side only — CSO Finding #8: ${} requires dangerous content)
  { category: "Template Injection", pattern: /\{\{.*\}\}/, severity: "critical", cwe: "CWE-94" },
  { category: "Template Injection", pattern: /\$\{(?:.*(?:process|require|import|eval|exec|spawn|constructor|__proto__|globalThis|Function))[^}]*\}/i, severity: "high", cwe: "CWE-94" },
  { category: "Template Injection", pattern: /<%=?.*%>/, severity: "critical", cwe: "CWE-94" },
];

/**
 * Check a string value for injection patterns.
 * Applies SQL normalization to defeat comment-based bypass (CSO Finding #6).
 * Returns the first matched pattern or null.
 *
 * @param value - The string to check
 * @param context - Optional context: "argument" (strict, default) or "description" (relaxed — skips template injection patterns to reduce false positives)
 */
export function checkForInjection(value: string, context: "argument" | "description" = "argument"): InjectionPattern | null {
  // Normalize for Unicode homoglyphs
  const normalized = normalizeForDetection(value);
  // Additional SQL normalization (strips comments)
  const sqlNormalized = normalizeForSql(value);

  for (const pat of INJECTION_PATTERNS) {
    // In description mode, skip template injection patterns to avoid false positives
    // on legitimate code examples or documentation
    if (context === "description" && pat.category === "Template Injection") {
      continue;
    }

    if (pat.category === "SQL Injection") {
      // Use SQL-normalized text for SQL patterns
      if (pat.pattern.test(sqlNormalized)) {
        return pat;
      }
    } else {
      // Use standard normalization for other patterns
      if (pat.pattern.test(normalized)) {
        return pat;
      }
    }
  }
  return null;
}

/** Response vulnerability indicators — with contextual patterns (CSO Finding #4, #9) */
export const VULN_INDICATORS = [
  { pattern: /(?:ENOENT|EACCES|EPERM).*\/etc\/|\/proc\/|\/root\//i, name: "Path Disclosure", cwe: "CWE-209", severity: "high" as Severity },
  { pattern: /at\s+\w+\s+\(.*:\d+:\d+\)/i, name: "Stack Trace Exposure", cwe: "CWE-209", severity: "high" as Severity },
  { pattern: /syntax\s+error|unexpected\s+token|unterminated/i, name: "SQL/Syntax Error Exposure", cwe: "CWE-209", severity: "high" as Severity },
  { pattern: /command\s+not\s+found|sh:|bash:|PWNED|uid=\d+/i, name: "Command Execution Evidence", cwe: "CWE-78", severity: "critical" as Severity },
  { pattern: /root:x:0:0|\/bin\/(?:ba)?sh/i, name: "/etc/passwd Content", cwe: "CWE-22", severity: "critical" as Severity },
  // CSO Finding #9: require assignment context (key=value or key:value) instead of bare word match; drop "token" (too generic)
  { pattern: /(?:^|[=:,\s])(?:password|secret|api[_-]?key)\s*[:=]\s*\S+/i, name: "Sensitive Data Exposure", cwe: "CWE-200", severity: "critical" as Severity },
  // CSO Finding #4: require computation context for template injection detection
  { pattern: /\b(?:7\s*\*\s*7\s*=\s*49|49\s*(?:=|==)\s*7\s*\*\s*7|\{\{7\*7\}\}.*49|<%.*7\*7.*%>.*49)/i, name: "Template Injection (7*7=49)", cwe: "CWE-94", severity: "critical" as Severity },
];

/**
 * Check response content for vulnerability indicators.
 * Returns the first matched indicator or null.
 */
export function checkResponseIndicators(content: string): (typeof VULN_INDICATORS)[number] | null {
  for (const ind of VULN_INDICATORS) {
    if (ind.pattern.test(content)) {
      return ind;
    }
  }
  return null;
}
