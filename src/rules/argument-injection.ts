/**
 * Argument Injection Rule — inspects tools/call request arguments for:
 * - SQL injection, command injection, path traversal, XSS, template injection
 * - Prompt injection phrases in argument values
 */

import type { GuardRule, JsonRpcMessage, Direction, RuleContext, RuleVerdict } from "../types.js";
import { isRequest } from "../types.js";
import { checkForInjection } from "../detectors/fuzz-patterns.js";
import { detectInjectionPhrase } from "../detectors/injection-phrases.js";
import { containsZeroWidth } from "../detectors/zero-width.js";
import { normalizeHomoglyphs } from "../detectors/homoglyph.js";
import { detectMultilingualInjection } from "../detectors/multilingual-phrases.js";

export class ArgumentInjectionRule implements GuardRule {
  readonly id = "argument-injection";
  readonly type = "argument-injection";

  private config: Record<string, unknown>;

  constructor(config?: Record<string, unknown>) {
    this.config = config ?? {};
  }

  evaluate(message: JsonRpcMessage, direction: Direction, context: RuleContext): RuleVerdict | null {
    // Only applies to client→server requests for tools/call
    if (direction !== "client-to-server") return null;
    if (!isRequest(message)) return null;
    if (message.method !== "tools/call") return null;

    const params = message.params as { name?: string; arguments?: Record<string, unknown> } | undefined;
    if (!params?.arguments) return null;

    const action = this.getAction(context);
    const allValues = extractStringValues(params.arguments);

    for (const value of allValues) {
      // Normalize homoglyphs before checking injection patterns
      const normalized = normalizeHomoglyphs(value);

      // Check injection patterns (on both original and normalized)
      const injection = checkForInjection(normalized);
      if (injection) {
        return {
          action,
          ruleId: this.id,
          severity: injection.severity,
          reason: `${injection.category} detected in tool "${params.name ?? "unknown"}" arguments (${injection.cwe})`,
        };
      }

      // Check prompt injection in arguments
      if (this.cfg("checkPromptInjection", true)) {
        const phrase = detectInjectionPhrase(normalized);
        if (phrase) {
          return {
            action,
            ruleId: this.id,
            severity: "high",
            reason: `Prompt injection phrase in tool "${params.name ?? "unknown"}" arguments: "${phrase}"`,
          };
        }
      }

      // Check multilingual injection phrases (Korean, Chinese, Japanese)
      if (this.cfg("checkMultilingualInjection", true)) {
        const mlPhrase = detectMultilingualInjection(value);
        if (mlPhrase) {
          return {
            action,
            ruleId: this.id,
            severity: "high",
            reason: `Multilingual prompt injection in tool "${params.name ?? "unknown"}" arguments: "${mlPhrase}"`,
          };
        }
      }

      // Check zero-width characters in arguments
      const zw = containsZeroWidth(value);
      if (zw.found) {
        return {
          action,
          ruleId: this.id,
          severity: "high",
          reason: `Hidden zero-width characters in tool "${params.name ?? "unknown"}" arguments`,
        };
      }
    }

    return null;
  }

  private cfg(key: string, defaultValue: unknown): unknown {
    return this.config[key] ?? defaultValue;
  }

  private getAction(context: RuleContext): "block" | "warn" {
    const rule = context.policy.rules.find((r) => r.id === this.id);
    return rule?.action ?? "block";
  }
}

/** Recursively extract all string values from a nested object */
function extractStringValues(obj: unknown): string[] {
  const values: string[] = [];

  function walk(val: unknown): void {
    if (typeof val === "string") {
      values.push(val);
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item);
    } else if (val !== null && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v);
    }
  }

  walk(obj);
  return values;
}
