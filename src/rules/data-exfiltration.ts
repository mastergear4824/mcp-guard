/**
 * Data Exfiltration Rule — inspects tools/call responses for:
 * - Sensitive data patterns (passwords, API keys, tokens)
 * - System path exposure (/etc/passwd, /proc)
 * - Stack trace leakage
 * - Command execution evidence
 */

import type { GuardRule, JsonRpcMessage, Direction, RuleContext, RuleVerdict } from "../types.js";
import { isResponse } from "../types.js";
import { checkResponseIndicators } from "../detectors/fuzz-patterns.js";

export class DataExfiltrationRule implements GuardRule {
  readonly id = "data-exfiltration";
  readonly type = "data-exfiltration";

  private config: Record<string, unknown>;

  constructor(config?: Record<string, unknown>) {
    this.config = config ?? {};
  }

  evaluate(message: JsonRpcMessage, direction: Direction, context: RuleContext): RuleVerdict | null {
    // Only applies to server→client responses for tools/call
    if (direction !== "server-to-client") return null;
    if (!isResponse(message)) return null;

    // Check if this is a response to a tools/call request
    const originalReq = context.requestMap.get(message.id);
    if (!originalReq || originalReq.method !== "tools/call") return null;

    // Extract text content from the response
    const content = extractResponseText(message.result);
    if (!content) return null;

    const action = this.getAction(context);

    const indicator = checkResponseIndicators(content);
    if (indicator) {
      return {
        action,
        ruleId: this.id,
        severity: indicator.severity,
        reason: `${indicator.name} in tool response (${indicator.cwe})`,
      };
    }

    return null;
  }

  private getAction(context: RuleContext): "block" | "warn" {
    const rule = context.policy.rules.find((r) => r.id === this.id);
    return rule?.action ?? "warn";
  }
}

/** Extract readable text from an MCP tool response result */
function extractResponseText(result: unknown): string | null {
  if (typeof result === "string") return result;

  if (result && typeof result === "object") {
    // MCP content array format: { content: [{ type: "text", text: "..." }] }
    const r = result as Record<string, unknown>;
    if (Array.isArray(r["content"])) {
      const texts: string[] = [];
      for (const item of r["content"] as Array<Record<string, unknown>>) {
        if (item["type"] === "text" && typeof item["text"] === "string") {
          texts.push(item["text"]);
        }
      }
      if (texts.length > 0) return texts.join("\n");
    }

    // Fallback: stringify the whole result
    try {
      return JSON.stringify(result);
    } catch {
      return null;
    }
  }

  return null;
}
