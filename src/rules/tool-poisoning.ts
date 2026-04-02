/**
 * Tool Poisoning Rule — inspects tools/list responses for:
 * - Zero-width characters in descriptions (steganography)
 * - Prompt injection phrases
 * - HTML comments hiding content
 * - Base64-encoded hidden payloads
 * - Tool name shadowing
 * - Instruction-like manipulation patterns
 */

import type { GuardRule, JsonRpcMessage, Direction, RuleContext, RuleVerdict, Severity } from "../types.js";
import { isResponse } from "../types.js";
import { containsZeroWidth } from "../detectors/zero-width.js";
import { detectInjectionPhrase, detectInstructionPattern } from "../detectors/injection-phrases.js";
import { checkShadowing } from "../detectors/shadow-names.js";
import { containsHomoglyphs } from "../detectors/homoglyph.js";
import { detectMultilingualInjection } from "../detectors/multilingual-phrases.js";

interface ToolDef {
  name: string;
  description?: string;
  inputSchema?: Record<string, unknown>;
}

export class ToolPoisoningRule implements GuardRule {
  readonly id = "tool-poisoning";
  readonly type = "tool-poisoning";

  private config: Record<string, unknown>;

  constructor(config?: Record<string, unknown>) {
    this.config = config ?? {};
  }

  evaluate(message: JsonRpcMessage, direction: Direction, context: RuleContext): RuleVerdict | null {
    // Only applies to server→client responses for tools/list
    if (direction !== "server-to-client") return null;
    if (!isResponse(message)) return null;

    // Check if this is a response to a tools/list request
    const originalReq = context.requestMap.get(message.id);
    if (!originalReq || originalReq.method !== "tools/list") return null;

    const result = message.result as { tools?: ToolDef[] } | undefined;
    if (!result?.tools || !Array.isArray(result.tools)) return null;

    const action = this.getAction(context);

    for (const tool of result.tools) {
      const finding = this.checkTool(tool);
      if (finding) {
        return {
          action,
          ruleId: this.id,
          severity: finding.severity,
          reason: `Tool "${tool.name}": ${finding.reason}`,
        };
      }
    }

    return null;
  }

  private checkTool(tool: ToolDef): { severity: Severity; reason: string } | null {
    const desc = tool.description ?? "";

    // 1. Zero-width characters
    if (this.cfg("checkZeroWidth", true)) {
      const zw = containsZeroWidth(desc);
      if (zw.found) {
        return { severity: "critical", reason: `Hidden zero-width characters detected (${zw.count} found)` };
      }
      const zwName = containsZeroWidth(tool.name);
      if (zwName.found) {
        return { severity: "critical", reason: `Hidden zero-width characters in tool name` };
      }
    }

    // 1b. Homoglyph characters in name or description
    if (this.cfg("checkHomoglyphs", true)) {
      const hgName = containsHomoglyphs(tool.name);
      if (hgName.found) {
        return { severity: "high", reason: `Homoglyph characters in tool name (${hgName.count} found, normalized: "${hgName.normalized}")` };
      }
      const hgDesc = containsHomoglyphs(desc);
      if (hgDesc.found && hgDesc.count >= 3) {
        return { severity: "medium", reason: `Homoglyph characters in description (${hgDesc.count} found)` };
      }
    }

    // 2. Prompt injection phrases
    if (this.cfg("checkInjectionPhrases", true)) {
      const phrase = detectInjectionPhrase(desc);
      if (phrase) {
        return { severity: "critical", reason: `Prompt injection phrase in description: "${phrase}"` };
      }
    }

    // 2b. Multilingual injection phrases (Korean, Chinese, Japanese)
    if (this.cfg("checkMultilingualInjection", true)) {
      const mlPhrase = detectMultilingualInjection(desc);
      if (mlPhrase) {
        return { severity: "critical", reason: `Multilingual prompt injection phrase in description: "${mlPhrase}"` };
      }
    }

    // 3. HTML comments hiding content
    if (this.cfg("checkHtmlComments", true)) {
      const htmlComment = /<!--[\s\S]*?-->/;
      if (htmlComment.test(desc)) {
        return { severity: "high", reason: `HTML comment hiding content in description` };
      }
    }

    // 4. Base64-encoded hidden content
    if (this.cfg("checkBase64", true)) {
      const base64 = /[A-Za-z0-9+/]{40,}={0,2}/;
      if (base64.test(desc) && desc.length > 200) {
        return { severity: "high", reason: `Suspicious base64-encoded content in description` };
      }
    }

    // 5. Tool name shadowing
    if (this.cfg("checkShadowing", true)) {
      const shadow = checkShadowing(tool.name);
      if (shadow && !shadow.isGeneric) {
        return { severity: "high", reason: `Tool name shadows dangerous system tool: "${shadow.target}"` };
      }
    }

    // 6. Instruction-like patterns
    if (this.cfg("checkInstructionPatterns", true)) {
      if (detectInstructionPattern(desc)) {
        return { severity: "medium", reason: `Instruction-like manipulation pattern in description` };
      }
    }

    // 7. Excessive description length
    const maxLen = this.cfg("maxDescriptionLength", 5000) as number;
    if (maxLen > 0 && desc.length > maxLen) {
      return { severity: "medium", reason: `Description exceeds ${maxLen} chars (${desc.length})` };
    }

    // 8. InputSchema inspection — check field descriptions and default values for hidden injection
    if (this.cfg("checkInputSchema", true) && tool.inputSchema) {
      const schemaFinding = this.checkInputSchema(tool.inputSchema);
      if (schemaFinding) {
        return schemaFinding;
      }
    }

    return null;
  }

  /**
   * Recursively inspect inputSchema for hidden injection in field descriptions and default values.
   */
  private checkInputSchema(schema: Record<string, unknown>): { severity: Severity; reason: string } | null {
    const strings = this.extractSchemaStrings(schema);
    for (const { path, value } of strings) {
      // Check for injection phrases
      const phrase = detectInjectionPhrase(value);
      if (phrase) {
        return { severity: "critical", reason: `Prompt injection in inputSchema ${path}: "${phrase}"` };
      }
      // Check for multilingual injection
      const mlPhrase = detectMultilingualInjection(value);
      if (mlPhrase) {
        return { severity: "critical", reason: `Multilingual injection in inputSchema ${path}: "${mlPhrase}"` };
      }
      // Check for zero-width characters
      const zw = containsZeroWidth(value);
      if (zw.found) {
        return { severity: "high", reason: `Hidden zero-width characters in inputSchema ${path}` };
      }
      // Check for instruction patterns
      if (detectInstructionPattern(value)) {
        return { severity: "medium", reason: `Instruction-like pattern in inputSchema ${path}` };
      }
    }
    return null;
  }

  /**
   * Extract all string values from a JSON schema, tracking their path (e.g., "properties.query.description").
   * Focuses on "description" and "default" fields which are common injection vectors.
   */
  private extractSchemaStrings(obj: unknown, path = ""): Array<{ path: string; value: string }> {
    const results: Array<{ path: string; value: string }> = [];

    if (obj === null || typeof obj !== "object") return results;

    const record = obj as Record<string, unknown>;
    for (const [key, val] of Object.entries(record)) {
      const currentPath = path ? `${path}.${key}` : key;
      if (typeof val === "string" && (key === "description" || key === "default" || key === "title" || key === "enum")) {
        results.push({ path: currentPath, value: val });
      } else if (typeof val === "string" && key === "const") {
        results.push({ path: currentPath, value: val });
      } else if (Array.isArray(val)) {
        for (let i = 0; i < val.length; i++) {
          if (typeof val[i] === "string") {
            results.push({ path: `${currentPath}[${i}]`, value: val[i] as string });
          } else {
            results.push(...this.extractSchemaStrings(val[i], `${currentPath}[${i}]`));
          }
        }
      } else if (typeof val === "object" && val !== null) {
        results.push(...this.extractSchemaStrings(val, currentPath));
      }
    }

    return results;
  }

  private cfg(key: string, defaultValue: unknown): unknown {
    return this.config[key] ?? defaultValue;
  }

  private getAction(context: RuleContext): "block" | "warn" {
    const rule = context.policy.rules.find((r) => r.id === this.id);
    return rule?.action ?? "block";
  }
}
