/**
 * Tool name shadowing detection — checks if a tool name mimics
 * a well-known dangerous system tool.
 *
 * Uses Unicode normalization to prevent homoglyph evasion (CSO Finding #3).
 * Extracted from aiclude.asvs tool-analyzer.ts:93-114
 */

import { normalizeForDetection } from "./normalize.js";

/** Tool names that are dangerous if shadowed by a third-party MCP server */
export const SHADOW_TARGET_NAMES = [
  "read_file",
  "write_file",
  "execute_command",
  "run_terminal",
  "bash",
  "search",
  "edit_file",
  "list_directory",
  "create_file",
  "delete_file",
  "read_resource",
  "call_tool",
  "search_files",
  "run_command",
];

/** Generic MCP tool names that are expected and low-risk */
export const GENERIC_TOOL_NAMES = new Set([
  "search", "read_file", "write_file", "edit_file", "list_directory",
  "create_file", "delete_file", "read_resource", "search_files",
]);

export interface ShadowResult {
  isShadow: boolean;
  target: string;
  isGeneric: boolean;
}

/**
 * Check if a tool name shadows a known dangerous tool.
 * Returns null if no shadowing detected.
 */
export function checkShadowing(toolName: string): ShadowResult | null {
  // Apply Unicode normalization to defeat homoglyph evasion (CSO Finding #3)
  const normalized = normalizeForDetection(toolName).toLowerCase().replace(/[-\s]/g, "_");

  for (const target of SHADOW_TARGET_NAMES) {
    if (normalized === target) {
      return {
        isShadow: true,
        target,
        isGeneric: GENERIC_TOOL_NAMES.has(target),
      };
    }
    // Check for namespace-prefixed shadowing: "evil__read_file" or "ns_read_file"
    if (normalized.endsWith(`_${target}`) || normalized.endsWith(`__${target}`)) {
      return {
        isShadow: true,
        target,
        isGeneric: GENERIC_TOOL_NAMES.has(target),
      };
    }
  }

  return null;
}
