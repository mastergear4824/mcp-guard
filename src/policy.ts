/**
 * Policy engine — loads and validates YAML security policies.
 */

import { readFileSync } from "node:fs";
import { parse as parseYaml } from "yaml";
import type { PolicyConfig, PolicyRule, Severity } from "./types.js";

const VALID_RULE_TYPES = new Set(["tool-poisoning", "argument-injection", "data-exfiltration"]);
const VALID_ACTIONS = new Set(["block", "warn"]);
const VALID_SEVERITIES = new Set<Severity>(["critical", "high", "medium", "low", "info"]);
const VALID_LOG_LEVELS = new Set(["debug", "info", "warn", "error"]);

/** Default policy: all 3 builtin rules enabled */
export function getDefaultPolicy(): PolicyConfig {
  return {
    version: 1,
    failMode: "closed",
    logging: { level: "info", destination: "stderr" },
    rules: [
      { id: "tool-poisoning", enabled: true, severity: "critical", action: "block", type: "tool-poisoning" },
      { id: "argument-injection", enabled: true, severity: "critical", action: "block", type: "argument-injection" },
      { id: "data-exfiltration", enabled: true, severity: "high", action: "warn", type: "data-exfiltration" },
    ],
  };
}

/** Load policy from a YAML file path */
export function loadPolicy(configPath: string): PolicyConfig {
  const raw = readFileSync(configPath, "utf-8");
  const parsed = parseYaml(raw) as unknown;
  const sanitized = sanitizeObject(parsed);
  return validatePolicy(sanitized);
}

/** Validate and type-check a raw parsed object into PolicyConfig */
export function validatePolicy(raw: unknown): PolicyConfig {
  if (!raw || typeof raw !== "object") {
    throw new Error("Policy must be a YAML object");
  }

  const obj = raw as Record<string, unknown>;

  // Version
  if (obj["version"] !== 1) {
    throw new Error(`Unsupported policy version: ${String(obj["version"])}. Expected 1`);
  }

  // failMode
  const failMode = obj["failMode"] ?? "closed";
  if (failMode !== "closed" && failMode !== "open") {
    throw new Error(`Invalid failMode: "${String(failMode)}". Must be "closed" or "open"`);
  }

  // logging
  const logging = obj["logging"] as Record<string, unknown> | undefined;
  const logLevel = (logging?.["level"] as string) ?? "info";
  if (!VALID_LOG_LEVELS.has(logLevel)) {
    throw new Error(`Invalid log level: "${logLevel}"`);
  }

  // rules
  const rawRules = obj["rules"];
  if (!Array.isArray(rawRules)) {
    throw new Error("Policy must contain a 'rules' array");
  }

  const rules: PolicyRule[] = rawRules.map((r: unknown, i: number) => {
    if (!r || typeof r !== "object") {
      throw new Error(`Rule at index ${i} must be an object`);
    }
    const rule = r as Record<string, unknown>;

    const id = rule["id"];
    if (typeof id !== "string" || id.length === 0) {
      throw new Error(`Rule at index ${i} must have a string 'id'`);
    }

    const type = rule["type"] as string;
    if (!VALID_RULE_TYPES.has(type)) {
      throw new Error(`Rule "${id}": unknown type "${type}". Valid: ${[...VALID_RULE_TYPES].join(", ")}`);
    }

    const action = (rule["action"] as string) ?? "block";
    if (!VALID_ACTIONS.has(action)) {
      throw new Error(`Rule "${id}": invalid action "${action}". Valid: ${[...VALID_ACTIONS].join(", ")}`);
    }

    const severity = (rule["severity"] as Severity) ?? "high";
    if (!VALID_SEVERITIES.has(severity)) {
      throw new Error(`Rule "${id}": invalid severity "${severity}"`);
    }

    const enabled = rule["enabled"] !== false;

    return {
      id,
      enabled,
      severity,
      action: action as "block" | "warn",
      type: type as PolicyRule["type"],
      config: (rule["config"] as Record<string, unknown>) ?? undefined,
    };
  });

  return {
    version: 1,
    failMode: failMode as "closed" | "open",
    logging: { level: logLevel as PolicyConfig["logging"]["level"], destination: "stderr" },
    rules,
  };
}

/**
 * Sanitize parsed YAML to prevent prototype pollution.
 * Adapted from aiclude.asvs security.ts:134-149
 */
function sanitizeObject(obj: unknown): unknown {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObject);

  const clean: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;
    clean[key] = sanitizeObject(value);
  }
  return clean;
}
