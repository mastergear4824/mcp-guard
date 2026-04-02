/**
 * Rule registry — creates rule instances from policy configuration.
 */

import type { GuardRule, PolicyConfig } from "../types.js";
import { ToolPoisoningRule } from "./tool-poisoning.js";
import { ArgumentInjectionRule } from "./argument-injection.js";
import { DataExfiltrationRule } from "./data-exfiltration.js";

const RULE_CONSTRUCTORS: Record<string, new (config?: Record<string, unknown>) => GuardRule> = {
  "tool-poisoning": ToolPoisoningRule,
  "argument-injection": ArgumentInjectionRule,
  "data-exfiltration": DataExfiltrationRule,
};

/**
 * Create rule instances from policy configuration.
 * Only enabled rules are instantiated.
 */
export function createRules(policy: PolicyConfig): GuardRule[] {
  const rules: GuardRule[] = [];

  for (const ruleConfig of policy.rules) {
    if (!ruleConfig.enabled) continue;

    const Constructor = RULE_CONSTRUCTORS[ruleConfig.type];
    if (!Constructor) {
      throw new Error(`Unknown rule type: "${ruleConfig.type}"`);
    }

    rules.push(new Constructor(ruleConfig.config));
  }

  return rules;
}
