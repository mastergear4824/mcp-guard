import { describe, it, expect } from "vitest";
import { getDefaultPolicy, validatePolicy } from "../policy.js";

describe("Policy", () => {
  it("should return valid default policy", () => {
    const policy = getDefaultPolicy();
    expect(policy.version).toBe(1);
    expect(policy.failMode).toBe("closed");
    expect(policy.rules).toHaveLength(3);
    expect(policy.rules[0]!.id).toBe("tool-poisoning");
    expect(policy.rules[1]!.id).toBe("argument-injection");
    expect(policy.rules[2]!.id).toBe("data-exfiltration");
  });

  it("should validate a correct policy object", () => {
    const raw = {
      version: 1,
      failMode: "closed",
      logging: { level: "info" },
      rules: [
        { id: "tool-poisoning", type: "tool-poisoning", action: "block", severity: "critical", enabled: true },
      ],
    };
    const policy = validatePolicy(raw);
    expect(policy.rules).toHaveLength(1);
    expect(policy.rules[0]!.action).toBe("block");
  });

  it("should reject unsupported version", () => {
    expect(() => validatePolicy({ version: 2, rules: [] })).toThrow("Unsupported policy version");
  });

  it("should reject invalid failMode", () => {
    expect(() => validatePolicy({ version: 1, failMode: "maybe", rules: [] })).toThrow("Invalid failMode");
  });

  it("should reject unknown rule type", () => {
    const raw = {
      version: 1,
      rules: [{ id: "test", type: "unknown-type", action: "block", severity: "high" }],
    };
    expect(() => validatePolicy(raw)).toThrow("unknown type");
  });

  it("should reject invalid action", () => {
    const raw = {
      version: 1,
      rules: [{ id: "test", type: "tool-poisoning", action: "destroy", severity: "high" }],
    };
    expect(() => validatePolicy(raw)).toThrow("invalid action");
  });

  it("should default enabled to true", () => {
    const raw = {
      version: 1,
      rules: [{ id: "test", type: "tool-poisoning", action: "block", severity: "high" }],
    };
    const policy = validatePolicy(raw);
    expect(policy.rules[0]!.enabled).toBe(true);
  });

  it("should strip prototype pollution keys", () => {
    const raw = {
      version: 1,
      __proto__: { admin: true },
      rules: [{ id: "test", type: "tool-poisoning", action: "block", severity: "high" }],
    };
    const policy = validatePolicy(raw);
    expect((policy as Record<string, unknown>)["admin"]).toBeUndefined();
  });
});
