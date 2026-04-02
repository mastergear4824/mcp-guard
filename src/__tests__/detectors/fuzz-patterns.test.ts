import { describe, it, expect } from "vitest";
import { checkForInjection, checkResponseIndicators } from "../../detectors/fuzz-patterns.js";

describe("checkForInjection — false positive fixes", () => {
  it("does NOT trigger on 'The answer is 49'", () => {
    const result = checkForInjection("The answer is 49");
    expect(result).toBeNull();
  });

  it("does NOT trigger on single-word markdown backtick", () => {
    const result = checkForInjection("`variable`");
    expect(result).toBeNull();
  });

  it("does NOT trigger on simple template literal '${name}'", () => {
    const result = checkForInjection("Hello ${name}");
    expect(result).toBeNull();
  });

  it("does NOT trigger on 'one=true' (not an event handler)", () => {
    const result = checkForInjection("one=true");
    expect(result).toBeNull();
  });
});

describe("checkForInjection — real attacks", () => {
  it("detects real command substitution '$(npm install)'", () => {
    const result = checkForInjection("$(npm install)");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("Command Injection");
  });

  it("detects real XSS 'onclick=alert(1)'", () => {
    const result = checkForInjection("onclick=alert(1)");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("XSS");
  });

  it("detects SQL injection", () => {
    const result = checkForInjection("' OR 1=1--");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("SQL Injection");
  });

  it("detects command injection with semicolon", () => {
    const result = checkForInjection("; cat /etc/passwd");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("Command Injection");
  });

  it("detects path traversal", () => {
    const result = checkForInjection("../../../etc/shadow");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("Path Traversal");
  });

  it("detects template injection with {{...}}", () => {
    const result = checkForInjection("{{7*7}}");
    expect(result).not.toBeNull();
    expect(result!.category).toBe("Template Injection");
  });
});

describe("checkResponseIndicators — false positive fixes", () => {
  it("does NOT trigger on 'The answer is 49'", () => {
    const result = checkResponseIndicators("The answer is 49");
    expect(result).toBeNull();
  });

  it("detects '7*7=49' as template injection", () => {
    const result = checkResponseIndicators("computed 7 * 7 = 49");
    expect(result).not.toBeNull();
    expect(result!.name).toBe("Template Injection (7*7=49)");
  });

  it("detects stack trace exposure", () => {
    const result = checkResponseIndicators("at processData (/app/handler.js:10:5)");
    expect(result).not.toBeNull();
    expect(result!.name).toBe("Stack Trace Exposure");
  });

  it("detects command execution evidence", () => {
    const result = checkResponseIndicators("uid=0(root) gid=0(root)");
    expect(result).not.toBeNull();
    expect(result!.name).toBe("Command Execution Evidence");
  });

  it("returns null for clean text", () => {
    const result = checkResponseIndicators("Everything is working fine.");
    expect(result).toBeNull();
  });
});
