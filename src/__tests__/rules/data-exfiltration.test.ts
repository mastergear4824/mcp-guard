import { describe, it, expect } from "vitest";
import { DataExfiltrationRule } from "../../rules/data-exfiltration.js";
import type { JsonRpcRequest, JsonRpcResponse, RuleContext, PolicyConfig } from "../../types.js";

function makeContext(requestMap?: Map<string | number, JsonRpcRequest>): RuleContext {
  const policy: PolicyConfig = {
    version: 1,
    failMode: "closed",
    logging: { level: "error", destination: "stderr" },
    rules: [{ id: "data-exfiltration", enabled: true, severity: "high", action: "warn", type: "data-exfiltration" }],
  };
  return {
    policy,
    serverCommand: "test",
    requestMap: requestMap ?? new Map(),
  };
}

function makeToolsCallExchange(result: unknown) {
  const req: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "test_tool" } };
  const res: JsonRpcResponse = { jsonrpc: "2.0", id: 1, result };
  const map = new Map<string | number, JsonRpcRequest>();
  map.set(1, req);
  return { req, res, map };
}

describe("DataExfiltrationRule", () => {
  const rule = new DataExfiltrationRule();

  it("should pass clean responses", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "The weather is sunny today." }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).toBeNull();
  });

  it("should detect sensitive data (password)", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "password=secret123" }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).not.toBeNull();
    expect(verdict!.reason).toContain("Sensitive Data");
  });

  it("should detect /etc/passwd content", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "root:x:0:0:root:/root:/bin/bash" }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).not.toBeNull();
    expect(verdict!.severity).toBe("critical");
  });

  it("should detect stack trace exposure", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "Error at processData (/app/src/handler.js:42:10)" }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).not.toBeNull();
    expect(verdict!.reason).toContain("Stack Trace");
  });

  it("should handle string result format", () => {
    const { res, map } = makeToolsCallExchange("api_key=sk-abc123secret");
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).not.toBeNull();
  });

  it("should ignore non-tools/call responses", () => {
    const req: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "tools/list", params: {} };
    const res: JsonRpcResponse = { jsonrpc: "2.0", id: 1, result: { content: [{ type: "text", text: "password=x" }] } };
    const map = new Map<string | number, JsonRpcRequest>();
    map.set(1, req);
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).toBeNull();
  });

  it("should default to warn action", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "password=leaked" }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).not.toBeNull();
    expect(verdict!.action).toBe("warn");
  });

  it("should NOT flag 'The answer is 49' (false positive fix)", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "The answer is 49" }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).toBeNull();
  });

  it("should NOT flag 'password' appearing in general discussion text", () => {
    const { res, map } = makeToolsCallExchange({
      content: [{ type: "text", text: "You should use a strong password for your accounts." }],
    });
    const verdict = rule.evaluate(res, "server-to-client", makeContext(map));
    expect(verdict).toBeNull();
  });
});
