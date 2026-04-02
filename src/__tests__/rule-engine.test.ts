import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { RuleEngine } from "../rule-engine.js";
import { Logger } from "../logger.js";
import type { GuardRule, JsonRpcRequest, PolicyConfig } from "../types.js";

function makePolicy(): PolicyConfig {
  return {
    version: 1,
    failMode: "closed",
    logging: { level: "error", destination: "stderr" },
    rules: [],
  };
}

function makeEngine(rules: GuardRule[] = []): RuleEngine {
  return new RuleEngine({
    rules,
    policy: makePolicy(),
    logger: new Logger("error"),
    serverInfo: "test-server",
    dryRun: false,
  });
}

function makeRequest(id: string | number, method: string): JsonRpcRequest {
  return { jsonrpc: "2.0", id, method, params: {} };
}

describe("RuleEngine — request tracking", () => {
  let engine: RuleEngine;

  afterEach(() => {
    engine?.dispose();
  });

  it("trackRequest stores entry and getRequestMap returns it", () => {
    engine = makeEngine();
    const req = makeRequest(1, "tools/call");
    engine.trackRequest(1, req);

    const map = engine.getRequestMap();
    expect(map.size).toBe(1);
    expect(map.get(1)).toEqual(req);
  });

  it("untrackRequest removes a tracked entry", () => {
    engine = makeEngine();
    const req = makeRequest(1, "tools/call");
    engine.trackRequest(1, req);
    engine.untrackRequest(1);

    const map = engine.getRequestMap();
    expect(map.size).toBe(0);
    expect(map.get(1)).toBeUndefined();
  });

  it("getRequestMap returns unwrapped requests without tracking metadata", () => {
    engine = makeEngine();
    const req1 = makeRequest(1, "tools/list");
    const req2 = makeRequest(2, "tools/call");
    engine.trackRequest(1, req1);
    engine.trackRequest(2, req2);

    const map = engine.getRequestMap();
    expect(map.size).toBe(2);
    // The values should be pure JsonRpcRequest objects, not TrackedEntry
    const val = map.get(1)!;
    expect(val.jsonrpc).toBe("2.0");
    expect(val.method).toBe("tools/list");
    expect((val as Record<string, unknown>)["trackedAt"]).toBeUndefined();
  });

  it("tracks multiple requests with different id types", () => {
    engine = makeEngine();
    engine.trackRequest(1, makeRequest(1, "tools/list"));
    engine.trackRequest("abc", makeRequest("abc", "tools/call"));

    const map = engine.getRequestMap();
    expect(map.size).toBe(2);
    expect(map.get(1)!.method).toBe("tools/list");
    expect(map.get("abc")!.method).toBe("tools/call");
  });
});

describe("RuleEngine — TTL cleanup", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: false });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("cleans up stale requests after 60+ seconds", () => {
    // Engine created with fake timers so Date.now() and setInterval are controlled
    const engine = makeEngine();

    // Track a request at faked time=0
    engine.trackRequest(1, makeRequest(1, "tools/call"));
    expect(engine.getRequestMap().size).toBe(1);

    // Advance past the 60s TTL; cleanup runs at 30s intervals
    // At 30s: request is 30s old, not stale yet
    // At 60s: request is 60s old, exactly at boundary — not cleaned (> not >=)
    // At 90s: request is 90s old, cleaned up
    vi.advanceTimersByTime(90_000);

    expect(engine.getRequestMap().size).toBe(0);

    engine.dispose();
  });

  it("does NOT clean up recent requests", () => {
    const engine = makeEngine();

    engine.trackRequest(1, makeRequest(1, "tools/call"));

    // Advance only 20 seconds — no cleanup interval fires yet (first at 30s)
    vi.advanceTimersByTime(20_000);

    expect(engine.getRequestMap().size).toBe(1);

    engine.dispose();
  });

  it("cleans up only stale entries, keeps recent ones", () => {
    const engine = makeEngine();

    // Track request at faked time=0
    engine.trackRequest(1, makeRequest(1, "tools/list"));

    // Advance 50 seconds (cleanup fires at 30s: req 1 is 30s old, survives)
    vi.advanceTimersByTime(50_000);

    // Track another request at time=50s
    engine.trackRequest(2, makeRequest(2, "tools/call"));

    // Advance another 40 seconds (total=90s)
    // Cleanup fires at 60s: req 1 is 60s old (boundary), req 2 is 10s old — both survive
    // Cleanup fires at 90s: req 1 is 90s old (stale, removed), req 2 is 40s old (survives)
    vi.advanceTimersByTime(40_000);

    const map = engine.getRequestMap();
    expect(map.size).toBe(1);
    expect(map.get(1)).toBeUndefined();
    expect(map.get(2)).toBeDefined();

    engine.dispose();
  });
});

describe("RuleEngine — dispose", () => {
  it("clears the cleanup interval", () => {
    vi.useFakeTimers();
    const engine = makeEngine();

    engine.trackRequest(1, makeRequest(1, "tools/call"));
    engine.dispose();

    // After dispose, advancing time should NOT cause cleanup
    // (the interval is cleared). We verify by checking the request is still there.
    // Note: since dispose only clears the interval but doesn't clear the map,
    // the request should remain.
    vi.advanceTimersByTime(120_000);
    expect(engine.getRequestMap().size).toBe(1);

    vi.useRealTimers();
  });

  it("can be called multiple times safely", () => {
    const engine = makeEngine();
    expect(() => {
      engine.dispose();
      engine.dispose();
    }).not.toThrow();
  });
});

describe("RuleEngine — evaluate", () => {
  it("returns null when no rules match", () => {
    const engine = makeEngine();
    const msg: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "tools/call", params: {} };
    const verdict = engine.evaluate(msg, "client-to-server");
    expect(verdict).toBeNull();
    engine.dispose();
  });

  it("blocks on rule evaluation error (fail-closed)", () => {
    const badRule: GuardRule = {
      id: "bad-rule",
      type: "test",
      evaluate() {
        throw new Error("boom");
      },
    };
    const engine = makeEngine([badRule]);
    const msg: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "tools/call", params: {} };
    const verdict = engine.evaluate(msg, "client-to-server");
    expect(verdict).not.toBeNull();
    expect(verdict!.action).toBe("block");
    expect(verdict!.severity).toBe("critical");
    expect(verdict!.reason).toContain("boom");
    engine.dispose();
  });
});
