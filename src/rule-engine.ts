/**
 * Shared rule evaluation engine — used by both stdio and HTTP proxies.
 */

import type {
  GuardRule,
  JsonRpcMessage,
  JsonRpcRequest,
  Direction,
  RuleContext,
  RuleVerdict,
  PolicyConfig,
} from "./types.js";
import { Logger } from "./logger.js";

const REQUEST_TTL_MS = 60_000;
const MAX_TRACKED_REQUESTS = 10_000;

interface TrackedEntry {
  request: JsonRpcRequest;
  trackedAt: number;
}

export class RuleEngine {
  private rules: GuardRule[];
  private policy: PolicyConfig;
  private logger: Logger;
  private requestMap = new Map<string | number, TrackedEntry>();
  private serverInfo: string;
  private dryRun: boolean;
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(opts: {
    rules: GuardRule[];
    policy: PolicyConfig;
    logger: Logger;
    serverInfo: string;
    dryRun: boolean;
  }) {
    this.rules = opts.rules;
    this.policy = opts.policy;
    this.logger = opts.logger;
    this.serverInfo = opts.serverInfo;
    this.dryRun = opts.dryRun;

    this.cleanupInterval = setInterval(() => this.cleanupStaleRequests(), 30_000);
    this.cleanupInterval.unref();
  }

  /** Remove tracked requests older than REQUEST_TTL_MS, or oldest when over capacity */
  private cleanupStaleRequests(): void {
    const now = Date.now();
    for (const [id, entry] of this.requestMap) {
      if (now - entry.trackedAt > REQUEST_TTL_MS) {
        this.requestMap.delete(id);
      }
    }

    if (this.requestMap.size > MAX_TRACKED_REQUESTS) {
      const sorted = [...this.requestMap.entries()].sort(
        (a, b) => a[1].trackedAt - b[1].trackedAt,
      );
      const toRemove = sorted.slice(0, this.requestMap.size - MAX_TRACKED_REQUESTS);
      for (const [id] of toRemove) {
        this.requestMap.delete(id);
      }
    }
  }

  /** Clean up resources */
  dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }

  /** Get the list of rule IDs for logging */
  getRuleIds(): string[] {
    return this.rules.map((r) => r.id);
  }

  /** Track a request for later response correlation */
  trackRequest(id: string | number, request: JsonRpcRequest): void {
    this.requestMap.set(id, { request, trackedAt: Date.now() });
  }

  /** Remove a tracked request after response is processed */
  untrackRequest(id: string | number): void {
    this.requestMap.delete(id);
  }

  /** Get the request map for rule context (returns requests only, without tracking metadata) */
  getRequestMap(): Map<string | number, JsonRpcRequest> {
    const result = new Map<string | number, JsonRpcRequest>();
    for (const [id, entry] of this.requestMap) {
      result.set(id, entry.request);
    }
    return result;
  }

  /**
   * Evaluate all rules against a message.
   * Returns the first non-null verdict, or null if all rules pass.
   */
  evaluate(message: JsonRpcMessage, direction: Direction): RuleVerdict | null {
    const context: RuleContext = {
      policy: this.policy,
      serverCommand: this.serverInfo,
      requestMap: this.getRequestMap(),
    };

    for (const rule of this.rules) {
      try {
        const verdict = rule.evaluate(message, direction, context);
        if (verdict) return verdict;
      } catch (err) {
        // Always block on rule exception — a rule that cannot confirm safety
        // must not silently pass. This prevents attackers from crafting inputs
        // that trigger exceptions to bypass specific rules (CSO Finding #7).
        this.logger.error("Rule evaluation error, blocking", {
          rule: rule.id,
          error: err instanceof Error ? err.message : String(err),
        });
        return {
          action: "block",
          ruleId: rule.id,
          severity: "critical",
          reason: `Rule evaluation error: ${err instanceof Error ? err.message : String(err)}`,
        };
      }
    }

    return null;
  }

  /**
   * Log a verdict appropriately (block, dry-run block, or warn).
   * Returns true if the message should be blocked (not forwarded).
   */
  handleVerdict(verdict: RuleVerdict | null, direction: string, method?: string): boolean {
    if (!verdict) return false;

    const dirLabel = direction === "client-to-server" ? "client→server" : "server→client";

    if (verdict.action === "block") {
      if (this.dryRun) {
        this.logger.warn(`DRY-RUN WOULD BLOCK ${dirLabel}`, {
          rule: verdict.ruleId,
          severity: verdict.severity,
          reason: verdict.reason,
          method,
        });
        return false; // don't block in dry-run
      }
      this.logger.warn(`BLOCKED ${dirLabel}`, {
        rule: verdict.ruleId,
        severity: verdict.severity,
        reason: verdict.reason,
        method,
      });
      return true;
    }

    if (verdict.action === "warn") {
      this.logger.warn(`WARNING ${dirLabel}`, {
        rule: verdict.ruleId,
        severity: verdict.severity,
        reason: verdict.reason,
      });
    }

    return false;
  }
}
