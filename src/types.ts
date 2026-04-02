// ─── Severity ────────────────────────────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

// ─── JSON-RPC 2.0 ───────────────────────────────────────────────────────────

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: Record<string, unknown>;
}

export interface JsonRpcResponse {
  jsonrpc: "2.0";
  id: string | number;
  result?: unknown;
  error?: { code: number; message: string; data?: unknown };
}

export type JsonRpcMessage = JsonRpcRequest | JsonRpcNotification | JsonRpcResponse;

export function isRequest(msg: JsonRpcMessage): msg is JsonRpcRequest {
  // Must have method + id, and must NOT have result/error (CSO Finding #10)
  return "method" in msg && "id" in msg && !("result" in msg) && !("error" in msg);
}

export function isNotification(msg: JsonRpcMessage): msg is JsonRpcNotification {
  return "method" in msg && !("id" in msg);
}

export function isResponse(msg: JsonRpcMessage): msg is JsonRpcResponse {
  return !("method" in msg) && "id" in msg;
}

/** Check if a message has contradictory fields (both request and response fields) */
export function isMalformed(msg: JsonRpcMessage): boolean {
  const hasMethod = "method" in msg;
  const hasResult = "result" in msg;
  const hasError = "error" in msg;
  return hasMethod && (hasResult || hasError);
}

// ─── Direction ───────────────────────────────────────────────────────────────

export type Direction = "client-to-server" | "server-to-client";

// ─── Rule System ─────────────────────────────────────────────────────────────

export interface RuleVerdict {
  action: "allow" | "block" | "warn";
  ruleId: string;
  severity: Severity;
  reason: string;
  /** Modified message for action=block on tools/list (strip offending tools) */
  modifiedMessage?: JsonRpcMessage;
}

export interface GuardRule {
  readonly id: string;
  readonly type: string;
  evaluate(
    message: JsonRpcMessage,
    direction: Direction,
    context: RuleContext,
  ): RuleVerdict | null;
}

export interface RuleContext {
  policy: PolicyConfig;
  serverCommand: string;
  /** Maps request id → original request, for correlating responses */
  requestMap: Map<string | number, JsonRpcRequest>;
}

// ─── Policy ──────────────────────────────────────────────────────────────────

export interface PolicyConfig {
  version: number;
  failMode: "closed" | "open";
  logging: { level: "debug" | "info" | "warn" | "error"; destination: "stderr" };
  rules: PolicyRule[];
}

export interface PolicyRule {
  id: string;
  enabled: boolean;
  severity: Severity;
  action: "block" | "warn";
  type: "tool-poisoning" | "argument-injection" | "data-exfiltration";
  config?: Record<string, unknown>;
}

// ─── Proxy Options ───────────────────────────────────────────────────────────

export type TransportMode = "stdio" | "http";

export interface StdioProxyOptions {
  mode: "stdio";
  configPath?: string;
  serverCommand: string;
  serverArgs: string[];
  verbose: boolean;
  failOpen: boolean;
  dryRun: boolean;
}

export interface HttpProxyOptions {
  mode: "http";
  configPath?: string;
  /** Upstream MCP server URL (e.g. http://localhost:8080/mcp) */
  upstream: string;
  /** Port to listen on */
  port: number;
  /** Host to bind to */
  host: string;
  verbose: boolean;
  failOpen: boolean;
  dryRun: boolean;
}

export type ProxyOptions = StdioProxyOptions | HttpProxyOptions;
