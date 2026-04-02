/**
 * HTTP proxy engine — sits between MCP client (HTTP) and MCP server (HTTP).
 *
 * Supports:
 * - Streamable HTTP (POST /mcp, GET /mcp for SSE, DELETE /mcp)
 * - Legacy HTTP+SSE (GET /sse for SSE stream, POST /messages?sessionId=xxx)
 *
 * Architecture:
 *   MCP Client ──HTTP──> mcp-guard (:port) ──HTTP──> upstream MCP server
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type {
  GuardRule,
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcResponse,
  HttpProxyOptions,
  PolicyConfig,
} from "./types.js";
import { isRequest, isResponse, isMalformed } from "./types.js";
import { RuleEngine } from "./rule-engine.js";
import { Logger } from "./logger.js";

const MAX_REQUEST_BODY = 5 * 1024 * 1024; // 5MB
const MAX_SSE_BUFFER = 1 * 1024 * 1024; // 1MB
const UPSTREAM_TIMEOUT_MS = 30_000; // 30s

export class McpHttpProxy {
  private server: ReturnType<typeof createServer> | null = null;
  private ruleEngine: RuleEngine;
  private options: HttpProxyOptions;
  private logger: Logger;

  constructor(options: HttpProxyOptions, policy: PolicyConfig, rules: GuardRule[]) {
    this.options = options;
    this.logger = new Logger(options.verbose ? "debug" : policy.logging.level);
    this.ruleEngine = new RuleEngine({
      rules,
      policy,
      logger: this.logger,
      serverInfo: options.upstream,
      dryRun: options.dryRun,
    });
  }

  async start(): Promise<void> {
    this.logger.info("mcp-guard HTTP proxy starting", {
      upstream: this.options.upstream,
      listen: `${this.options.host}:${this.options.port}`,
      dryRun: this.options.dryRun,
    });

    this.server = createServer((req, res) => {
      this.handleRequest(req, res).catch((err) => {
        this.logger.error("Request handler error", { error: (err as Error).message });
        if (!res.headersSent) {
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Internal proxy error" }));
        }
      });
    });

    return new Promise<void>((resolve, reject) => {
      this.server!.on("error", reject);
      this.server!.listen(this.options.port, this.options.host, () => {
        this.logger.info("mcp-guard HTTP proxy listening", {
          url: `http://${this.options.host}:${this.options.port}`,
        });
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    this.ruleEngine.dispose();
    return new Promise<void>((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const method = req.method?.toUpperCase() ?? "GET";
    const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);

    this.logger.debug("Incoming request", { method, path: url.pathname, query: url.search });

    // Route based on HTTP method
    if (method === "POST") {
      await this.handlePost(req, res, url);
    } else if (method === "GET") {
      await this.handleGet(req, res, url);
    } else if (method === "DELETE") {
      await this.handleDelete(req, res);
    } else {
      res.writeHead(405, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Method ${method} not allowed` }));
    }
  }

  // ─── POST: Client sends JSON-RPC messages ──────────────────────────────────

  private async handlePost(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const body = await readBody(req);
    if (!body) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Empty request body" }));
      return;
    }

    // Parse JSON-RPC message(s)
    let messages: JsonRpcMessage[];
    try {
      const parsed = JSON.parse(body);
      messages = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Invalid JSON" }));
      return;
    }

    // Check each message against rules (client→server)
    const blocked: JsonRpcResponse[] = [];
    const allowed: JsonRpcMessage[] = [];

    for (const msg of messages) {
      // Reject messages with contradictory fields (CSO Finding #10)
      if (isMalformed(msg)) {
        this.logger.warn("Dropping malformed JSON-RPC message (has both method and result/error)");
        if ("id" in msg) {
          blocked.push({
            jsonrpc: "2.0",
            id: (msg as JsonRpcRequest).id,
            error: { code: -32600, message: "Malformed JSON-RPC: contradictory fields" },
          });
        }
        continue;
      }

      if (isRequest(msg)) {
        this.ruleEngine.trackRequest(msg.id, msg);
      }

      const verdict = this.ruleEngine.evaluate(msg, "client-to-server");
      const shouldBlock = this.ruleEngine.handleVerdict(
        verdict,
        "client-to-server",
        isRequest(msg) ? msg.method : undefined,
      );

      if (shouldBlock && isRequest(msg)) {
        blocked.push({
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32600,
            message: `Blocked by mcp-guard: ${verdict!.reason}`,
            data: { rule: verdict!.ruleId, severity: verdict!.severity },
          },
        });
      } else {
        allowed.push(msg);
      }
    }

    // If all messages were blocked, return errors directly
    if (allowed.length === 0 && blocked.length > 0) {
      const accept = req.headers.accept ?? "";
      if (accept.includes("text/event-stream")) {
        // Client expects SSE
        res.writeHead(200, sseHeaders());
        for (const err of blocked) {
          writeSseEvent(res, "message", JSON.stringify(err));
        }
        res.end();
      } else {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(blocked.length === 1 ? blocked[0] : blocked));
      }
      return;
    }

    // Forward allowed messages to upstream
    const upstreamUrl = new URL(url.pathname + url.search, this.options.upstream);
    const upstreamRes = await this.forwardPost(upstreamUrl.toString(), req, allowed);

    if (!upstreamRes.ok && !upstreamRes.body) {
      res.writeHead(upstreamRes.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Upstream returned ${upstreamRes.status}` }));
      return;
    }

    const upstreamContentType = upstreamRes.headers.get("content-type") ?? "";

    // Copy relevant headers from upstream
    const proxyHeaders: Record<string, string> = {};
    const sessionId = upstreamRes.headers.get("mcp-session-id");
    if (sessionId) proxyHeaders["mcp-session-id"] = sessionId;

    if (upstreamContentType.includes("text/event-stream")) {
      // Upstream returns SSE — stream through with rule inspection
      proxyHeaders["content-type"] = "text/event-stream";
      proxyHeaders["cache-control"] = "no-cache, no-transform";
      proxyHeaders["connection"] = "keep-alive";
      res.writeHead(upstreamRes.status, proxyHeaders);

      await this.streamSseResponse(upstreamRes, res, blocked);
    } else {
      // Upstream returns plain JSON
      const responseBody = await upstreamRes.text();
      proxyHeaders["content-type"] = upstreamContentType || "application/json";
      res.writeHead(upstreamRes.status, proxyHeaders);

      // Inspect JSON response for server→client rules
      const inspected = this.inspectJsonResponse(responseBody, blocked);
      res.end(inspected);
    }
  }

  // ─── GET: SSE stream (server→client notifications) ─────────────────────────

  private async handleGet(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    const upstreamUrl = new URL(url.pathname + url.search, this.options.upstream);

    // Forward GET to upstream with SSE headers
    const headers: Record<string, string> = {
      "Accept": "text/event-stream",
    };
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId) headers["Mcp-Session-Id"] = String(sessionId);
    const protocolVersion = req.headers["mcp-protocol-version"];
    if (protocolVersion) headers["Mcp-Protocol-Version"] = String(protocolVersion);
    const lastEventId = req.headers["last-event-id"];
    if (lastEventId) headers["Last-Event-Id"] = String(lastEventId);

    let upstreamRes: Response;
    try {
      const ac = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
      upstreamRes = await fetch(upstreamUrl.toString(), { method: "GET", headers, signal: ac });
    } catch (err) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Upstream connection failed: ${(err as Error).message}` }));
      return;
    }

    if (!upstreamRes.ok || !upstreamRes.body) {
      res.writeHead(upstreamRes.status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Upstream returned ${upstreamRes.status}` }));
      return;
    }

    // Stream SSE from upstream to client
    const proxyHeaders: Record<string, string> = {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      "connection": "keep-alive",
    };
    const upSessionId = upstreamRes.headers.get("mcp-session-id");
    if (upSessionId) proxyHeaders["mcp-session-id"] = upSessionId;
    res.writeHead(200, proxyHeaders);

    await this.streamSseResponse(upstreamRes, res, []);
  }

  // ─── DELETE: Session termination ───────────────────────────────────────────

  private async handleDelete(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const headers: Record<string, string> = {};
    const sessionId = req.headers["mcp-session-id"];
    if (sessionId) headers["Mcp-Session-Id"] = String(sessionId);

    try {
      const ac = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
      const upstreamRes = await fetch(this.options.upstream, { method: "DELETE", headers, signal: ac });
      res.writeHead(upstreamRes.status);
      res.end();
    } catch (err) {
      res.writeHead(502, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: `Upstream connection failed: ${(err as Error).message}` }));
    }
  }

  // ─── Helpers ───────────────────────────────────────────────────────────────

  private async forwardPost(
    upstreamUrl: string,
    originalReq: IncomingMessage,
    messages: JsonRpcMessage[],
  ): Promise<Response> {
    const body = messages.length === 1 ? JSON.stringify(messages[0]) : JSON.stringify(messages);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      "Accept": originalReq.headers.accept ?? "application/json, text/event-stream",
    };

    // Forward MCP-specific headers
    const sessionId = originalReq.headers["mcp-session-id"];
    if (sessionId) headers["Mcp-Session-Id"] = String(sessionId);
    const protocolVersion = originalReq.headers["mcp-protocol-version"];
    if (protocolVersion) headers["Mcp-Protocol-Version"] = String(protocolVersion);
    const auth = originalReq.headers["authorization"];
    if (auth) headers["Authorization"] = String(auth);

    try {
      const ac = AbortSignal.timeout(UPSTREAM_TIMEOUT_MS);
      return await fetch(upstreamUrl, { method: "POST", headers, body, signal: ac });
    } catch (err) {
      // Return a synthetic error response
      return new Response(JSON.stringify({ error: `Upstream connection failed: ${(err as Error).message}` }), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  /**
   * Stream SSE from upstream Response to client ServerResponse,
   * inspecting each JSON-RPC message through security rules.
   */
  private async streamSseResponse(
    upstreamRes: Response,
    clientRes: ServerResponse,
    prependErrors: JsonRpcResponse[],
  ): Promise<void> {
    // Send any blocked messages first as SSE events
    for (const err of prependErrors) {
      writeSseEvent(clientRes, "message", JSON.stringify(err));
    }

    if (!upstreamRes.body) {
      clientRes.end();
      return;
    }

    const reader = upstreamRes.body.getReader();
    const decoder = new TextDecoder();
    let sseBuffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        sseBuffer += decoder.decode(value, { stream: true });

        // Guard against unbounded SSE buffer growth
        if (sseBuffer.length > MAX_SSE_BUFFER) {
          this.logger.warn("SSE buffer exceeded limit, resetting", { size: sseBuffer.length });
          sseBuffer = "";
          continue;
        }

        // Parse SSE events from buffer
        const events = parseSseEvents(sseBuffer);
        sseBuffer = events.remaining;

        for (const event of events.parsed) {
          if (event.event === "message" && event.data) {
            // Inspect JSON-RPC message
            const inspected = this.inspectSseMessage(event.data);
            if (inspected !== null) {
              writeSseEvent(clientRes, event.event, inspected, event.id);
            }
            // null = blocked, don't forward
          } else {
            // Non-message events (endpoint, ping, etc.) — pass through
            writeSseEventRaw(clientRes, event);
          }
        }
      }
    } catch (err) {
      this.logger.error("SSE stream error", { error: (err as Error).message });
    } finally {
      clientRes.end();
    }
  }

  /**
   * Inspect a single JSON-RPC message from an SSE event.
   * Returns the (possibly modified) JSON string, or null to block.
   */
  private inspectSseMessage(data: string): string | null {
    let msg: JsonRpcMessage;
    try {
      msg = JSON.parse(data) as JsonRpcMessage;
    } catch {
      // Block unparseable messages — passing through bypasses all rules
      this.logger.warn("Dropping unparseable SSE JSON-RPC message");
      return null;
    }

    // Reject malformed messages (CSO Finding #10)
    if (isMalformed(msg)) {
      this.logger.warn("Dropping malformed SSE JSON-RPC message");
      return null;
    }

    const verdict = this.ruleEngine.evaluate(msg, "server-to-client");
    const shouldBlock = this.ruleEngine.handleVerdict(verdict, "server-to-client");

    if (shouldBlock) {
      if (isResponse(msg)) {
        // Replace with error response
        const errorResponse: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32600,
            message: `Blocked by mcp-guard: ${verdict!.reason}`,
            data: { rule: verdict!.ruleId, severity: verdict!.severity },
          },
        };
        return JSON.stringify(errorResponse);
      }
      return null; // Block notification entirely
    }

    // Clean up request tracking
    if (isResponse(msg)) {
      this.ruleEngine.untrackRequest(msg.id);
    }

    return data;
  }

  /**
   * Inspect a plain JSON response body.
   */
  private inspectJsonResponse(body: string, prependErrors: JsonRpcResponse[]): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      // Block unparseable JSON responses
      this.logger.warn("Dropping unparseable JSON response from upstream");
      const err: JsonRpcResponse = {
        jsonrpc: "2.0",
        id: 0,
        error: { code: -32600, message: "Upstream returned unparseable JSON" },
      };
      return JSON.stringify(prependErrors.length > 0 ? [...prependErrors, err] : err);
    }

    const messages: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
    const results: unknown[] = [...prependErrors];

    for (const raw of messages) {
      const msg = raw as JsonRpcMessage;
      if (msg.jsonrpc !== "2.0") {
        results.push(raw);
        continue;
      }

      // Reject malformed messages (CSO Finding #10)
      if (isMalformed(msg)) {
        this.logger.warn("Dropping malformed JSON-RPC response");
        if (isResponse(msg)) {
          results.push({
            jsonrpc: "2.0",
            id: msg.id,
            error: { code: -32600, message: "Malformed JSON-RPC: contradictory fields" },
          });
        }
        continue;
      }

      const verdict = this.ruleEngine.evaluate(msg, "server-to-client");
      const shouldBlock = this.ruleEngine.handleVerdict(verdict, "server-to-client");

      if (shouldBlock && isResponse(msg)) {
        results.push({
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32600,
            message: `Blocked by mcp-guard: ${verdict!.reason}`,
            data: { rule: verdict!.ruleId, severity: verdict!.severity },
          },
        });
      } else {
        if (isResponse(msg)) {
          this.ruleEngine.untrackRequest(msg.id);
        }
        results.push(raw);
      }
    }

    // Return single or array based on original format
    if (!Array.isArray(parsed) && results.length === 1) {
      return JSON.stringify(results[0]);
    }
    return JSON.stringify(results);
  }
}

// ─── SSE Utilities ─────────────────────────────────────────────────────────

interface SseEvent {
  event?: string;
  data?: string;
  id?: string;
  retry?: string;
}

function sseHeaders(): Record<string, string> {
  return {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache, no-transform",
    "Connection": "keep-alive",
  };
}

/** Sanitize SSE field value to prevent injection via embedded newlines */
function sanitizeSseField(value: string): string {
  return value.replace(/[\n\r]/g, "");
}

function writeSseEvent(res: ServerResponse, event: string, data: string, id?: string): void {
  if (id) res.write(`id: ${sanitizeSseField(id)}\n`);
  res.write(`event: ${sanitizeSseField(event)}\n`);
  // SSE data lines: split on newlines
  for (const line of data.split("\n")) {
    res.write(`data: ${line}\n`);
  }
  res.write("\n");
}

function writeSseEventRaw(res: ServerResponse, event: SseEvent): void {
  if (event.id) res.write(`id: ${sanitizeSseField(event.id)}\n`);
  if (event.event) res.write(`event: ${sanitizeSseField(event.event)}\n`);
  if (event.retry) res.write(`retry: ${sanitizeSseField(event.retry)}\n`);
  if (event.data !== undefined) {
    for (const line of event.data.split("\n")) {
      res.write(`data: ${line}\n`);
    }
  }
  res.write("\n");
}

function parseSseEvents(buffer: string): { parsed: SseEvent[]; remaining: string } {
  const events: SseEvent[] = [];

  // SSE events are separated by double newlines
  const parts = buffer.split("\n\n");
  // Last part may be incomplete
  const remaining = parts.pop() ?? "";

  for (const part of parts) {
    if (part.trim() === "") continue;

    const event: SseEvent = {};
    for (const line of part.split("\n")) {
      if (line.startsWith("event:")) {
        event.event = line.substring(6).trim();
      } else if (line.startsWith("data:")) {
        const val = line.substring(5).trimStart();
        event.data = event.data !== undefined ? event.data + "\n" + val : val;
      } else if (line.startsWith("id:")) {
        event.id = line.substring(3).trim();
      } else if (line.startsWith("retry:")) {
        event.retry = line.substring(6).trim();
      }
    }
    events.push(event);
  }

  return { parsed: events, remaining };
}

async function readBody(req: IncomingMessage): Promise<string | null> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalSize = 0;
    req.on("data", (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_REQUEST_BODY) {
        req.destroy();
        reject(new Error(`Request body exceeds ${MAX_REQUEST_BODY} bytes limit`));
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf-8");
      resolve(body.length > 0 ? body : null);
    });
    req.on("error", () => resolve(null));
  });
}
