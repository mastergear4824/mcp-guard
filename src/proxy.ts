/**
 * Stdio proxy engine — spawns MCP server as child process,
 * pipes stdin/stdout through security rules via shared RuleEngine.
 */

import spawn from "cross-spawn";
import type { ChildProcess } from "node:child_process";
import { MessageFramer } from "./framing.js";
import type {
  GuardRule,
  JsonRpcMessage,
  JsonRpcRequest,
  JsonRpcResponse,
  StdioProxyOptions,
  PolicyConfig,
} from "./types.js";
import { isRequest, isResponse, isMalformed } from "./types.js";
import { RuleEngine } from "./rule-engine.js";
import { Logger } from "./logger.js";

export class McpGuardProxy {
  private child: ChildProcess | null = null;
  private clientFramer = new MessageFramer();
  private serverFramer = new MessageFramer();
  private ruleEngine: RuleEngine;
  private options: StdioProxyOptions;
  private policy: PolicyConfig;
  private logger: Logger;
  private stopped = false;

  constructor(options: StdioProxyOptions, policy: PolicyConfig, rules: GuardRule[]) {
    this.options = options;
    this.policy = policy;
    this.logger = new Logger(options.verbose ? "debug" : policy.logging.level);
    this.ruleEngine = new RuleEngine({
      rules,
      policy,
      logger: this.logger,
      serverInfo: options.serverCommand,
      dryRun: options.dryRun,
    });
  }

  async start(): Promise<void> {
    this.logger.info("mcp-guard starting", {
      server: this.options.serverCommand,
      args: this.options.serverArgs,
      rules: this.ruleEngine.getRuleIds(),
      failMode: this.policy.failMode,
      dryRun: this.options.dryRun,
    });

    // Spawn MCP server as child process
    this.child = spawn(this.options.serverCommand, this.options.serverArgs, {
      stdio: ["pipe", "pipe", "inherit"], // stderr passes through
    });

    if (!this.child.stdin || !this.child.stdout) {
      throw new Error("Failed to open stdio pipes to MCP server");
    }

    // Handle child exit
    this.child.on("exit", (code, signal) => {
      this.logger.info("MCP server exited", { code, signal });
      if (!this.stopped) {
        process.exit(code ?? 1);
      }
    });

    this.child.on("error", (err) => {
      this.logger.error("Failed to spawn MCP server", { error: err.message });
      process.exit(1);
    });

    // Client → Server pipe
    process.stdin.on("data", (chunk: Buffer) => {
      this.handleClientData(chunk);
    });

    process.stdin.on("end", () => {
      this.logger.debug("Client stdin closed");
      this.stop();
    });

    // Server → Client pipe
    this.child.stdout.on("data", (chunk: Buffer) => {
      this.handleServerData(chunk);
    });

    this.child.stdout.on("end", () => {
      this.logger.debug("Server stdout closed");
    });

    // Signal forwarding
    const handleSignal = (sig: NodeJS.Signals) => {
      this.logger.info("Received signal, shutting down", { signal: sig });
      this.stop();
    };
    process.on("SIGTERM", handleSignal);
    process.on("SIGINT", handleSignal);
  }

  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.ruleEngine.dispose();

    if (this.child) {
      try { this.child.kill("SIGTERM"); } catch { /* already dead */ }
      setTimeout(() => {
        try { this.child?.kill("SIGKILL"); } catch { /* already dead */ }
      }, 2000);
    }
  }

  private handleClientData(chunk: Buffer): void {
    let messages: JsonRpcMessage[];
    try {
      messages = this.clientFramer.feed(chunk);
    } catch (err) {
      // Never forward raw bytes — malformed framing bypasses all rules (CSO Finding #1)
      this.logger.error("Client framing error, dropping message", {
        failMode: this.policy.failMode,
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    if (messages.length === 0) return;

    for (const msg of messages) {
      // Reject messages with contradictory fields (CSO Finding #10)
      if (isMalformed(msg)) {
        this.logger.warn("Dropping malformed JSON-RPC message (has both method and result/error)");
        if ("id" in msg) {
          this.writeToClient({
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
      const blocked = this.ruleEngine.handleVerdict(
        verdict,
        "client-to-server",
        isRequest(msg) ? msg.method : undefined,
      );

      if (blocked && isRequest(msg)) {
        const errorResponse: JsonRpcResponse = {
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: -32600,
            message: `Blocked by mcp-guard: ${verdict!.reason}`,
            data: { rule: verdict!.ruleId, severity: verdict!.severity },
          },
        };
        this.writeToClient(errorResponse);
        continue;
      }

      this.writeToServer(msg);
    }
  }

  private handleServerData(chunk: Buffer): void {
    let messages: JsonRpcMessage[];
    try {
      messages = this.serverFramer.feed(chunk);
    } catch (err) {
      // Never forward raw bytes — malformed framing bypasses all rules (CSO Finding #1)
      this.logger.error("Server framing error, dropping message", {
        failMode: this.policy.failMode,
        error: err instanceof Error ? err.message : String(err),
      });
      return;
    }

    if (messages.length === 0) return;

    for (const msg of messages) {
      // Reject messages with contradictory fields (CSO Finding #10)
      if (isMalformed(msg)) {
        this.logger.warn("Dropping malformed server JSON-RPC message (has both method and result/error)");
        continue;
      }

      const verdict = this.ruleEngine.evaluate(msg, "server-to-client");
      const blocked = this.ruleEngine.handleVerdict(verdict, "server-to-client");

      if (blocked) {
        if (isResponse(msg)) {
          const errorResponse: JsonRpcResponse = {
            jsonrpc: "2.0",
            id: msg.id,
            error: {
              code: -32600,
              message: `Blocked by mcp-guard: ${verdict!.reason}`,
              data: { rule: verdict!.ruleId, severity: verdict!.severity },
            },
          };
          this.writeToClient(errorResponse);
        }
        continue;
      }

      if (isResponse(msg)) {
        this.ruleEngine.untrackRequest(msg.id);
      }

      this.writeToClient(msg);
    }
  }

  private writeToClient(msg: JsonRpcMessage): void {
    process.stdout.write(MessageFramer.serialize(msg));
  }

  private writeToServer(msg: JsonRpcMessage): void {
    this.child?.stdin?.write(MessageFramer.serialize(msg));
  }

}
