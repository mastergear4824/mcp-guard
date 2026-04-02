#!/usr/bin/env node

/**
 * mcp-guard — MCP runtime security proxy
 *
 * Two modes:
 *   stdio: mcp-guard [options] -- <server-command> [server-args...]
 *   http:  mcp-guard http [options] --upstream <url>
 */

import { Command } from "commander";
import { loadPolicy, getDefaultPolicy } from "./policy.js";
import { createRules } from "./rules/index.js";
import { McpGuardProxy } from "./proxy.js";
import { McpHttpProxy } from "./http-proxy.js";
import type { PolicyConfig } from "./types.js";

function resolvePolicy(configPath?: string, failOpen?: boolean): PolicyConfig {
  let policy = getDefaultPolicy();
  if (configPath) {
    try {
      policy = loadPolicy(configPath);
    } catch (err) {
      console.error(`[mcp-guard] Failed to load policy: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }
  if (failOpen) {
    policy.failMode = "open";
  }
  return policy;
}

const program = new Command();

program
  .name("mcp-guard")
  .description("MCP runtime security proxy — intercepts and enforces security policies on MCP tool calls")
  .version("0.2.0");

// ─── Default command: stdio mode ─────────────────────────────────────────────

program
  .option("-c, --config <path>", "Path to policy YAML file")
  .option("-v, --verbose", "Enable debug logging", false)
  .option("--fail-open", "Allow traffic on policy errors (NOT recommended)", false)
  .option("--dry-run", "Log decisions but never block", false)
  .argument("<server-command>", "MCP server command to proxy (stdio mode)")
  .argument("[server-args...]", "Arguments for the MCP server")
  .action(async (serverCommand: string, serverArgs: string[], opts: Record<string, unknown>) => {
    try {
      const policy = resolvePolicy(opts["config"] as string | undefined, opts["failOpen"] as boolean);
      const rules = createRules(policy);
      if (rules.length === 0) console.error("[mcp-guard] Warning: no rules enabled");

      const proxy = new McpGuardProxy(
        {
          mode: "stdio",
          serverCommand,
          serverArgs,
          verbose: opts["verbose"] as boolean,
          failOpen: opts["failOpen"] as boolean,
          dryRun: opts["dryRun"] as boolean,
          configPath: opts["config"] as string | undefined,
        },
        policy,
        rules,
      );
      await proxy.start();
    } catch (err) {
      console.error(`[mcp-guard] Fatal: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  });

// ─── Subcommand: http mode ───────────────────────────────────────────────────

program
  .command("http")
  .description("Run as HTTP reverse proxy between MCP client and a remote MCP server")
  .requiredOption("-u, --upstream <url>", "Upstream MCP server URL (e.g. http://localhost:8080/mcp)")
  .option("-p, --port <number>", "Port to listen on", "9090")
  .option("-H, --host <host>", "Host to bind to", "127.0.0.1")
  .option("-c, --config <path>", "Path to policy YAML file")
  .option("-v, --verbose", "Enable debug logging", false)
  .option("--fail-open", "Allow traffic on policy errors (NOT recommended)", false)
  .option("--dry-run", "Log decisions but never block", false)
  .action(async (opts: Record<string, unknown>) => {
    try {
      const policy = resolvePolicy(opts["config"] as string | undefined, opts["failOpen"] as boolean);
      const rules = createRules(policy);
      if (rules.length === 0) console.error("[mcp-guard] Warning: no rules enabled");

      const proxy = new McpHttpProxy(
        {
          mode: "http",
          upstream: opts["upstream"] as string,
          port: parseInt(opts["port"] as string, 10),
          host: (opts["host"] as string) ?? "127.0.0.1",
          verbose: opts["verbose"] as boolean,
          failOpen: opts["failOpen"] as boolean,
          dryRun: opts["dryRun"] as boolean,
          configPath: opts["config"] as string | undefined,
        },
        policy,
        rules,
      );

      await proxy.start();

      // Keep process alive
      const handleSignal = () => {
        proxy.stop().then(() => process.exit(0));
      };
      process.on("SIGTERM", handleSignal);
      process.on("SIGINT", handleSignal);
    } catch (err) {
      console.error(`[mcp-guard] Fatal: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  });

program.parse();
