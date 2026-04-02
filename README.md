# MCP Guard

**Real-time security firewall for AI agents**

MCP Guard is an inline security proxy that sits between MCP clients and servers. It inspects every message in real-time and blocks malicious tool calls before they reach the server.

[![npm version](https://img.shields.io/npm/v/@aiclude/mcp-guard.svg)](https://www.npmjs.com/package/@aiclude/mcp-guard)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Why MCP Guard?

In 2026, **MCP (Model Context Protocol)** has become the de facto standard for AI agents to interact with external systems. Claude, Cursor, Copilot, and other major AI tools use MCP to connect to databases, APIs, file systems, and cloud services.

**But MCP communication is unprotected.**

- **30+ CVEs** reported in Jan–Feb 2026 alone
- **92% exploit probability** with just 10 MCP plugins installed ([VentureBeat](https://venturebeat.com))
- **OWASP MCP Top 10** published — Tool Poisoning, Prompt Injection, Context Spoofing confirmed as real attack vectors

Existing security tools (WAF, SAST, DAST) don't understand MCP protocol semantics. A WAF can see HTTP requests, but it cannot detect MCP-specific attacks like zero-width character hiding in tool descriptions, tool name spoofing, or prompt injection embedded in tool definitions. In stdio mode, traffic doesn't even use HTTP — it's completely off the radar.

> **MCP Guard** inspects all messages in real-time and **blocks dangerous tool calls before they reach the server**.

---

## Quick Start

### Install

```bash
npm install -g @aiclude/mcp-guard
```

### stdio mode — Protect a local MCP server

```bash
mcp-guard -- npx @modelcontextprotocol/server-fetch
```

### HTTP mode — Protect a remote MCP server

```bash
mcp-guard http --upstream http://mcp-server:8080/mcp --port 9090
```

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "fetch-guarded": {
      "command": "npx",
      "args": ["-y", "@aiclude/mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    }
  }
}
```

### Cursor IDE Integration

Add to `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "my-server-guarded": {
      "command": "npx",
      "args": ["-y", "@aiclude/mcp-guard", "--", "npx", "-y", "@some/mcp-server"]
    }
  }
}
```

---

## Key Features

### 3 Security Rule Engines

| Rule | Inspects | Threats Addressed |
|------|----------|-------------------|
| **Tool Poisoning Detection** | Tool definitions from server | Zero-width steganography, prompt injection, homoglyph spoofing, name shadowing |
| **Argument Injection Detection** | Tool call arguments from client | SQL / Command / XSS / Path Traversal / Template injection (21+ patterns) |
| **Data Exfiltration Detection** | Tool responses from server | Credential leaks, system path exposure, stack trace disclosure |

### Multilingual Threat Detection

Detects prompt injection phrases in **English, Korean, Chinese, and Japanese**. Normalizes Cyrillic/Greek homoglyphs to block character-disguise bypass attacks.

### Dual Protocol Support

| Mode | Use Case | Target |
|------|----------|--------|
| **stdio** | Wrap local MCP server processes | Claude Desktop, Cursor, etc. |
| **HTTP** | Reverse proxy for remote MCP servers | Streamable HTTP + Legacy SSE |

### Zero Configuration

Works out of the box with built-in default policies. Customize with YAML policy files when needed.

---

## Protection Coverage

| Tool Definitions (server → client) | Tool Call Arguments (client → server) | Tool Responses (server → client) |
|:-----------------------------------|:--------------------------------------|:---------------------------------|
| Zero-width steganography | SQL Injection | Credential exposure |
| Prompt injection phrases | Command Injection | System path leaks |
| Homoglyph spoofing | Path Traversal | Stack trace exposure |
| HTML comment hiding | XSS | Command exec evidence |
| Base64 encoding hiding | Template Injection | Template injection results |
| Name shadowing | Prompt injection | Credential leaks |
| Multilingual injection | Multilingual injection | |
| Agent manipulation patterns | Zero-width char hiding | |
| InputSchema validation | | |

**CWE Coverage:** CWE-22, CWE-78, CWE-79, CWE-89, CWE-94, CWE-200, CWE-209

**OWASP MCP Top 10:** Tool Poisoning, Prompt Injection, and more

---

## How It Works

MCP Guard operates as a **transparent proxy** between client and server.

### stdio Mode

> **MCP Client** → *stdio* → **MCP Guard (Proxy)** → *stdio* → **MCP Server (Local)**
>
> All messages pass through the **Rule Engine** for real-time inspection.

### HTTP Mode

> **MCP Client** → *HTTP POST* → **MCP Guard (:9090)** → *HTTP POST* → **MCP Server (Remote)**
>
> Responses (JSON or SSE stream) are inspected before forwarding back to the client.

**Default behavior: Fail-Close.** If the policy engine errors, all traffic is blocked for safety.

---

## CLI Reference

### stdio mode (default)

```bash
mcp-guard [options] -- <server-command> [server-args...]
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--config <path>` | `-c` | YAML policy file path | Built-in defaults |
| `--verbose` | `-v` | Enable debug-level logging | `false` |
| `--fail-open` | | Allow traffic on policy engine error (not recommended) | `false` |
| `--dry-run` | | Log violations without blocking | `false` |
| `--version` | `-V` | Print version | |
| `--help` | `-h` | Print help | |

### HTTP mode

```bash
mcp-guard http [options] --upstream <url>
```

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--upstream <url>` | `-u` | Upstream MCP server URL **(required)** | |
| `--port <number>` | `-p` | Listen port | `9090` |
| `--host <host>` | `-H` | Bind host | `127.0.0.1` |
| `--config <path>` | `-c` | YAML policy file path | Built-in defaults |
| `--verbose` | `-v` | Enable debug-level logging | `false` |
| `--fail-open` | | Allow traffic on policy engine error | `false` |
| `--dry-run` | | Log violations without blocking | `false` |

---

## Policy File

Policy files are written in YAML. Without a policy file, built-in defaults apply.

### Basic Structure

```yaml
version: 1
failMode: closed    # closed (recommended) | open

logging:
  level: info       # debug | info | warn | error
  destination: stderr

rules:
  - id: tool-poisoning
    enabled: true
    severity: critical
    action: block       # block | warn
    type: tool-poisoning

  - id: argument-injection
    enabled: true
    severity: critical
    action: block
    type: argument-injection

  - id: data-exfiltration
    enabled: true
    severity: high
    action: warn        # warn recommended — blocking may break normal flow
    type: data-exfiltration
```

### Tool Poisoning Config

```yaml
config:
  checkZeroWidth: true
  checkInjectionPhrases: true
  checkHtmlComments: true
  checkBase64: true
  checkShadowing: true
  checkInstructionPatterns: true
  maxDescriptionLength: 5000
```

### Argument Injection Config

```yaml
config:
  checkPromptInjection: true
```

SQL, Command, Path Traversal, XSS, and Template Injection checks are always active.

### Data Exfiltration Config

```yaml
config:
  checkCredentials: true
  checkPathExposure: true
  checkStackTraces: true
```

---

## Usage Scenarios

### Evaluate a new MCP server safely

```bash
# Step 1: Dry-run to observe
mcp-guard --dry-run --verbose -- npx @unknown/mcp-server 2>guard.log

# Step 2: Review findings
cat guard.log | grep "DRY-RUN"

# Step 3: Enable blocking if clean
mcp-guard -- npx @unknown/mcp-server
```

### Protect multiple servers in Claude Desktop

```json
{
  "mcpServers": {
    "fetch-guarded": {
      "command": "npx",
      "args": ["-y", "@aiclude/mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-fetch"]
    },
    "github-guarded": {
      "command": "npx",
      "args": ["-y", "@aiclude/mcp-guard", "--", "npx", "-y", "@modelcontextprotocol/server-github"]
    }
  }
}
```

### HTTP security gateway

```bash
mcp-guard http \
  -u http://internal-mcp:8080/mcp \
  -p 9090 -H 0.0.0.0 \
  -c /etc/mcp-guard/policy.yaml
```

### Custom policy with selective rules

```bash
mcp-guard -c my-policy.yaml -- npx @some/mcp-server
```

---

## Understanding Logs

All logs are written to **stderr** in JSON format. stdout is reserved for MCP JSON-RPC communication.

### Startup

```json
{"ts":"...","level":"info","msg":"mcp-guard starting","rules":["tool-poisoning","argument-injection","data-exfiltration"],"failMode":"closed"}
```

### Blocked

```json
{"ts":"...","level":"warn","msg":"BLOCKED server->client","rule":"tool-poisoning","severity":"critical","reason":"Tool \"search\": Zero-width characters detected in description"}
```

### Warning

```json
{"ts":"...","level":"warn","msg":"WARNING server->client","rule":"data-exfiltration","severity":"critical","reason":"Sensitive Data Exposure in tool response (CWE-200)"}
```

### Dry-Run

```json
{"ts":"...","level":"warn","msg":"DRY-RUN WOULD BLOCK client->server","rule":"argument-injection","severity":"critical","reason":"SQL Injection detected (CWE-89)"}
```

---

## Troubleshooting

**"Failed to spawn MCP server"**
— Verify the command after `--` runs independently: `npx @some/mcp-server`

**Legitimate tools being blocked**
1. Run with `--dry-run --verbose` to identify which rule triggers
2. Disable the specific check in a policy file, or change the rule action to `warn`

**No logs visible**
— Logs go to stderr. Redirect: `mcp-guard --verbose -- ... 2>/tmp/guard.log`

**HTTP "Upstream connection failed"**
— Verify upstream is reachable: `curl -v http://mcp-server:8080/mcp`

**SSE stream disconnecting**
— If behind nginx, disable buffering:
```nginx
proxy_buffering off;
proxy_cache off;
```

---

## FAQ

**Does it affect MCP communication speed?**
Barely. Synchronous pattern matching adds microsecond-level latency per message.

**Can I use it without a policy file?**
Yes. Built-in defaults apply: tool-poisoning (block), argument-injection (block), data-exfiltration (warn).

**What is fail-close?**
If the policy engine itself errors, all traffic is blocked for safety. Use `--fail-open` to override (not recommended).

**Does it work on Windows?**
Yes. Uses `cross-spawn` for Windows compatibility.

**Does it support HTTP/SSE MCP servers?**
Yes. Both Streamable HTTP and Legacy HTTP+SSE are supported since v0.2.0.

**How is authentication handled in HTTP mode?**
`Authorization` headers are forwarded to upstream as-is. MCP Guard does not store or modify tokens.

---

## Technical Specifications

| Spec | Details |
|------|---------|
| Language | TypeScript (strict mode, ESM-only) |
| Runtime | Node.js 20+ |
| Bundle Size | ~60KB (single file) |
| Dependencies | 3 (commander, cross-spawn, yaml) |
| Transport | stdio + HTTP (Streamable HTTP, Legacy SSE) |
| Security Rules | 3 engines, 7 detector modules |
| Injection Patterns | 21+ fuzz patterns, 33+ prompt injection phrases (EN/KO/ZH/JA) |
| CWE Coverage | CWE-22, CWE-78, CWE-79, CWE-89, CWE-94, CWE-200, CWE-209 |
| OS | macOS, Linux, Windows |

---

## Related

- **[AIclude ASVS](https://vs.aiclude.com)** — AI Agent Security Vulnerability Scanner platform
- **[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)** — MCP security threat classification

---

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.

Copyright 2026 AIclude Inc.
