/**
 * JSON-RPC message framing — supports both Content-Length header protocol
 * and newline-delimited JSON (MCP SDK v1.x default).
 *
 * Security: locks framing mode on first successful parse to prevent
 * dual-mode desynchronization attacks (CSO Finding #5). Validates
 * Content-Length boundaries to prevent message smuggling (CSO Finding #2).
 *
 * Adapted from McpSession.processBuffer() in aiclude.asvs dast.ts:427-451.
 */

import type { JsonRpcMessage } from "./types.js";

/** Maximum allowed Content-Length to prevent memory exhaustion */
const MAX_CONTENT_LENGTH = 10 * 1024 * 1024; // 10 MB

/** Maximum buffer size before forced reset */
const MAX_BUFFER_SIZE = 20 * 1024 * 1024; // 20 MB

type FramingMode = "unknown" | "content-length" | "newline";

export class MessageFramer {
  private buffer = "";
  private mode: FramingMode = "unknown";

  /**
   * Feed raw data from a stream. Returns an array of complete parsed messages.
   * Locks to detected framing mode on first successful parse to prevent
   * mixed-protocol desynchronization attacks.
   */
  feed(chunk: Buffer | string): JsonRpcMessage[] {
    this.buffer += typeof chunk === "string" ? chunk : chunk.toString("utf-8");
    const messages: JsonRpcMessage[] = [];

    // Guard against unbounded buffer growth
    if (this.buffer.length > MAX_BUFFER_SIZE) {
      this.buffer = "";
      throw new Error("Message buffer exceeded maximum size");
    }

    while (this.buffer.length > 0) {
      // Try Content-Length header protocol (if mode allows)
      if (this.mode !== "newline") {
        const headerMatch = this.buffer.match(/^Content-Length:\s*(\d+)\r?\n\r?\n/);
        if (headerMatch) {
          const contentLength = parseInt(headerMatch[1]!, 10);

          // Reject oversized Content-Length
          if (contentLength > MAX_CONTENT_LENGTH) {
            this.buffer = "";
            throw new Error(`Content-Length ${contentLength} exceeds maximum ${MAX_CONTENT_LENGTH}`);
          }

          const headerEnd = headerMatch[0].length;
          if (this.buffer.length < headerEnd + contentLength) break; // incomplete

          const body = this.buffer.substring(headerEnd, headerEnd + contentLength);
          this.buffer = this.buffer.substring(headerEnd + contentLength);

          // Lock to content-length mode on first successful parse
          this.mode = "content-length";

          const parsed = tryParseJson(body);
          if (parsed) messages.push(parsed);
          continue;
        }
      }

      // Newline-delimited JSON (only if mode allows)
      if (this.mode !== "content-length") {
        const nlIndex = this.buffer.indexOf("\n");
        if (nlIndex === -1) {
          // No newline yet — wait for more data
          break;
        }
        const line = this.buffer.substring(0, nlIndex).trim();
        this.buffer = this.buffer.substring(nlIndex + 1);
        if (line.length > 0 && line.startsWith("{")) {
          const parsed = tryParseJson(line);
          if (parsed) {
            // Lock to newline mode on first successful parse
            this.mode = "newline";
            messages.push(parsed);
          }
        }
        // Skip non-JSON lines (empty lines, garbage)
        continue;
      }

      // If locked to content-length mode but no header found, wait for more data
      break;
    }

    return messages;
  }

  /** Reset the internal buffer and mode detection */
  reset(): void {
    this.buffer = "";
    this.mode = "unknown";
  }

  /** Get the current framing mode (for testing/diagnostics) */
  getMode(): FramingMode {
    return this.mode;
  }

  /** Serialize a message to newline-delimited JSON (MCP SDK convention) */
  static serialize(message: JsonRpcMessage): string {
    return JSON.stringify(message) + "\n";
  }
}

function tryParseJson(raw: string): JsonRpcMessage | null {
  try {
    const obj = JSON.parse(raw) as Record<string, unknown>;
    if (obj["jsonrpc"] === "2.0") {
      return obj as unknown as JsonRpcMessage;
    }
    return null;
  } catch {
    return null;
  }
}
