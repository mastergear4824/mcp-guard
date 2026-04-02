import { describe, it, expect } from "vitest";
import { MessageFramer } from "../framing.js";

describe("MessageFramer", () => {
  it("should parse newline-delimited JSON", () => {
    const framer = new MessageFramer();
    const msg = { jsonrpc: "2.0" as const, id: 1, method: "test", params: {} };
    const result = framer.feed(JSON.stringify(msg) + "\n");
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(msg);
  });

  it("should parse Content-Length framed messages", () => {
    const framer = new MessageFramer();
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "test" });
    const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    const result = framer.feed(frame);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ jsonrpc: "2.0", id: 1, method: "test" });
  });

  it("should handle chunked delivery", () => {
    const framer = new MessageFramer();
    const msg = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "foo" }) + "\n";
    // Split in the middle
    const part1 = msg.substring(0, 10);
    const part2 = msg.substring(10);

    expect(framer.feed(part1)).toHaveLength(0);
    const result = framer.feed(part2);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual({ jsonrpc: "2.0", id: 1, method: "foo" });
  });

  it("should handle multiple messages in one chunk", () => {
    const framer = new MessageFramer();
    const msg1 = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "a" }) + "\n";
    const msg2 = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "b" }) + "\n";
    const result = framer.feed(msg1 + msg2);
    expect(result).toHaveLength(2);
    expect(result[0]).toEqual({ jsonrpc: "2.0", id: 1, method: "a" });
    expect(result[1]).toEqual({ jsonrpc: "2.0", id: 2, method: "b" });
  });

  it("should skip non-jsonrpc lines", () => {
    const framer = new MessageFramer();
    const result = framer.feed('{"key": "value"}\n');
    expect(result).toHaveLength(0);
  });

  it("should handle Buffer input", () => {
    const framer = new MessageFramer();
    const msg = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "test" }) + "\n";
    const result = framer.feed(Buffer.from(msg));
    expect(result).toHaveLength(1);
  });

  it("should handle Content-Length with chunked delivery", () => {
    const framer = new MessageFramer();
    const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "test" });
    const frame = `Content-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`;
    // Deliver header and partial body
    const part1 = frame.substring(0, 25);
    const part2 = frame.substring(25);

    expect(framer.feed(part1)).toHaveLength(0);
    const result = framer.feed(part2);
    expect(result).toHaveLength(1);
  });

  it("should round-trip with serialize", () => {
    const framer = new MessageFramer();
    const original = { jsonrpc: "2.0" as const, id: 42, method: "tools/list", params: {} };
    const serialized = MessageFramer.serialize(original);
    const result = framer.feed(serialized);
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(original);
  });

  it("should parse response messages", () => {
    const framer = new MessageFramer();
    const response = { jsonrpc: "2.0", id: 1, result: { tools: [] } };
    const result = framer.feed(JSON.stringify(response) + "\n");
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(response);
  });

  it("should parse notification messages (no id)", () => {
    const framer = new MessageFramer();
    const notification = { jsonrpc: "2.0", method: "notifications/initialized" };
    const result = framer.feed(JSON.stringify(notification) + "\n");
    expect(result).toHaveLength(1);
    expect(result[0]).toEqual(notification);
  });
});
