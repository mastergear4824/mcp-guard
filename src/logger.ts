type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private threshold: number;

  constructor(level: LogLevel = "info") {
    this.threshold = LEVEL_ORDER[level];
  }

  debug(msg: string, data?: Record<string, unknown>): void {
    this.log("debug", msg, data);
  }

  info(msg: string, data?: Record<string, unknown>): void {
    this.log("info", msg, data);
  }

  warn(msg: string, data?: Record<string, unknown>): void {
    this.log("warn", msg, data);
  }

  error(msg: string, data?: Record<string, unknown>): void {
    this.log("error", msg, data);
  }

  private log(level: LogLevel, msg: string, data?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < this.threshold) return;
    const entry = {
      ts: new Date().toISOString(),
      level,
      msg,
      ...data,
    };
    // Always stderr — stdout is the MCP JSON-RPC pipe
    process.stderr.write(JSON.stringify(entry) + "\n");
  }
}
