import { redactSecrets } from './redact.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'silent';

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  silent: 100,
};

export interface LoggerOptions {
  level?: LogLevel;
  /** Sink for rendered lines. Defaults to stderr for warn/error, stdout otherwise. */
  sink?: (line: string, level: LogLevel) => void;
  /** Include ISO timestamps on every line. */
  timestamps?: boolean;
  /** Emit JSON lines instead of pretty text. */
  json?: boolean;
}

export interface LogFields {
  [key: string]: unknown;
}

/**
 * Structured logger.
 *
 * All messages pass through secret redaction before they reach a sink, so a
 * token accidentally interpolated into a log message cannot be persisted.
 */
export class Logger {
  private level: LogLevel;
  private readonly sink: (line: string, level: LogLevel) => void;
  private readonly timestamps: boolean;
  private readonly json: boolean;

  constructor(options: LoggerOptions = {}) {
    this.level = options.level ?? 'info';
    this.sink =
      options.sink ??
      ((line, lvl) => {
        if (lvl === 'error' || lvl === 'warn') process.stderr.write(`${line}\n`);
        else process.stdout.write(`${line}\n`);
      });
    this.timestamps = options.timestamps ?? false;
    this.json = options.json ?? false;
  }

  setLevel(level: LogLevel): void {
    this.level = level;
  }

  getLevel(): LogLevel {
    return this.level;
  }

  child(): Logger {
    return new Logger({
      level: this.level,
      sink: this.sink,
      timestamps: this.timestamps,
      json: this.json,
    });
  }

  debug(message: string, fields?: LogFields): void {
    this.write('debug', message, fields);
  }
  info(message: string, fields?: LogFields): void {
    this.write('info', message, fields);
  }
  warn(message: string, fields?: LogFields): void {
    this.write('warn', message, fields);
  }
  error(message: string, fields?: LogFields): void {
    this.write('error', message, fields);
  }

  private write(level: LogLevel, message: string, fields?: LogFields): void {
    if (LEVEL_RANK[level] < LEVEL_RANK[this.level]) return;
    const safeMessage = redactSecrets(message);
    if (this.json) {
      this.sink(
        JSON.stringify({
          level,
          message: safeMessage,
          ...(this.timestamps ? { time: new Date().toISOString() } : {}),
          ...(fields ?? {}),
        }),
        level,
      );
      return;
    }
    const prefix = `${this.timestamps ? `[${new Date().toISOString()}] ` : ''}${level.toUpperCase()}`;
    const suffix = fields && Object.keys(fields).length > 0 ? ` ${JSON.stringify(fields)}` : '';
    this.sink(`${prefix} ${safeMessage}${suffix}`, level);
  }
}

export const nullLogger = new Logger({ level: 'silent' });
