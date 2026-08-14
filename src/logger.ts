// src/logger.ts
// ==========================================
// LEVELED LOGGING (#14)
// Level comes from LOG_LEVEL (error|warn|info|debug) and defaults to info.
// Render captures stdout, and at this scale having a record of what broke is
// worth more than the log volume. Set LOG_LEVEL=warn to quiet it down, or
// LOG_LEVEL=debug when chasing something specific.
//
// Do not log request bodies or user records here — guest names, emails and
// reservation detail are PII and these lines persist in Render's log store.
// ==========================================
const LEVELS = { error: 0, warn: 1, info: 2, debug: 3 } as const;
type Level = keyof typeof LEVELS;

const configured = (process.env.LOG_LEVEL || 'info').toLowerCase() as Level;
const threshold = LEVELS[configured] ?? LEVELS.info;

const emit = (level: Level, args: unknown[]) => {
  if (LEVELS[level] > threshold) return;
  const line = `[${new Date().toISOString()}] ${level.toUpperCase()}`;
  if (level === 'error') console.error(line, ...args);
  else if (level === 'warn') console.warn(line, ...args);
  else console.log(line, ...args);
};

export const log = {
  error: (...args: unknown[]) => emit('error', args),
  warn:  (...args: unknown[]) => emit('warn', args),
  info:  (...args: unknown[]) => emit('info', args),
  debug: (...args: unknown[]) => emit('debug', args),
};

// ==========================================
// Single exit point for route failures. Previously every catch block returned
// e.message to the client and logged nothing server-side, so a user reporting
// "it failed" left no trace. This logs full detail with request context, and
// returns the same shape the frontend already expects.
//
// Note: still returns e.message to the client. Hardening that to a generic
// message plus a reference id is a separate decision — it changes what the UI
// displays — so it's deliberately not bundled here.
// ==========================================
export const fail = (req: any, res: any, e: any) => {
  log.error(`${req?.method} ${req?.originalUrl} —`, e?.message, e?.stack);
  res.status(500).json({ error: e?.message });
};
