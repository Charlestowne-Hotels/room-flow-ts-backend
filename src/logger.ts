// src/log.ts
// ==========================================
// LEVELED LOGGING (#14) — frontend
// error and warn always emit. info and debug are off unless debug mode is on.
//
// Turn it on:  add ?debug=1 to the URL (persists across reloads)
// Turn it off: ?debug=0
//
// Never pass guest names, emails, or reservation detail to info/debug — the
// browser console is shoulder-surfable and gets pasted into tickets.
// ==========================================
const KEY = 'pf_debug';

const resolveDebug = (): boolean => {
  try {
    const param = new URLSearchParams(window.location.search).get('debug');
    if (param === '1') { localStorage.setItem(KEY, '1'); return true; }
    if (param === '0') { localStorage.removeItem(KEY); return false; }
    return localStorage.getItem(KEY) === '1';
  } catch {
    return false;
  }
};

const debugOn = resolveDebug();

export const log = {
  enabled: debugOn,
  error: (...args: unknown[]) => console.error('[PF]', ...args),
  warn:  (...args: unknown[]) => console.warn('[PF]', ...args),
  info:  (...args: unknown[]) => { if (debugOn) console.log('[PF]', ...args); },
  debug: (...args: unknown[]) => { if (debugOn) console.log('[PF debug]', ...args); },
};

if (debugOn) console.log('[PF] debug logging on — append ?debug=0 to turn off');


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
