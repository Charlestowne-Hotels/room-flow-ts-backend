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
    // localStorage throws outright in some privacy modes. A logger must never
    // be able to crash the app on load.
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
