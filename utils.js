// utils.js
const UA_PATTERNS = (process.env.ALLOWLISTED_UA_PATTERNS || '')
  .split(',')
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);
const DISALLOW_BROWSER_UA = String(process.env.DISALLOW_BROWSER_UA || 'true') === 'true';

function isExecutorUserAgent(uaHeader) {
  if (!uaHeader) return false;
  const ua = Array.isArray(uaHeader) ? uaHeader.join(' ') : String(uaHeader);
  const raw = ua.toLowerCase();

  if (DISALLOW_BROWSER_UA) {
    const browsers = ['mozilla','chrome','safari','firefox','edge','opera','brave'];
    const isBrowser = browsers.some(b => raw.includes(b));
    if (isBrowser && !raw.includes('roblox') && !raw.includes('executor')) return false;
  }

  return UA_PATTERNS.some(p => raw.includes(p));
}

function json(res, status, obj) {
  res.status(status).json(obj);
}

module.exports = { isExecutorUserAgent, json };
