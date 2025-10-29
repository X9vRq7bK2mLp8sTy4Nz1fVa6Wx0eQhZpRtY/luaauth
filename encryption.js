// encryption.js - minimal obfuscator wrapper (replace with luraph later)
const crypto = require('crypto');

function obfuscateBase64(code) {
  const b64 = Buffer.from(code, 'utf8').toString('base64');
  // small loader that decodes base64 and runs it
  return `local s='${b64}' local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' local o='' s:gsub('.',function(c)local i=b:find(c)-1 if i then o=o..string.format('%06d',i) end end) local out=(o:gsub('%d%d%d%d%d%d',function(d)return string.char(tonumber(d,2))end)) local fn,err=loadstring(out) if not fn then error('decode fail '..tostring(err),2) end return fn()`;
}

function genToken(len = 16) {
  return crypto.randomBytes(len).toString('hex');
}

module.exports = { obfuscateBase64, genToken };
