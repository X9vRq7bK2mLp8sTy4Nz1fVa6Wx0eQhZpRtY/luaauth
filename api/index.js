const express = require('express');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');
const connectToMongo = require('../mongo.js');          // fixed path
const { base64Encode, hmacSha256 } = require('../encryption.js'); // fixed path
const { isAllowedUA } = require('../utils.js');        // fixed path

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..')));  // serve static files from root

const MONGO_URI = process.env.MONGO_URI;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

let db = null;
let initPromise = null;

async function initDb() {
  if (db) return db;
  if (!initPromise) {
    initPromise = (async () => {
      try {
        db = await connectToMongo(MONGO_URI);
        const admins = db.collection('secure_lua_admins_v3');
        const admin = await admins.findOne({ username: ADMIN_USERNAME });
        if (!admin) {
          const hash = await bcrypt.hash(ADMIN_PASSWORD, 10);
          await admins.insertOne({ username: ADMIN_USERNAME, passwordHash: hash, sessionToken: null });
        }
        return db;
      } catch (err) {
        console.error('Failed to connect to MongoDB:', err);
        throw err;
      }
    })();
  }
  return initPromise;
}

app.use(async (req, res, next) => {
  try {
    await initDb();
    next();
  } catch (err) {
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// admin login
app.post('/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const admins = db.collection('secure_lua_admins_v3');
  const admin = await admins.findOne({ username });
  if (!admin || !await bcrypt.compare(password, admin.passwordHash)) {
    return res.json({ error: 'Invalid credentials' });
  }
  const sessionToken = uuid();
  await admins.updateOne({ username }, { $set: { sessionToken } });
  res.json({ sessionToken });
});

// create script
app.post('/admin/create', async (req, res) => {
  const { payload } = req.body;
  const sessionToken = req.headers['x-session-token'];
  const admins = db.collection('secure_lua_admins_v3');
  const admin = await admins.findOne({ sessionToken });
  if (!admin) return res.status(403).json({ error: 'Unauthorized' });
  const scripts = db.collection('secure_lua_scripts_v3');
  const id = uuid();
  await scripts.insertOne({ id, payload });
  const rawUrl = `https://${req.headers.host}/api/raw/${id}`;
  res.json({ rawUrl });
});

// raw endpoint
app.get('/raw/:id', async (req, res) => {
  const { id } = req.params;
  const userAgent = req.headers['user-agent'];
  if (!isAllowedUA(userAgent)) return res.status(403).send('Forbidden');
  const scripts = db.collection('secure_lua_scripts_v3');
  const script = await scripts.findOne({ id });
  if (!script) return res.status(404).send('Not found');

  const token = crypto.randomBytes(16).toString('hex');
  const nonce = crypto.randomBytes(16).toString('hex');
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30000);
  const runs = db.collection('secure_lua_runs_v3');
  await runs.insertOne({ token, nonce, scriptId: id, expiresAt, used: false });

  const host = req.headers.host;

  // loader payload
  const loaderPayload = `
local HttpService = game:GetService("HttpService")
if not HttpService or type(HttpService.RequestAsync) ~= "function" then error("env fail",2) end
local playerId = (game.Players.LocalPlayer and game.Players.LocalPlayer.UserId) or 0
local token = "${token}"
local blobUrl = "https://${host}/api/blob/${id}"
local function fetch()
  local ok, res = pcall(function()
    return HttpService:RequestAsync({Url = blobUrl, Method = "GET", Headers={["User-Agent"]="roblox", ["x-run-token"]=token, ["x-player-id"]=tostring(playerId)}, Timeout=10})
  end)
  if not ok or not res or res.StatusCode ~= 200 then error("loader fetch failed: "..tostring(res and res.StatusCode or ok),2) end
  return res.Body
end
local oldPrint, oldWarn = print, warn
print = function() end
warn = function() end
local ok, err = pcall(function() local body = fetch() loadstring(body)() end)
print, warn = oldPrint, oldWarn
if not ok then error("tamper/fetch fail: "..tostring(err),2) end
`;

  const obfuscatedLoader = base64Encode(loaderPayload);
  const loader = `
-- base64 wrapper
local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local function b64decode(s)
  s = string.gsub(s, '[^'..b..'=]', '')
  return (s:gsub('.', function(x)
    if x=='=' then return '' end
    local r,f='',(b:find(x)-1)
    for i=6,1,-1 do r=r..(f%2^i-f%2^(i-1)>0 and '1' or '0') end
    return r;
  end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
    if #x~=8 then return '' end
    local c=0
    for i=1,8 do c=c + (x:sub(i,i)=='1' and 2^(8-i) or 0) end
    return string.char(c)
  end))
end
local encoded = "${obfuscatedLoader}"
local fn, err = loadstring(b64decode(encoded))
if not fn then error("loader decode failed: "..tostring(err),2) end
fn()
`;

  res.setHeader('Content-Type', 'text/plain');
  res.send(loader);
});

// blob endpoint
app.get('/blob/:id', async (req, res) => {
  const { id } = req.params;
  const userAgent = req.headers['user-agent'];
  if (!isAllowedUA(userAgent)) return res.status(403).send('Forbidden');
  const token = req.headers['x-run-token'];
  const playerId = req.headers['x-player-id'];
  if (!token || !playerId) return res.status(403).send('Missing headers');

  const runs = db.collection('secure_lua_runs_v3');
  const run = await runs.findOneAndUpdate(
    { token, scriptId: id, used: false, expiresAt: { $gt: new Date() } },
    { $set: { used: true, usedAt: new Date(), usedBy: playerId } },
    { returnDocument: 'before' }
  );
  if (!run.value) return res.status(403).send('Invalid token');

  const scripts = db.collection('secure_lua_scripts_v3');
  const script = await scripts.findOne({ id });
  if (!script) return res.status(404).send('Not found');

  res.setHeader('Content-Type', 'text/plain');
  res.send(script.payload);
});

module.exports = app;
