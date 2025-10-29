const express = require('express');
const { v4: uuid } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const connectToMongo = require('./mongo.js');
const { base64Encode, hmacSha256 } = require('./encryption.js');
const { isAllowedUA } = require('./utils.js');

const app = express();
app.use(express.json());

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

app.post('/api/admin/login', async (req, res) => {
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

app.post('/api/admin/create', async (req, res) => {
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

app.get('/api/raw/:id', async (req, res) => {
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
  const loader = `
-- Suppress print and warn
local oldprint = print
local oldwarn = warn
print = function() end
warn = function() end

-- Environment checks
if not game or not game.Players or not game.Players.LocalPlayer then return end

local playerId = tostring(game.Players.LocalPlayer.UserId)

local token = "${token}"
local nonce = "${nonce}"
local ts = os.time()

local data = token .. nonce .. playerId .. tostring(ts)
local proof = hmac_sha256(token, data)  -- Implement pure Lua HMAC-SHA256 here or assume executor provides it

local headers = {
  ["x-run-token"] = token,
  ["x-run-proof"] = proof,
  ["x-ts"] = tostring(ts),
  ["x-player-id"] = playerId
}

local response = game:HttpGetAsync("https://${host}/api/blob/${id}", headers)  -- Adjust to actual RequestAsync if needed

if not response or response.StatusCode ~= 200 then 
  oldprint("Error: " .. (response and response.StatusCode or "No response"))
  return 
end

local body = response.Body

-- Restore print and warn
print = oldprint
warn = oldwarn

loadstring(body)()
`;
  const obfuscatedLoader = base64Encode(loader);
  res.setHeader('Content-Type', 'text/plain');
  res.send(obfuscatedLoader);
});

app.get('/api/blob/:id', async (req, res) => {
  const { id } = req.params;
  const userAgent = req.headers['user-agent'];
  if (!isAllowedUA(userAgent)) return res.status(403).send('Forbidden');
  const token = req.headers['x-run-token'];
  const proof = req.headers['x-run-proof'];
  const tsStr = req.headers['x-ts'];
  const playerId = req.headers['x-player-id'];
  if (!token || !proof || !tsStr || !playerId) return res.status(403).send('Missing headers');
  const ts = parseInt(tsStr);
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - ts) > 5) return res.status(403).send('Invalid timestamp');
  const runs = db.collection('secure_lua_runs_v3');
  const run = await runs.findOneAndUpdate(
    { token, scriptId: id, used: false, expiresAt: { $gt: new Date() } },
    { $set: { used: true, usedAt: new Date(), usedBy: playerId } },
    { returnDocument: 'before' }
  );
  if (!run.value) return res.status(403).send('Invalid token');
  const nonce = run.value.nonce;
  const data = token + nonce + playerId + tsStr;
  const expected = hmacSha256(token, data);
  if (expected !== proof) return res.status(403).send('Invalid proof');
  const scripts = db.collection('secure_lua_scripts_v3');
  const script = await scripts.findOne({ id });
  if (!script) return res.status(404).send('Not found');
  res.setHeader('Content-Type', 'text/plain');
  res.send(script.payload);
});

module.exports = app;
