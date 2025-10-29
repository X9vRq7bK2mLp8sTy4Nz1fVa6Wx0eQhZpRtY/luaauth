// server.js
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { init } = require('./mongo');
const { obfuscateBase64, genToken } = require('./encryption');
const { isExecutorUserAgent, json } = require('./utils');

const PORT = parseInt(process.env.PORT || '3000', 10);
const RUN_TOKEN_BYTES = parseInt(process.env.RUN_TOKEN_BYTES || '16', 10);
const TOKEN_TTL_MS = parseInt(process.env.TOKEN_TTL_MS || '30000', 10);
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin';

(async function main() {
  const { db, scripts, runs, admins, names } = await init();

  // ensure admin user exists (create default admin:admin hashed)
  const existing = await admins.findOne({ username: ADMIN_USERNAME });
  if (!existing) {
    const hash = bcrypt.hashSync(ADMIN_PASSWORD, 8);
    await admins.insertOne({ username: ADMIN_USERNAME, passwordHash: hash, createdAt: new Date(), role: 'admin' });
    console.log('default admin created:', ADMIN_USERNAME);
  }

  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static('static'));

  function baseUrl(req) {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return `${proto}://${host}`;
  }

  // admin login (simple)
  app.post('/api/admin/login', async (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password) return json(res, 400, { error: 'missing' });
      const user = await admins.findOne({ username });
      if (!user) return json(res, 401, { error: 'invalid' });
      if (!bcrypt.compareSync(password, user.passwordHash)) return json(res, 401, { error: 'invalid' });
      // simple token: return a short-lived session token in response (not a JWT)
      const sessionToken = genToken(12);
      // store session token in admins collection for simplicity
      await admins.updateOne({ username }, { $set: { sessionToken, sessionAt: new Date() } });
      return json(res, 200, { ok: true, sessionToken, username });
    } catch (err) {
      console.error(err);
      return json(res, 500, { error: 'internal' });
    }
  });

  // admin create: expects already-obfuscated payload (we don't store plaintext)
  app.post('/api/create', async (req, res) => {
    try {
      const sessionToken = req.headers['x-session-token'] || req.body.sessionToken;
      if (!sessionToken) return json(res, 401, { error: 'unauthenticated' });
      const admin = await admins.findOne({ sessionToken });
      if (!admin) return json(res, 401, { error: 'unauthenticated' });

      const { title, obfCode } = req.body;
      if (!obfCode || typeof obfCode !== 'string') return json(res, 400, { error: 'missing obfCode' });

      const id = uuidv4();
      const doc = {
        _id: id,
        title: title || '(no title)',
        obfPayload: obfCode,
        createdAt: new Date()
      };
      // write the script into YOUR existing scripts collection (SCRIPTS_COLLECTION)
      // NOTE: our mongo.init provided 'scripts' variable pointing at that collection
      await scripts.insertOne(doc);
      return json(res, 201, { id, rawUrl: `${baseUrl(req)}/api/raw/${id}` });
    } catch (err) {
      console.error('create error', err && err.stack ? err.stack : err);
      return json(res, 500, { error: 'internal' });
    }
  });

  // raw: returns obf-loader (only to executor UA). creates one-use run token in runs collection.
  app.get('/api/raw/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const script = await scripts.findOne({ _id: id });
      if (!script) return res.status(404).send('not found');

      // UA check
      const ua = req.headers['user-agent'];
      if (!isExecutorUserAgent(ua)) {
        return res.status(403).send('access denied');
      }

      const token = genToken(RUN_TOKEN_BYTES);
      const now = Date.now();
      const expiresAt = new Date(now + TOKEN_TTL_MS);

      // insert run token doc
      await runs.insertOne({
        token,
        scriptId: id,
        used: false,
        createdAt: new Date(now),
        expiresAt
      });

      // build blob url (loader will call this with header x-run-token and x-player-id)
      const blobUrl = `${baseUrl(req)}/api/blob/${id}`;

      // loader plaintext (does env checks, sends headers, suppresses prints)
      const loaderPlain = `
local HttpService = game:GetService("HttpService")
-- basic environment checks
if not HttpService or type(HttpService.RequestAsync) ~= "function" then error("env fail",2) end
local playerId = (game.Players.LocalPlayer and game.Players.LocalPlayer.UserId) or 0

local function fetch()
  local ok,res = pcall(function()
    return HttpService:RequestAsync({
      Url = "${blobUrl}",
      Method = "GET",
      Headers = {
        ["User-Agent"] = "roblox",
        ["x-run-token"] = "${token}",
        ["x-player-id"] = tostring(playerId)
      },
      Timeout = 10
    })
  end)
  if not ok or not res or res.StatusCode ~= 200 then
    error("loader fetch failed: "..tostring(res and res.StatusCode or ok), 2)
  end
  return res.Body
end

local oldPrint, oldWarn = print,warn
print = function() end; warn = function() end

local ok, err = pcall(function()
  local body = fetch()
  loadstring(body)()
end)

print = oldPrint; warn = oldWarn
if not ok then error("tamper/fetch fail: "..tostring(err), 2) end
`.trim();

      // obfuscate loader before returning
      const obfLoader = obfuscateBase64(loaderPlain);

      res.setHeader('content-type', 'text/plain');
      return res.status(200).send(obfLoader);
    } catch (err) {
      console.error('raw error', err && err.stack ? err.stack : err);
      return res.status(500).send('internal');
    }
  });

  // blob: consume token atomically and return obf payload
  app.get('/api/blob/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const token = req.headers['x-run-token'];
      const playerIdHeader = req.headers['x-player-id'] || '0';
      const ua = req.headers['user-agent'];

      if (!isExecutorUserAgent(ua)) {
        return res.status(403).end('access denied');
      }
      if (!token) return res.status(403).end('missing token');

      const now = new Date();
      const filter = { token, scriptId: id, used: false, expiresAt: { $gt: now } };
      const update = { $set: { used: true, usedAt: now, usedBy: playerIdHeader } };

      const r = await runs.findOneAndUpdate(filter, update, { returnDocument: 'after' });
      if (!r.value) {
        return res.status(403).end('invalid or used token');
      }

      const script = await scripts.findOne({ _id: id });
      if (!script || !script.obfPayload) return res.status(404).end('payload not found');

      res.setHeader('content-type', 'text/plain');
      return res.status(200).send(script.obfPayload);
    } catch (err) {
      console.error('blob error', err && err.stack ? err.stack : err);
      return res.status(500).end('internal');
    }
  });

  // admin: list runs (for debugging)
  app.get('/api/admin/runs', async (req, res) => {
    const session = req.headers['x-session-token'];
    const admin = await admins.findOne({ sessionToken: session });
    if (!admin) return json(res, 401, { error: 'unauthorized' });
    const list = await runs.find({}).sort({ createdAt: -1 }).limit(200).toArray();
    return json(res, 200, list);
  });

  app.listen(PORT, () => console.log('listening', PORT));
})();
