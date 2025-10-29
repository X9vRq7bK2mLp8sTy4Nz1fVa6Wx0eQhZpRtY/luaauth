// server.js - minimal, uses only MONGO_URI + ADMIN_USERNAME + ADMIN_PASSWORD from env
require('dotenv').config();
const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { init } = require('./mongo');
const { obfuscateBase64, genToken } = require('./encryption');

const PORT = parseInt(process.env.PORT || '3000', 10);
const RUN_TOKEN_BYTES = 16;
const TOKEN_TTL_MS = 30000;

(async () => {
  const { db, scripts, runs, admins } = await init();
  const app = express();
  app.use(express.json({ limit: '1mb' }));
  app.use(express.static('static'));

  // ensure default admin exists or create from env
  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'admin';
  const existing = await admins.findOne({ username: adminUser });
  if (!existing) {
    const hash = bcrypt.hashSync(adminPass, 8);
    await admins.insertOne({ username: adminUser, passwordHash: hash, createdAt: new Date() });
    console.log('created default admin:', adminUser);
  }

  function baseUrl(req) {
    const proto = req.headers['x-forwarded-proto'] || req.protocol || 'https';
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    return `${proto}://${host}`;
  }

  // admin login (returns session token stored in admin doc)
  app.post('/api/admin/login', async (req, res) => {
    try {
      const { username, password } = req.body || {};
      if (!username || !password) return res.status(400).json({ error: 'missing' });
      const user = await admins.findOne({ username });
      if (!user) return res.status(401).json({ error: 'invalid' });
      if (!bcrypt.compareSync(password, user.passwordHash)) return res.status(401).json({ error: 'invalid' });
      const sessionToken = genToken(12);
      await admins.updateOne({ username }, { $set: { sessionToken, sessionAt: new Date() } });
      return res.json({ ok: true, sessionToken, username });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'internal' });
    }
  });

  // create script (admin only). accepts obfuscated payload (string).
  app.post('/api/create', async (req, res) => {
    try {
      const session = req.headers['x-session-token'] || req.body.sessionToken;
      if (!session) return res.status(401).json({ error: 'unauthenticated' });
      const admin = await admins.findOne({ sessionToken: session });
      if (!admin) return res.status(401).json({ error: 'unauthenticated' });

      const { title, obfCode } = req.body;
      if (!obfCode || typeof obfCode !== 'string') return res.status(400).json({ error: 'missing obfCode' });

      const id = uuidv4();
      await scripts.insertOne({ _id: id, title: title || '(no title)', obfPayload: obfCode, createdAt: new Date() });
      return res.status(201).json({ id, rawUrl: `${baseUrl(req)}/api/raw/${id}` });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ error: 'internal' });
    }
  });

  // raw: returns obf-loader and creates one-use run token. no browser UA checks here (you asked to remove complex env vars)
  app.get('/api/raw/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const script = await scripts.findOne({ _id: id });
      if (!script) return res.status(404).send('not found');

      const token = genToken(RUN_TOKEN_BYTES);
      const now = Date.now();
      const expiresAt = new Date(now + TOKEN_TTL_MS);
      await runs.insertOne({ token, scriptId: id, used: false, createdAt: new Date(now), expiresAt });

      const blobUrl = `${baseUrl(req)}/api/blob/${id}`;
      const loaderPlain = `
local HttpService = game:GetService("HttpService")
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
  if not ok or not res or res.StatusCode ~= 200 then error("loader fetch failed: "..tostring(res and res.StatusCode or ok),2) end
  return res.Body
end
local oldPrint,oldWarn=print,warn
print=function() end; warn=function() end
local ok,err = pcall(function() local body = fetch(); loadstring(body)() end)
print=oldPrint; warn=oldWarn
if not ok then error("tamper/fetch fail: "..tostring(err),2) end
`.trim();

      const obfLoader = obfuscateBase64(loaderPlain);
      res.setHeader('content-type', 'text/plain');
      return res.status(200).send(obfLoader);
    } catch (e) {
      console.error(e);
      return res.status(500).send('internal');
    }
  });

  // blob: consume token atomically and return obf payload
  app.get('/api/blob/:id', async (req, res) => {
    try {
      const id = req.params.id;
      const token = req.headers['x-run-token'];
      if (!token) return res.status(403).end('missing token');

      const now = new Date();
      const filter = { token, scriptId: id, used: false, expiresAt: { $gt: now } };
      const update = { $set: { used: true, usedAt: now } };
      const r = await runs.findOneAndUpdate(filter, update, { returnDocument: 'after' });
      if (!r.value) return res.status(403).end('invalid or used token');

      const script = await scripts.findOne({ _id: id });
      if (!script || !script.obfPayload) return res.status(404).end('payload not found');

      res.setHeader('content-type', 'text/plain');
      return res.status(200).send(script.obfPayload);
    } catch (e) {
      console.error(e);
      return res.status(500).end('internal');
    }
  });

  app.listen(PORT, () => console.log('listening', PORT));
})();
