// mongo.js
const { MongoClient } = require('mongodb');
const uri = process.env.MONGO_URI;
if (!uri) throw new Error('MONGO_URI required');

const client = new MongoClient(uri, {});

async function init() {
  await client.connect();
  const db = client.db(process.env.DB_NAME || 'lua_protect_min');

  // safe unique collection names (defaults)
  const scripts = db.collection(process.env.SCRIPTS_COLLECTION || 'lua_protect_scripts_min'); // read/write if you use create
  const runs = db.collection(process.env.RUNS_COLLECTION || 'lua_protect_runs_min');
  const admins = db.collection(process.env.ADMINS_COLLECTION || 'lua_protect_admins_min');

  // TTL index for runs (expiresAt) - expireAfterSeconds 0
  await runs.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  return { db, scripts, runs, admins };
}

module.exports = { init, client };
