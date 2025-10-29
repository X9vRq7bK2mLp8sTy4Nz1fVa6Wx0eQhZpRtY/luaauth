// mongo.js
const { MongoClient } = require('mongodb');
const uri = process.env.MONGO_URI;
if (!uri) throw new Error('MONGO_URI required in env');

const client = new MongoClient(uri, {});
async function init() {
  await client.connect();
  const dbName = process.env.DB_NAME || 'lua_protect_db_full';
  const db = client.db(dbName);

  const scriptsName = process.env.SCRIPTS_COLLECTION || 'existing_scripts_collection';
  const runsName = process.env.RUNS_COLLECTION || 'lua_one_use_runs_full';
  const adminsName = process.env.ADMINS_COLLECTION || 'lua_admins_full';

  const scripts = db.collection(scriptsName);
  const runs = db.collection(runsName);
  const admins = db.collection(adminsName);

  // TTL index to auto-delete expired run tokens (expireAfterSeconds 0)
  await runs.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });

  return { db, scripts, runs, admins, names: { scriptsName, runsName, adminsName } };
}

module.exports = { init, client };
