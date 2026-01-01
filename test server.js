/**
 * OPTIONAL server example (Node.js + Express + SQLite)
 * USAGE (optional): node server-example/index.js
 *
 * This example accepts POST /hash (application/json) { hash: "<hex>" }
 * and stores it in a SQLite DB. This is OPTIONAL and not used by default.
 *
 * SECURITY NOTES: only accept hashed values (never plaintext passwords).
 * Enforce rate limits / auth in production. Use HTTPS and strong auth.
 */

const express = require("express");
const bodyParser = require("body-parser");
const Database = require("better-sqlite3");

const app = express();
app.use(bodyParser.json({ limit: "2kb" }));

const db = new Database("./pf_hashes.db");
db.exec(
  `CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY, hash TEXT UNIQUE, created_at INTEGER)`
);

const insertStmt = db.prepare(
  "INSERT OR IGNORE INTO hashes (hash, created_at) VALUES (?,?)"
);
const existsStmt = db.prepare(
  "SELECT COUNT(1) as c FROM hashes WHERE hash = ?"
);

app.post("/hash", (req, res) => {
  try {
    const { hash } = req.body;
    if (!hash || typeof hash !== "string" || hash.length !== 64) {
      return res.status(400).json({ error: "invalid_hash" });
    }
    const exists = existsStmt.get(hash);
    if (exists.c > 0) return res.status(200).json({ ok: true, existed: true });
    insertStmt.run(hash, Date.now());
    return res.status(201).json({ ok: true, existed: false });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "server_error" });
  }
});

app.listen(3000, () =>
  console.log(
    "Optional PasswordForge server example running on http://localhost:3000"
  )
);
