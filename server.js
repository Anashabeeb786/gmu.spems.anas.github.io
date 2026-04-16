const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const sqlite3 = require("sqlite3").verbose();

const app = express();
const PORT = process.env.PORT || 3000;

const dataDir = path.join(__dirname, "data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}
const dbPath = path.join(dataDir, "spems.db");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL
    )
  `);
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "spems-auth", db: "sqlite" });
});

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    const cleanName = String(name || "").trim();
    const cleanEmail = String(email || "").trim().toLowerCase();
    const cleanPassword = String(password || "");

    if (!cleanName || !cleanEmail || !cleanPassword) {
      return res.status(400).json({ ok: false, message: "Missing required fields" });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(cleanEmail)) {
      return res.status(400).json({ ok: false, message: "Invalid email format" });
    }
    if (cleanPassword.length < 6) {
      return res.status(400).json({ ok: false, message: "Password must be at least 6 characters" });
    }

    const passwordHash = await bcrypt.hash(cleanPassword, 10);

    db.run(
      "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
      [cleanName, cleanEmail, passwordHash, new Date().toISOString()],
      function onInsert(err) {
        if (err) {
          if (err.message && err.message.includes("UNIQUE")) {
            return res.status(409).json({ ok: false, message: "User already exists with this email" });
          }
          return res.status(500).json({ ok: false, message: "Failed to register user" });
        }
        return res.json({ ok: true, user: { id: this.lastID, name: cleanName, email: cleanEmail } });
      }
    );
  } catch (error) {
    return res.status(500).json({ ok: false, message: "Unexpected server error" });
  }
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body || {};
  const cleanEmail = String(email || "").trim().toLowerCase();
  const cleanPassword = String(password || "");

  if (!cleanEmail || !cleanPassword) {
    return res.status(400).json({ ok: false, message: "Email and password are required" });
  }

  db.get("SELECT id, name, email, password_hash FROM users WHERE email = ?", [cleanEmail], async (err, row) => {
    if (err) {
      return res.status(500).json({ ok: false, message: "Failed to login" });
    }
    if (!row) {
      return res.status(401).json({ ok: false, message: "Invalid email or password" });
    }

    const matches = await bcrypt.compare(cleanPassword, row.password_hash);
    if (!matches) {
      return res.status(401).json({ ok: false, message: "Invalid email or password" });
    }

    return res.json({
      ok: true,
      user: {
        id: row.id,
        name: row.name,
        email: row.email
      }
    });
  });
});

app.listen(PORT, () => {
  console.log(`SPEMS auth server running on http://localhost:${PORT}`);
});
