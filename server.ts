import express from "express";
import { createServer as createViteServer } from "vite";
import Database from "better-sqlite3";
import path from "path";

const db = new Database("vault.db");

// Initialize database
db.exec(`
  CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT,
    email TEXT,
    phone TEXT,
    backup_code TEXT,
    password TEXT NOT NULL,
    custom_fields TEXT,
    signature TEXT, -- HMAC-SHA256 of the entry's encrypted data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    content TEXT,
    image TEXT, -- Base64 encoded image
    link TEXT,
    code TEXT,
    signature TEXT, -- HMAC-SHA256 of the note's encrypted data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS qrcodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL,
    username TEXT,
    content TEXT NOT NULL,
    signature TEXT, -- HMAC-SHA256 of the QR code's encrypted data
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );

  CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    user_handle TEXT NOT NULL
  );
`);

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: '50mb' })); // Increase limit for base64 images

  // Settings API (for Master Salt)
  app.get("/api/settings/:key", (req, res) => {
    try {
      const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(req.params.key);
      res.json({ value: row ? (row as any).value : null });
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch setting" });
    }
  });

  app.post("/api/settings", (req, res) => {
    const { key, value } = req.body;
    try {
      db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").run(key, value);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to save setting" });
    }
  });

  // WebAuthn Routes
  app.post("/api/webauthn/register", (req, res) => {
    const { id, publicKey, userHandle } = req.body;
    try {
      db.prepare("INSERT OR REPLACE INTO webauthn_credentials (id, public_key, user_handle) VALUES (?, ?, ?)").run(id, publicKey, userHandle);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to register credential" });
    }
  });

  app.get("/api/webauthn/credentials", (req, res) => {
    try {
      const credentials = db.prepare("SELECT * FROM webauthn_credentials").all();
      res.json(credentials);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch credentials" });
    }
  });

  // Vault API
  app.get("/api/passwords", (req, res) => {
    try {
      const entries = db.prepare("SELECT * FROM vault_entries ORDER BY created_at DESC").all();
      const formatted = entries.map(p => ({
        ...p,
        custom_fields: p.custom_fields ? JSON.parse(p.custom_fields) : []
      }));
      res.json(formatted);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch entries" });
    }
  });

  app.post("/api/passwords", (req, res) => {
    const { service, username, email, phone, backup_code, password, custom_fields, signature } = req.body;
    if (!service || !password) {
      return res.status(400).json({ error: "Service and Password are required" });
    }
    try {
      const customFieldsJson = JSON.stringify(custom_fields || []);
      const info = db.prepare(`
        INSERT INTO vault_entries (service, username, email, phone, backup_code, password, custom_fields, signature) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(service, username, email, phone, backup_code, password, customFieldsJson, signature);
      res.json({ id: info.lastInsertRowid });
    } catch (error) {
      res.status(500).json({ error: "Failed to save entry" });
    }
  });

  app.put("/api/passwords/:id", (req, res) => {
    const { id } = req.params;
    const { service, username, email, phone, backup_code, password, custom_fields, signature } = req.body;
    try {
      const customFieldsJson = JSON.stringify(custom_fields || []);
      db.prepare(`
        UPDATE vault_entries 
        SET service = ?, username = ?, email = ?, phone = ?, backup_code = ?, password = ?, custom_fields = ?, signature = ?
        WHERE id = ?
      `).run(service, username, email, phone, backup_code, password, customFieldsJson, signature, id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to update entry" });
    }
  });

  app.delete("/api/passwords/:id", (req, res) => {
    const { id } = req.params;
    try {
      db.prepare("DELETE FROM vault_entries WHERE id = ?").run(id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete entry" });
    }
  });

  // Notes API
  app.get("/api/notes", (req, res) => {
    try {
      const notes = db.prepare("SELECT * FROM notes ORDER BY created_at DESC").all();
      res.json(notes);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch notes" });
    }
  });

  app.post("/api/notes", (req, res) => {
    const { title, content, image, link, code, signature } = req.body;
    try {
      const info = db.prepare("INSERT INTO notes (title, content, image, link, code, signature) VALUES (?, ?, ?, ?, ?, ?)").run(title, content, image, link, code, signature);
      res.json({ id: info.lastInsertRowid });
    } catch (error) {
      res.status(500).json({ error: "Failed to save note" });
    }
  });

  app.delete("/api/notes/:id", (req, res) => {
    try {
      db.prepare("DELETE FROM notes WHERE id = ?").run(req.params.id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete note" });
    }
  });

  // QR Codes API
  app.get("/api/qrcodes", (req, res) => {
    try {
      const qrcodes = db.prepare("SELECT * FROM qrcodes ORDER BY created_at DESC").all();
      res.json(qrcodes);
    } catch (error) {
      res.status(500).json({ error: "Failed to fetch QR codes" });
    }
  });

  app.post("/api/qrcodes", (req, res) => {
    const { service, username, content, signature } = req.body;
    try {
      const info = db.prepare("INSERT INTO qrcodes (service, username, content, signature) VALUES (?, ?, ?, ?)").run(service, username, content, signature);
      res.json({ id: info.lastInsertRowid });
    } catch (error) {
      res.status(500).json({ error: "Failed to save QR code" });
    }
  });

  app.delete("/api/qrcodes/:id", (req, res) => {
    try {
      db.prepare("DELETE FROM qrcodes WHERE id = ?").run(req.params.id);
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Failed to delete QR code" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static("dist"));
    app.get("*", (req, res) => {
      res.sendFile(path.resolve("dist/index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    // Silent startup
  });
}

startServer();
