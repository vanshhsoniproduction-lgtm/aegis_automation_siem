import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { LogType, SIEMLog } from './src/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize SQLite
const dbPath = path.join(__dirname, 'siem.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS attack_patterns (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL,
      description TEXT,
      severity TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_proof (
      id TEXT PRIMARY KEY,
      action TEXT NOT NULL,
      target TEXT NOT NULL,
      reason TEXT,
      confidence REAL,
      proof TEXT,
      status TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // In-memory log store for demo purposes
  const logs: SIEMLog[] = [];

  // API Routes
  app.get('/api/logs', (req, res) => {
    res.json(logs);
  });

  app.post('/api/logs', (req, res) => {
    const log: SIEMLog = {
      id: Math.random().toString(36).substring(7),
      timestamp: new Date().toISOString(),
      ...req.body
    };
    logs.push(log);
    res.status(201).json(log);
  });

  // Attack Patterns Endpoints
  app.get('/api/patterns', (req, res) => {
    db.all('SELECT * FROM attack_patterns', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  app.post('/api/patterns', (req, res) => {
    const { type, description, severity } = req.body;
    db.run(
      'INSERT INTO attack_patterns (type, description, severity) VALUES (?, ?, ?)',
      [type, description, severity],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID });
      }
    );
  });

  // SOAR Confirmation & Proof Endpoints
  app.post('/api/soar/pending', (req, res) => {
    const { id, action, target, reason, confidence, proof } = req.body;
    db.run(
      'INSERT INTO audit_proof (id, action, target, reason, confidence, proof, status) VALUES (?, ?, ?, ?, ?, ?, "pending")',
      [id, action, target, reason, confidence, JSON.stringify(proof)],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ status: 'pending' });
      }
    );
  });

  app.get('/api/soar/pending', (req, res) => {
    db.all('SELECT * FROM audit_proof WHERE status = "pending"', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  app.post('/api/soar/confirm', (req, res) => {
    const { id, status } = req.body; // status: 'approved' | 'rejected'
    db.run(
      'UPDATE audit_proof SET status = ? WHERE id = ?',
      [status, id],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id, status });
      }
    );
  });

  app.get('/api/soar/audit', (req, res) => {
    db.all('SELECT * FROM audit_proof ORDER BY timestamp DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', logCount: logs.length });
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
