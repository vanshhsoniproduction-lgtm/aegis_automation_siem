import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import sqlite3 from 'sqlite3';
import { fileURLToPath } from 'url';
import { LogType, SIEMLog } from './src/types.ts';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

  db.run(`
    CREATE TABLE IF NOT EXISTS user_profile (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      username TEXT DEFAULT 'Operator',
      role TEXT DEFAULT 'Security Analyst',
      avatar_seed TEXT DEFAULT 'secure_1'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS blocked_ips (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ip TEXT NOT NULL UNIQUE,
      reason TEXT,
      blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      active INTEGER DEFAULT 1
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS scan_history (
      id TEXT PRIMARY KEY,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      result JSON,
      terminal_log JSON
    )
  `);

  // Seed data
  db.get('SELECT COUNT(*) as count FROM attack_patterns', (err, row: any) => {
    if (row?.count === 0) {
      const patterns = [
        ['SQL Injection', 'UNION SELECT payloads in HTTP GET params targeting /api/users', 'Critical'],
        ['Brute Force', 'Automated SSH dictionary attack from botnet C2 server', 'High'],
        ['Credential Stuffing', 'Bulk login attempts using leaked credential databases', 'High'],
        ['Lateral Movement', 'Privilege escalation from workstation to domain controller', 'High'],
        ['Data Exfiltration', 'Unusual outbound data volume on port 443 to unknown CDN', 'Critical'],
        ['Reverse Shell', 'Netcat listener detected on non-standard port 4444', 'Critical'],
        ['Port Scanning', 'SYN scan detected across 65535 ports from single source', 'Medium'],
        ['DNS Tunneling', 'Encoded payloads detected in DNS TXT record queries', 'High'],
      ];
      patterns.forEach(p => {
        db.run('INSERT INTO attack_patterns (type, description, severity) VALUES (?, ?, ?)', p);
      });
    }
  });

  db.get('SELECT COUNT(*) as count FROM audit_proof', (err, row: any) => {
    if (row?.count === 0) {
      const history = [
        ['ACT-001', 'BLOCK_IP', '45.122.31.5', 'Automated SQLMap scan targeting auth endpoint', 0.98, 'WAF rule deployed via Cloudflare API', 'approved', '2025-04-15 10:30:00'],
        ['ACT-002', 'BLOCK_IP', '185.220.101.34', 'Tor exit node conducting credential stuffing', 0.95, 'Blocked at network ingress via iptables', 'approved', '2025-04-15 08:22:00'],
        ['ACT-003', 'ISOLATE_SYSTEM', 'WKS-FINANCE-07', 'Cobalt Strike beacon detected in memory', 0.97, 'Isolated via CrowdStrike RTR', 'approved', '2025-04-14 14:20:00'],
        ['ACT-004', 'ALERT', 'admin@corp.io', 'Login from anomalous geolocation (Pyongyang)', 0.85, 'Email notification + MFA challenge issued', 'approved', '2025-04-14 09:15:00'],
        ['ACT-005', 'BLOCK_IP', '102.12.89.4', 'Distributed brute force on /api/v2/auth', 0.99, 'IP added to permanent denylist', 'approved', '2025-04-13 22:45:00'],
        ['ACT-006', 'ALERT', 'svc-backup', 'Service account accessed outside maintenance window', 0.78, 'Logged for SOC review', 'approved', '2025-04-13 03:10:00'],
        ['ACT-007', 'BLOCK_IP', '91.240.118.172', 'Port scan across entire /24 subnet', 0.92, 'Firewall deny rule applied', 'approved', '2025-04-12 18:30:00'],
        ['ACT-008', 'ISOLATE_SYSTEM', 'SRV-DB-PROD-02', 'Suspicious mysqldump to external S3 bucket', 0.94, 'Network segmentation enforced', 'approved', '2025-04-12 11:05:00'],
        ['ACT-009', 'BLOCK_IP', '45.122.31.5', 'Repeat offender — second SQLi campaign', 0.99, 'Permanent block + ISP abuse report', 'approved', '2025-04-11 16:40:00'],
        ['ACT-010', 'ALERT', 'j.smith@corp.io', 'Password spray detected across 50+ accounts', 0.88, 'Forced password reset for affected accounts', 'rejected', '2025-04-11 07:20:00'],
      ];
      history.forEach(h => {
        db.run('INSERT INTO audit_proof (id, action, target, reason, confidence, proof, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', h);
      });
    }
  });

  db.get('SELECT COUNT(*) as count FROM blocked_ips', (err, row: any) => {
    if (row?.count === 0) {
      const ips = [
        ['45.122.31.5', 'Automated SQLMap scan — repeat offender'],
        ['185.220.101.34', 'Tor exit node — credential stuffing'],
        ['102.12.89.4', 'Distributed brute force bot'],
        ['91.240.118.172', 'Port scanning entire subnet'],
      ];
      ips.forEach(ip => {
        db.run('INSERT INTO blocked_ips (ip, reason) VALUES (?, ?)', ip);
      });
    }
  });

  db.get('SELECT COUNT(*) as count FROM user_profile', (err, row: any) => {
    if (row?.count === 0) {
      db.run('INSERT INTO user_profile (id, username, role) VALUES (1, "Operator", "Security Analyst")');
    }
  });
});

async function startServer() {
  const app = express();
  const PORT = 3000;
  app.use(express.json());

  // In-memory log store and scan buffer
  let logs: SIEMLog[] = [];
  let rawBuffer: any[] = [];

  // ─── Log Routes ───
  app.get('/api/logs', (req, res) => res.json(logs));

  app.delete('/api/logs', (req, res) => {
    logs = [];
    rawBuffer = [];
    res.json({ success: true });
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

  // ─── Agent Data Ingestion Routes ───
  app.post('/api/agent/logs', (req, res) => {
    const body = req.body;
    let receivedLogs = Array.isArray(body.logs) ? body.logs : [body];
    
    // Add them to the buffer for the next scan
    rawBuffer.push(...receivedLogs);
    
    // Also broadcast to the Logs UI immediately
    receivedLogs.forEach((l: any) => {
      logs.push({
        id: Math.random().toString(36).substring(7),
        timestamp: new Date().toISOString(),
        type: LogType.INGESTION as any,
        source: body.device_name || 'Agent',
        details: l
      });
    });
    
    res.status(201).json({ success: true, count: receivedLogs.length });
  });

  app.get('/api/agent/buffer', (req, res) => {
    res.json(rawBuffer);
  });

  app.delete('/api/agent/buffer', (req, res) => {
    rawBuffer = [];
    res.json({ success: true });
  });

  // ─── Attack Patterns ───
  app.get('/api/patterns', (req, res) => {
    db.all('SELECT * FROM attack_patterns ORDER BY created_at DESC', (err, rows) => {
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

  // ─── SOAR ───
  app.post('/api/soar/pending', (req, res) => {
    const { id, action, target, reason, confidence, proof } = req.body;
    db.run(
      'INSERT OR REPLACE INTO audit_proof (id, action, target, reason, confidence, proof, status) VALUES (?, ?, ?, ?, ?, ?, "pending")',
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
    const { id, status } = req.body;
    db.run('UPDATE audit_proof SET status = ? WHERE id = ?', [status, id], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id, status });
    });
  });

  app.get('/api/soar/audit', (req, res) => {
    db.all('SELECT * FROM audit_proof ORDER BY timestamp DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  // ─── Blocked IP Management ───
  app.get('/api/firewall', (req, res) => {
    db.all('SELECT * FROM blocked_ips ORDER BY blocked_at DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  app.get('/api/firewall/active', (req, res) => {
    db.all('SELECT * FROM blocked_ips WHERE active = 1 ORDER BY blocked_at DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    });
  });

  app.post('/api/firewall/block', (req, res) => {
    const { ip, reason } = req.body;
    if (!ip) return res.status(400).json({ error: 'IP is required' });
    db.run(
      'INSERT OR REPLACE INTO blocked_ips (ip, reason, active, blocked_at) VALUES (?, ?, 1, datetime("now"))',
      [ip, reason || 'Manually blocked by operator'],
      function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, ip, blocked: true });
      }
    );
  });

  app.post('/api/firewall/unblock', (req, res) => {
    const { ip } = req.body;
    db.run('UPDATE blocked_ips SET active = 0 WHERE ip = ?', [ip], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ ip, unblocked: true });
    });
  });

  // ─── Profile ───
  app.get('/api/profile', (req, res) => {
    db.get('SELECT * FROM user_profile WHERE id = 1', (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(row);
    });
  });

  app.post('/api/profile', (req, res) => {
    const { username } = req.body;
    db.run('UPDATE user_profile SET username = ? WHERE id = 1', [username], function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ success: true, username });
    });
  });

  // ─── Stats ───
  app.get('/api/stats', (req, res) => {
    const stats: any = {};
    db.get('SELECT COUNT(*) as total FROM audit_proof', (err, row: any) => {
      stats.totalEvents = row?.total || 0;
      db.get('SELECT COUNT(*) as total FROM blocked_ips WHERE active = 1', (err2, row2: any) => {
        stats.activeBlocks = row2?.total || 0;
        db.all('SELECT action, COUNT(*) as count FROM audit_proof GROUP BY action', (err3, rows: any) => {
          stats.actionBreakdown = rows || [];
          db.all('SELECT target, COUNT(*) as count FROM audit_proof WHERE action = "BLOCK_IP" GROUP BY target ORDER BY count DESC', (err4, rows2: any) => {
            stats.topBlockedIPs = rows2 || [];
            res.json(stats);
          });
        });
      });
    });
  });

  // ─── Scans ───
  app.get('/api/scans', (req, res) => {
    db.all('SELECT * FROM scan_history ORDER BY timestamp DESC', (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      const formatted = rows?.map((r: any) => ({
        id: r.id,
        timestamp: r.timestamp,
        result: JSON.parse(r.result || '{}'),
        terminalLog: JSON.parse(r.terminal_log || '[]')
      })) || [];
      res.json(formatted);
    });
  });

  app.post('/api/scans', (req, res) => {
    const { id, timestamp, result, terminalLog } = req.body;
    db.run(
      'INSERT INTO scan_history (id, timestamp, result, terminal_log) VALUES (?, ?, ?, ?)',
      [id, timestamp, JSON.stringify(result), JSON.stringify(terminalLog)],
      (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ success: true, id });
      }
    );
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
