import { SOARAction } from '../types';

export class SOARService {
  static async getPendingActions(): Promise<SOARAction[]> {
    try {
      const response = await fetch('/api/soar/pending');
      const data = await response.json();
      return data.map((d: any) => ({
        ...d,
        proof: typeof d.proof === 'string' ? (() => { try { return JSON.parse(d.proof); } catch { return d.proof; } })() : d.proof
      }));
    } catch { return []; }
  }

  static async confirmAction(id: string, status: 'approved' | 'rejected'): Promise<boolean> {
    try {
      const r = await fetch('/api/soar/confirm', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id, status }) });
      return r.ok;
    } catch { return false; }
  }

  static async getAuditLog(): Promise<any[]> {
    try { return await (await fetch('/api/soar/audit')).json(); } catch { return []; }
  }

  static async getPatterns(): Promise<any[]> {
    try { return await (await fetch('/api/patterns')).json(); } catch { return []; }
  }

  static async addPattern(type: string, description: string, severity: string): Promise<boolean> {
    try {
      const r = await fetch('/api/patterns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type, description, severity }) });
      return r.ok;
    } catch { return false; }
  }

  // ─── Firewall ───
  static async getBlockedIPs(): Promise<any[]> {
    try { return await (await fetch('/api/firewall')).json(); } catch { return []; }
  }

  static async getActiveBlocks(): Promise<any[]> {
    try { return await (await fetch('/api/firewall/active')).json(); } catch { return []; }
  }

  static async blockIP(ip: string, reason: string): Promise<boolean> {
    try {
      const r = await fetch('/api/firewall/block', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip, reason }) });
      return r.ok;
    } catch { return false; }
  }

  static async unblockIP(ip: string): Promise<boolean> {
    try {
      const r = await fetch('/api/firewall/unblock', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ip }) });
      return r.ok;
    } catch { return false; }
  }

  // ─── Profile ───
  static async getProfile(): Promise<any> {
    try { return await (await fetch('/api/profile')).json(); } catch { return { username: 'Operator', role: 'Security Analyst' }; }
  }

  static async updateProfile(username: string): Promise<boolean> {
    try {
      const r = await fetch('/api/profile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username }) });
      return r.ok;
    } catch { return false; }
  }

  // ─── Stats & Buffer ───
  static async getStats(): Promise<any> {
    try { return await (await fetch('/api/stats')).json(); } catch { return {}; }
  }

  static async getBufferedAgentLogs(): Promise<any[]> {
    try { return await (await fetch('/api/agent/buffer')).json(); } catch { return []; }
  }
  
  static async clearBufferedAgentLogs(): Promise<boolean> {
    try { return (await fetch('/api/agent/buffer', { method: 'DELETE' })).ok; } catch { return false; }
  }

  static async clearSystemLogs(): Promise<boolean> {
    try { return (await fetch('/api/logs', { method: 'DELETE' })).ok; } catch { return false; }
  }

  // ─── Agent System Control ───
  static async startAgent(): Promise<boolean> {
    try { return (await fetch('/api/agent/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'start' }) })).ok; } catch { return false; }
  }

  static async stopAgent(): Promise<boolean> {
    try { return (await fetch('/api/agent/control', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'stop' }) })).ok; } catch { return false; }
  }

  static async getAgentStatus(): Promise<any> {
    try { return await (await fetch('/api/agent/status')).json(); } catch { return { isRunning: false, output: [] }; }
  }

  // ─── Scans ───
  static async getScans(): Promise<any[]> {
    try { return await (await fetch('/api/scans')).json(); } catch { return []; }
  }

  static async saveScan(scanData: any): Promise<boolean> {
    try {
      const r = await fetch('/api/scans', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(scanData) });
      return r.ok;
    } catch { return false; }
  }
}
