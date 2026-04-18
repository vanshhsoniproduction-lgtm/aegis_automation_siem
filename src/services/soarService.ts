import { SOARAction } from '../types';

export class SOARService {
  static async getPendingActions(): Promise<SOARAction[]> {
    try {
      const response = await fetch('/api/soar/pending');
      const data = await response.json();
      return data.map((d: any) => ({
        ...d,
        proof: typeof d.proof === 'string' ? JSON.parse(d.proof) : d.proof
      }));
    } catch (error) {
      console.error("Failed to fetch pending actions:", error);
      return [];
    }
  }

  static async confirmAction(id: string, status: 'approved' | 'rejected'): Promise<boolean> {
    try {
      const response = await fetch('/api/soar/confirm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id, status })
      });
      return response.ok;
    } catch (error) {
      console.error("Failed to confirm action:", error);
      return false;
    }
  }

  static async getAuditLog(): Promise<any[]> {
    try {
      const response = await fetch('/api/soar/audit');
      return await response.json();
    } catch (error) {
      console.error("Failed to fetch audit log:", error);
      return [];
    }
  }

  static async getPatterns(): Promise<any[]> {
    try {
      const response = await fetch('/api/patterns');
      return await response.json();
    } catch (error) {
      console.error("Failed to fetch patterns:", error);
      return [];
    }
  }

  static async addPattern(type: string, description: string, severity: string): Promise<boolean> {
    try {
      const response = await fetch('/api/patterns', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type, description, severity })
      });
      return response.ok;
    } catch (error) {
      console.error("Failed to add pattern:", error);
      return false;
    }
  }
}
