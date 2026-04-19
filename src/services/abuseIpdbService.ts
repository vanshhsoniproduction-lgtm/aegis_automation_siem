import { loggingService } from './loggingService';
import { LogType } from '../types';

export class AbuseIpdbService {
  private static cache = new Map<string, { score: number, timestamp: number }>();
  private static readonly CACHE_TTL = 1000 * 60 * 60; // 1 hour

  static async checkIP(ip: string): Promise<number> {
    // Ignore internal or invalid IPs
    if (!ip || ip === '0.0.0.0' || this.isInternalIP(ip)) return 0;

    const cached = this.cache.get(ip);
    if (cached && Date.now() - cached.timestamp < this.CACHE_TTL) {
      return cached.score;
    }

    try {
      const response = await fetch(`/api/proxy/abuseipdb/${ip}`);

      if (response.ok) {
        const data = await response.json();
        const score = data.data.abuseConfidenceScore;
        this.cache.set(ip, { score, timestamp: Date.now() });
        return score;
      } else {
        console.warn("AbuseIPDB API error:", response.status);
      }
    } catch (e) {
      console.error("Failed to check AbuseIPDB:", e);
    }
    return 0;
  }

  private static isInternalIP(ip: string): boolean {
    const parts = ip.split('.');
    if (parts.length !== 4) return false;
    if (parts[0] === '10' || parts[0] === '127') return true;
    if (parts[0] === '192' && parts[1] === '168') return true;
    if (parts[0] === '172') {
      const p2 = parseInt(parts[1], 10);
      if (p2 >= 16 && p2 <= 31) return true;
    }
    return false;
  }
}
