import { Detection } from '../types';

export class VirusTotalService {
  private static cache = new Map<string, any>();

  // Extract IPs, Hashes (MD5/SHA1/SHA256), and URLs from text
  static extractEntities(text: string): { type: string, value: string }[] {
    const entities: { type: string, value: string }[] = [];
    
    // Match IPs
    const ips = text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [];
    ips.forEach(ip => {
      // Exclude simple internal IP patterns (10.*, 127.*, 192.168.*)
      if (!ip.startsWith('10.') && !ip.startsWith('127.') && !ip.startsWith('192.168.')) {
        entities.push({ type: 'ip', value: ip });
      }
    });

    // Match Hashes
    const hashes = text.match(/\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b/g) || [];
    hashes.forEach(hash => entities.push({ type: 'hash', value: hash }));

    // Match URLs (very basic regex for common structures)
    const urls = text.match(/https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g) || [];
    urls.forEach(url => entities.push({ type: 'url', value: url }));

    return entities;
  }

  static async analyzeDetections(detections: Detection[]): Promise<any> {
    const combinedLogText = detections.map(d => JSON.stringify(d.evidence)).join(' ');
    
    // De-duplicate entities
    const rawEntities = this.extractEntities(combinedLogText);
    const uniqueEntities = [];
    const seen = new Set<string>();
    
    for (const ent of rawEntities) {
      if (!seen.has(ent.value)) {
        seen.add(ent.value);
        uniqueEntities.push(ent);
      }
    }

    const results: any[] = [];
    
    // To respect basic rate limits and keep it swift, analyze up to 3 distinct entities max per run
    const targets = uniqueEntities.slice(0, 3);

    for (const target of targets) {
      if (this.cache.has(target.value)) {
        results.push(this.cache.get(target.value));
        continue;
      }

      try {
        const val = target.type === 'url' ? btoa(target.value).replace(/=/g, '') : target.value;
        const typeMap: any = { 'ip': 'ip_addresses', 'hash': 'files', 'url': 'urls' };
        const response = await fetch(`/api/proxy/virustotal/${typeMap[target.type]}/${val}`);

        if (response.ok) {
          const data = await response.json();
          // Extract just the core stats we care about to keep payload to Groq small
          const stats = data.data?.attributes?.last_analysis_stats || {};
          const intel = { 
            entity: target.value, 
            type: target.type, 
            malicious: stats.malicious || 0,
            suspicious: stats.suspicious || 0,
            undetected: stats.undetected || 0
          };
          this.cache.set(target.value, intel);
          results.push(intel);
        }
      } catch (err) {
        console.error("VT Scan failed for", target.value, err);
      }
    }

    return { status: "success", analyzed: results.length, findings: results };
  }
}
