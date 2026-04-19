import { 
  LogType, 
  NormalizedLog, 
  SecurityGraph, 
  Detection, 
  AIReport, 
  SOARAction, 
  PipelineResult,
  PipelineAuditEntry
} from '../types';
import { loggingService } from './loggingService';
import { GeminiService } from './geminiService';

export class PipelineService {
  private static validateIP(ip: string): string {
    // Accept any dot-separated numeric string (lab IPs, IPv4, etc.)
    const ipRegex = /^[\d]+(?:\.[\d]+)+$/;
    return ipRegex.test(ip) ? ip : ip && ip !== '' ? ip : "0.0.0.0";
  }

  private static validateTimestamp(ts: string): string {
    const date = new Date(ts);
    return isNaN(date.getTime()) ? "1970-01-01T00:00:00Z" : date.toISOString();
  }

  // Phase 1: Ingestion
  static ingest(input: any[]): any[] {
    if (!Array.isArray(input)) throw new Error("Phase 1 Fail: Input must be a JSON array");
    const rawLogs = input.map(log => ({ raw_log: log }));
    
    // Log the entire batch
    loggingService.log(LogType.INGESTION, "Pipeline", { batch_size: input.length });
    
    // Also log individually so the user can see the raw ingress on the Logs page
    input.forEach(log => {
      loggingService.log(LogType.INGESTION, `Raw API Ingress [${log.ip || log.source_ip || 'unknown'}]`, JSON.stringify(log));
    });
    
    return rawLogs;
  }

  // Phase 2: Normalization
  static normalize(rawLogs: any[]): NormalizedLog[] {
    const normalized: NormalizedLog[] = rawLogs.map(entry => {
      const raw = entry.raw_log || {};
      
      // Fallback handlers for various log formats (Standard SIEM, custom attacker sim, risk_dataset format)
      let logType = String(raw.event_type || raw.category || raw.type || "UNKNOWN").toUpperCase();
      let actionTxt = String(raw.action || raw.action_taken || raw.pattern || "UNKNOWN").toUpperCase();
      
      const log: NormalizedLog = {
        timestamp: this.validateTimestamp(raw.timestamp || raw.time || raw.ts),
        event_type: logType,
        user: String(raw.user || raw.username || "anonymous").toLowerCase(),
        source_ip: this.validateIP(raw.source_ip || raw.ip || raw.src_ip || "0.0.0.0"),
        action: actionTxt,
        status: String(raw.status || raw.risk || raw.severity || "UNKNOWN").toUpperCase()
      };

      // Strict Gate: No null values allowed
      if (Object.values(log).some(v => v === null || v === undefined)) {
        throw new Error("Phase 2 Fail: Null values detected in normalized schema");
      }
      
      return log;
    });

    loggingService.log(LogType.NORMALIZATION, "Pipeline", normalized);
    return normalized;
  }

  // Phase 3: Graph Engine
  static buildGraph(logs: NormalizedLog[]): SecurityGraph {
    const nodes: Map<string, 'user' | 'ip'> = new Map();
    const edges: any[] = [];

    logs.forEach(log => {
      if (!nodes.has(log.user)) nodes.set(log.user, 'user');
      if (!nodes.has(log.source_ip)) nodes.set(log.source_ip, 'ip');

      edges.push({
        source: log.user,
        target: log.source_ip,
        action: log.action,
        timestamp: log.timestamp,
        status: log.status
      });
    });

    const graph: SecurityGraph = {
      nodes: Array.from(nodes.entries()).map(([id, type]) => ({ id, type })),
      edges: edges
    };

    loggingService.log(LogType.GRAPH, "Pipeline", graph);
    return graph;
  }

  // Phase 4: Detection Engine
  static detect(graph: SecurityGraph, logs: NormalizedLog[], threshold: number = 3): Detection[] {
    const detections: Detection[] = [];

    // 1. IP-Based Brute Force & Password Spraying
    const ipAttempts = new Map<string, NormalizedLog[]>();
    logs.forEach(log => {
      if (log.status === 'FAILURE' || log.status === 'DENIED') {
        const attempts = ipAttempts.get(log.source_ip) || [];
        attempts.push(log);
        ipAttempts.set(log.source_ip, attempts);
      }
    });

    ipAttempts.forEach((attempts, ip) => {
      if (attempts.length >= threshold) {
        detections.push({
          type: "brute_force",
          confidence: Math.min(0.5 + (attempts.length * 0.1), 0.99),
          evidence: attempts,
          entities: [ip, ...new Set(attempts.map(a => a.user))]
        });
      }
    });

    // 2. Lateral Movement (User logging in from multiple IPs)
    const userIps = new Map<string, Set<string>>();
    logs.forEach(log => {
      const ips = userIps.get(log.user) || new Set();
      ips.add(log.source_ip);
      userIps.set(log.user, ips);
    });

    userIps.forEach((ips, user) => {
      if (ips.size >= 3) {
        detections.push({
          type: "lateral_movement",
          confidence: Math.min(0.6 + (ips.size * 0.05), 0.95),
          evidence: logs.filter(l => l.user === user),
          entities: [user, ...Array.from(ips)]
        });
      }
    });

    // 3. High-Risk Signatures & Universal Critical Threats
    const knownThreatKeywords = ['MALWARE', 'EXPLOIT', 'EXFILTRATION', 'THREAT_DETECTION', 'RANSOMWARE', 'SQLI', 'DOS', 'PHISHING', 'C2', 'INTRUSION', 'BOTNET'];
    const criticalSeverities = ['CRITICAL', 'HIGH', 'SEVERE', 'QUARANTINED', 'INFECTED', 'MALICIOUS'];

    logs.forEach(log => {
      let isThreat = false;
      let conf = 0.85;

      // 3A. Match by recognized event type
      if (knownThreatKeywords.some(k => log.event_type.includes(k))) {
        isThreat = true;
        conf = (log.status === 'SUCCESS' || criticalSeverities.includes(log.status)) ? 0.99 : 0.85;
      }
      // 3B. Match by generic high severity / risk regardless of event_type
      else if (criticalSeverities.some(c => log.status.includes(c) || log.action.includes(c))) {
        isThreat = true;
        conf = 0.90;
      }
      
      if (isThreat) {
        let detType = log.event_type.toLowerCase();
        if (detType === 'threat_detection' || detType === 'unknown') {
          detType = 'generic_high_risk_anomaly';
        }

        detections.push({
          type: detType,
          confidence: conf,
          evidence: [log],
          entities: [log.source_ip, log.user]
        });
      }

      // 4. Critical command execution & actions
      const badCommands = ['SPAWN_SHELL', 'PRIVILEGE_ESCALATION', 'REVERSE_SHELL', 'SYSTEM_COMPROMISE', 'DUMP_CREDENTIALS', 'BYPASS_DEFENSE'];
      if (badCommands.some(cmd => log.action.includes(cmd))) {
        detections.push({
          type: "system_compromise",
          confidence: 0.99,
          evidence: [log],
          entities: [log.source_ip, log.user]
        });
      }
    });

    loggingService.log(LogType.DETECTION, "Pipeline", detections);
    return detections;
  }

  // Phase 5: AI Explanation
  static async explain(detections: Detection[], graph: SecurityGraph): Promise<AIReport> {
    if (detections.length === 0) {
      return {
        summary: "No threats detected.",
        attack_type: "NONE",
        risk: "LOW",
        explanation: "The system analyzed the logs and found no suspicious patterns matching known attack signatures.",
        recommended_action: "Continue monitoring."
      };
    }

    const report = await GeminiService.explainDetections(detections, graph);
    loggingService.log(LogType.EXPLANATION, "Pipeline", report);
    return report;
  }

  // Phase 6: SOAR Engine
  static async executeSOAR(detections: Detection[]): Promise<SOARAction[]> {
    const actions: SOARAction[] = [];

    for (const det of detections) {
      // RULE 1: brute_force AND confidence >= 0.8 -> BLOCK_IP
      if (det.type === 'brute_force' && det.confidence >= 0.8) {
        const ip = det.entities.find(e => e.includes('.'));
        if (ip) {
          const action: SOARAction = {
            id: `ACT-${Math.random().toString(36).substring(7)}`,
            action: "BLOCK_IP",
            target: ip,
            reason: `Detected brute force with ${det.confidence.toFixed(2)} confidence.`,
            confidence: det.confidence,
            executed: false,
            status: 'pending',
            proof: `Evidence logs: ${det.evidence.length} failed login events from ${ip}`
          };
          actions.push(action);
          await this.saveActionToDB(action);
        }
      }

      // RULE 4: lateral_movement AND confidence >= 0.85 -> ISOLATE_SYSTEM
      if (det.type === 'lateral_movement' && det.confidence >= 0.85) {
        const action: SOARAction = {
          id: `ACT-${Math.random().toString(36).substring(7)}`,
          action: "ISOLATE_SYSTEM",
          target: det.entities[0],
          reason: `Suspicious lateral movement across ${det.entities.length - 1} IPs.`,
          confidence: det.confidence,
          executed: false,
          status: 'pending',
          proof: `Target user/system observed authenticating from multiple IPs in short sequence: ${det.entities.join(', ')}`
        };
        actions.push(action);
        await this.saveActionToDB(action);
      }

      // RULE 5: High-Risk Signatures -> Immediate Block & Isolate
      if (['malware', 'exploit', 'exfiltration', 'system_compromise'].includes(det.type)) {
        const ip = det.entities.find(e => e.includes('.'));
        if (ip) {
          const action: SOARAction = {
            id: `ACT-${Math.random().toString(36).substring(7)}`,
            action: "BLOCK_IP",
            target: ip,
            reason: `Critical network block triggered by ${det.type.toUpperCase()}`,
            confidence: det.confidence,
            executed: false,
            status: 'pending',
            proof: `High-severity indicator matched. Event detail: ${det.type}`
          };
          actions.push(action);
          await this.saveActionToDB(action);
        }
      }

      // Always Alert — these also get saved to DB now
      const alertAction: SOARAction = {
        id: `ALRT-${Math.random().toString(36).substring(7)}`,
        action: "ALERT",
        target: det.entities[0] || "Security Console",
        reason: `Generated alert for ${det.type} — ${det.entities.join(', ')}`,
        confidence: det.confidence,
        executed: true,
        status: 'approved',
        proof: `Detection type: ${det.type}, Evidence: ${det.evidence.length} events, Confidence: ${(det.confidence * 100).toFixed(0)}%`
      };
      actions.push(alertAction);
      await this.saveActionToDB(alertAction);
    }

    loggingService.log(LogType.SOAR, "Pipeline", actions);
    return actions;
  }

  private static async saveActionToDB(action: SOARAction) {
    try {
      await fetch('/api/soar/pending', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action)
      });
    } catch (error) {
      console.error("Failed to save action:", error);
    }
  }

  // Phase 7: Final Assembly
  static async runFullPipeline(logs: any[], threshold: number = 3): Promise<PipelineResult> {
    try {
      const raw = this.ingest(logs);
      const normalized = this.normalize(raw);
      const graph = this.buildGraph(normalized);
      const detections = this.detect(graph, normalized, threshold);
      const aiReport = await this.explain(detections, graph);
      const soarActions = await this.executeSOAR(detections);

      const auditLog: PipelineAuditEntry[] = [
        ...soarActions.map(a => ({
          timestamp: new Date().toISOString(),
          action: a.action,
          target: a.target,
          reason: a.reason
        }))
      ];

      const result: PipelineResult = {
        graph,
        detections,
        ai_report: aiReport,
        soar_actions: soarActions,
        audit_log: auditLog
      };

      loggingService.log(LogType.AUDIT, "Pipeline", result);
      return result;
    } catch (error) {
      loggingService.log(LogType.ERROR, "Pipeline", { error: error instanceof Error ? error.message : String(error) });
      throw error;
    }
  }
}
