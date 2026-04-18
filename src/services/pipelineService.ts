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
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    return ipRegex.test(ip) ? ip : "0.0.0.0";
  }

  private static validateTimestamp(ts: string): string {
    const date = new Date(ts);
    return isNaN(date.getTime()) ? "1970-01-01T00:00:00Z" : date.toISOString();
  }

  // Phase 1: Ingestion
  static ingest(input: any[]): any[] {
    if (!Array.isArray(input)) throw new Error("Phase 1 Fail: Input must be a JSON array");
    const rawLogs = input.map(log => ({ raw_log: log }));
    loggingService.log(LogType.INGESTION, "Pipeline", rawLogs);
    return rawLogs;
  }

  // Phase 2: Normalization
  static normalize(rawLogs: any[]): NormalizedLog[] {
    const normalized: NormalizedLog[] = rawLogs.map(entry => {
      const raw = entry.raw_log || {};
      const log: NormalizedLog = {
        timestamp: this.validateTimestamp(raw.timestamp || raw.time || raw.ts),
        event_type: String(raw.event_type || raw.type || "UNKNOWN").toUpperCase(),
        user: String(raw.user || raw.username || "anonymous").toLowerCase(),
        source_ip: this.validateIP(raw.source_ip || raw.ip || raw.src_ip || "0.0.0.0"),
        action: String(raw.action || "UNKNOWN").toUpperCase(),
        status: String(raw.status || "UNKNOWN").toUpperCase()
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
  static detect(graph: SecurityGraph, logs: NormalizedLog[]): Detection[] {
    const detections: Detection[] = [];

    // Brute Force Detection (Simple temporal correlation)
    const userAttempts = new Map<string, NormalizedLog[]>();
    logs.forEach(log => {
      if (log.status === 'FAILURE' || log.status === 'DENIED') {
        const attempts = userAttempts.get(log.user) || [];
        attempts.push(log);
        userAttempts.set(log.user, attempts);
      }
    });

    userAttempts.forEach((attempts, user) => {
      if (attempts.length >= 3) {
        detections.push({
          type: "brute_force",
          confidence: Math.min(0.5 + (attempts.length * 0.1), 0.99),
          evidence: attempts,
          entities: [user, ...new Set(attempts.map(a => a.source_ip))]
        });
      }
    });

    // Lateral Movement (User logging in from multiple IPs)
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
          await this.savePendingAction(action);
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
        await this.savePendingAction(action);
      }

      // Always Alert (Automatic execution for alerts)
      actions.push({
        id: `ALRT-${Math.random().toString(36).substring(7)}`,
        action: "ALERT",
        target: "Security Console",
        reason: `Generated alert for ${det.type} activity.`,
        confidence: det.confidence,
        executed: true,
        status: 'approved'
      });
    }

    loggingService.log(LogType.SOAR, "Pipeline", actions);
    return actions;
  }

  private static async savePendingAction(action: SOARAction) {
    try {
      await fetch('/api/soar/pending', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(action)
      });
    } catch (error) {
      console.error("Failed to save pending action:", error);
    }
  }

  // Phase 7: Final Assembly
  static async runFullPipeline(logs: any[]): Promise<PipelineResult> {
    try {
      const raw = this.ingest(logs);
      const normalized = this.normalize(raw);
      const graph = this.buildGraph(normalized);
      const detections = this.detect(graph, normalized);
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
