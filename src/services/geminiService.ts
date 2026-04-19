import { GoogleGenAI, Type } from "@google/genai";
import { loggingService } from "./loggingService";
import { LogType, SecurityGraph, Detection, AIReport } from "../types";

// Prefer env variable if exists, otherwise use the provided API key
const API_KEY = (import.meta as any).env?.VITE_GEMINI_API_KEY || "AIzaSyDA7Rd77IFym7SYuxP0R5jCKGoGd7WbHGg";
const ai = new GoogleGenAI({ apiKey: API_KEY });

export class GeminiService {
  /**
   * Phase 5: AI Explanation
   * Translates detections and graph data into a human-readable report.
   * DOES NOT modify detections or make decisions.
   */
  static async explainDetections(detections: Detection[], graph: SecurityGraph): Promise<AIReport> {
    const source = "GeminiExplanationNode";
    
    await loggingService.log(LogType.INGESTION, source, { 
      action: "explainDetections", 
      detectionCount: detections.length 
    });

    try {
      const response = await ai.models.generateContent({
        model: "gemini-3.1-pro-preview",
        contents: `Analyze these security detections and the behavioral graph to provide a human-readable summary.
        
        DETECTIONS: ${JSON.stringify(detections)}
        GRAPH SUMMARY: ${graph.nodes.length} nodes, ${graph.edges.length} edges
        
        STRICT RULES:
        1. DO NOT modify the detection details.
        2. DO NOT introduce new facts.
        3. Explain the "Why" behind the detections using the evidence provided.
        4. Focus on risk levels (LOW, MEDIUM, HIGH).
        5. Map to at least one MITRE ATT&CK Technique ID (e.g. T1110).
        6. Provide a "remediation_code" snippet (e.g. iptables or powershell to block).
        
        Respond in JSON format according to the schema.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              attack_type: { type: Type.STRING },
              mitre_id: { type: Type.STRING },
              remediation_code: { type: Type.STRING },
              risk: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH"] },
              explanation: { type: Type.STRING },
              recommended_action: { type: Type.STRING }
            },
            required: ["summary", "attack_type", "mitre_id", "remediation_code", "risk", "explanation", "recommended_action"]
          }
        }
      });

      const result = JSON.parse(response.text || '{}') as AIReport;
      
      await loggingService.log(LogType.EXPLANATION, source, { result });

      return result;
    } catch (error) {
      await loggingService.log(LogType.ERROR, source, { 
        message: error instanceof Error ? error.message : "AI Explanation failed",
        detections 
      });
      
      // Fallback if AI is unavailable (MANDATORY per global rules)
      const firstDet = detections[0];
      const count = detections.length;
      return {
        summary: `Automated analysis completed. Identified ${count} distinct threat vectors requiring immediate attention.`,
        attack_type: firstDet ? firstDet.type.toUpperCase() : "UNKNOWN_THREAT",
        mitre_id: firstDet?.type === 'brute_force' ? 'T1110' : firstDet?.type === 'lateral_movement' ? 'T1021' : 'T1059',
        remediation_code: firstDet ? `# Block attacker IPs\niptables -A INPUT -s ${firstDet.entities.find(e => e.includes('.')) || '0.0.0.0'} -j DROP` : "# No remediation code available",
        risk: firstDet?.confidence >= 0.8 ? "HIGH" : "MEDIUM",
        explanation: `Detection engine flagged suspicious activity related to ${firstDet ? firstDet.type.replace('_', ' ') : 'unknown behavior'} across ${firstDet ? firstDet.entities.length : 0} entities. Confidence level is assessed at ${Math.round((firstDet?.confidence || 0) * 100)}%. System recommends applying the provided remediation rules to prevent escalation.`,
        recommended_action: "Review the audit logs for evidence and confirm isolation of affected assets."
      };
    }

  }

  /**
   * Generates sample raw logs for the ingestion phase
   */
  static generateSampleRawLogs(): any[] {
    const users = ["admin", "root", "guest", "db_manager", "j.doe"];
    const ips = ["192.168.1.50", "10.0.0.12", "45.22.11.89", "172.16.0.4", "192.168.1.100"];
    
    const logs = [];
    // Generate some brute force noise
    for (let i = 0; i < 4; i++) {
      logs.push({
        timestamp: new Date(Date.now() - (i * 1000 * 60)).toISOString(),
        user: "root",
        ip: "45.22.11.89",
        action: "LOGIN",
        status: "FAILURE",
        msg: "Invalid password for user root"
      });
    }

    // Generate some normal traffic
    for (let i = 0; i < 5; i++) {
      logs.push({
        timestamp: new Date().toISOString(),
        user: users[Math.floor(Math.random() * users.length)],
        ip: ips[Math.floor(Math.random() * ips.length)],
        action: "ACCESS_RESOURCE",
        status: "SUCCESS"
      });
    }

    return logs;
  }
}
