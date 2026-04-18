import { GoogleGenAI, Type } from "@google/genai";
import { loggingService } from "./loggingService";
import { LogType, SecurityGraph, Detection, AIReport } from "../types";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

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
        model: "gemini-3-flash-preview",
        contents: `Analyze these security detections and the behavioral graph to provide a human-readable summary.
        
        DETECTIONS: ${JSON.stringify(detections)}
        GRAPH SUMMARY: ${graph.nodes.length} nodes, ${graph.edges.length} edges
        
        STRICT RULES:
        1. DO NOT modify the detection details.
        2. DO NOT introduce new facts.
        3. Explain the "Why" behind the detections using the evidence provided.
        4. Focus on risk levels (LOW, MEDIUM, HIGH).
        
        Respond in JSON format according to the schema.`,
        config: {
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              summary: { type: Type.STRING },
              attack_type: { type: Type.STRING },
              risk: { type: Type.STRING, enum: ["LOW", "MEDIUM", "HIGH"] },
              explanation: { type: Type.STRING },
              recommended_action: { type: Type.STRING }
            },
            required: ["summary", "attack_type", "risk", "explanation", "recommended_action"]
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
      return {
        summary: "Automated analysis of security detections completed.",
        attack_type: detections.length > 0 ? detections[0].type : "UNKNOWN",
        risk: "MEDIUM",
        explanation: "Detection engine identified suspicious patterns. AI explanation is currently summarized via fallback due to model unavailability.",
        recommended_action: "Review the audit logs for evidence and context."
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
