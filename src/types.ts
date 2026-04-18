/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum LogType {
  INGESTION = 'INGESTION',
  NORMALIZATION = 'NORMALIZATION',
  GRAPH = 'GRAPH',
  DETECTION = 'DETECTION',
  EXPLANATION = 'EXPLANATION',
  SOAR = 'SOAR',
  AUDIT = 'AUDIT',
  ERROR = 'ERROR'
}

export interface SIEMLog {
  id: string;
  timestamp: string;
  type: LogType;
  source: string;
  details: any;
  metadata?: Record<string, any>;
}

// Phase 2: Normalization Schema
export interface NormalizedLog {
  timestamp: string;
  event_type: string;
  user: string;
  source_ip: string;
  action: string;
  status: string;
}

// Phase 3: Graph Schema
export interface GraphNode {
  id: string;
  type: 'user' | 'ip';
}

export interface GraphEdge {
  source: string;
  target: string;
  action: string;
  timestamp: string;
  status: string;
}

export interface SecurityGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// Phase 4: Detection Schema
export interface Detection {
  type: string;
  confidence: number;
  evidence: NormalizedLog[];
  entities: string[];
}

// Phase 5: AI Explanation Schema
export interface AIReport {
  summary: string;
  attack_type: string;
  mitre_id: string;
  remediation_code: string;
  risk: 'LOW' | 'MEDIUM' | 'HIGH';
  explanation: string;
  recommended_action: string;
}

// Phase 6: SOAR Action Schema
export interface SOARAction {
  id: string;
  action: string;
  target: string;
  reason: string;
  confidence: number;
  executed: boolean;
  status: 'pending' | 'approved' | 'rejected';
  proof?: string; // Local storage of evidence summary
}

// Phase 7: Final Audit Output
export interface PipelineAuditEntry {
  timestamp: string;
  action: string;
  target: string;
  reason: string;
}

export interface PipelineResult {
  graph: SecurityGraph;
  detections: Detection[];
  ai_report: AIReport;
  soar_actions: SOARAction[];
  audit_log: PipelineAuditEntry[];
}
