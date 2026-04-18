/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  ShieldCheck, 
  Search, 
  Settings, 
  Bell, 
  LayoutDashboard, 
  Zap, 
  Cpu, 
  Database,
  RefreshCcw,
  Play,
  Activity,
  ShieldAlert,
  Fingerprint,
  Share2,
  Box,
  FileSearch,
  CheckCircle2,
  FileUp,
  History,
  ShieldQuestion,
  UserCheck,
  UserX,
  Plus,
  Moon,
  Sun
} from 'lucide-react';
import { PipelineResult, LogType, SOARAction } from './types';
import { GeminiService } from './services/geminiService';
import { PipelineService } from './services/pipelineService';
import { LogViewer } from './components/LogViewer';
import { SOARService } from './services/soarService';

export default function App() {
  const [pipelineResult, setPipelineResult] = useState<PipelineResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const [autoPilot, setAutoPilot] = useState(false);
  const [activePhase, setActivePhase] = useState<number | null>(null);
  const [manualLogs, setManualLogs] = useState("");
  const [showManualInput, setShowManualInput] = useState(false);
  const [pendingActions, setPendingActions] = useState<SOARAction[]>([]);
  const [patterns, setPatterns] = useState<any[]>([]);
  const [showPatterns, setShowPatterns] = useState(false);
  const [theme, setTheme] = useState<'light' | 'dark'>(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('siem-theme') as 'light' | 'dark' || 'light';
    }
    return 'light';
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    localStorage.setItem('siem-theme', theme);
  }, [theme]);

  const toggleTheme = () => setTheme(prev => prev === 'light' ? 'dark' : 'light');

  const fetchPendingAndPatterns = useCallback(async () => {
    const [pending, pts] = await Promise.all([
      SOARService.getPendingActions(),
      SOARService.getPatterns()
    ]);
    setPendingActions(pending);
    setPatterns(pts);
  }, []);

  useEffect(() => {
    fetchPendingAndPatterns();
    const interval = setInterval(fetchPendingAndPatterns, 5000);
    return () => clearInterval(interval);
  }, [fetchPendingAndPatterns]);

  const runPipeline = useCallback(async (customLogs?: any[]) => {
    setIsProcessing(true);
    try {
      const logsToProcess = customLogs || GeminiService.generateSampleRawLogs();
      
      // Step-by-step visual feedback
      setActivePhase(1);
      await new Promise(r => setTimeout(r, 600));
      setActivePhase(2);
      await new Promise(r => setTimeout(r, 600));
      setActivePhase(3);
      await new Promise(r => setTimeout(r, 600));
      setActivePhase(4);
      await new Promise(r => setTimeout(r, 600));
      
      const result = await PipelineService.runFullPipeline(logsToProcess);
      
      setActivePhase(5);
      await new Promise(r => setTimeout(r, 800));
      setActivePhase(6);
      await new Promise(r => setTimeout(r, 600));
      setActivePhase(7);
      
      setPipelineResult(result);
    } catch (error) {
      console.error("Pipeline breakdown:", error);
    } finally {
      setIsProcessing(false);
      setTimeout(() => setActivePhase(null), 2000);
    }
  }, []);

  const handleManualIngest = () => {
    try {
      const parsed = JSON.parse(manualLogs);
      const logsArray = Array.isArray(parsed) ? parsed : [parsed];
      runPipeline(logsArray);
      setShowManualInput(false);
      setManualLogs("");
    } catch (e) {
      alert("Invalid JSON format. Please provide a JSON array of logs.");
    }
  };

  const handleConfirmAction = async (id: string, status: 'approved' | 'rejected') => {
    const success = await SOARService.confirmAction(id, status);
    if (success) {
      setPendingActions(prev => prev.filter(a => a.id !== id));
    }
  };

  const handleAddPattern = async () => {
    const type = prompt("Pattern Type (e.g. SQL Injection)");
    const severity = prompt("Severity (Low/Medium/High/Critical)");
    if (type && severity) {
      await SOARService.addPattern(type, "Manually identified threat pattern", severity);
      fetchPendingAndPatterns();
    }
  };

  const phases = [
    { id: 1, name: 'Ingestion', icon: <Database className="w-4 h-4" /> },
    { id: 2, name: 'Normalization', icon: <Fingerprint className="w-4 h-4" /> },
    { id: 3, name: 'Graph Engine', icon: <Share2 className="w-4 h-4" /> },
    { id: 4, name: 'Detection', icon: <Search className="w-4 h-4" /> },
    { id: 5, name: 'AI Explanation', icon: <Cpu className="w-4 h-4" /> },
    { id: 6, name: 'SOAR Engine', icon: <Zap className="w-4 h-4" /> },
    { id: 7, name: 'Audit Output', icon: <CheckCircle2 className="w-4 h-4" /> },
  ];

  return (
    <div className="min-h-screen bg-bg text-text-main font-sans selection:bg-accent/30 flex">
      {/* Sidebar Navigation */}
      <nav className="w-16 bg-sidebar flex flex-col items-center py-5 shrink-0 grow-0 h-screen fixed top-0 left-0 z-50">
        <div className="w-8 h-8 bg-accent rounded-lg mb-6 flex items-center justify-center text-white shrink-0 shadow-[0_4px_10px_rgba(0,122,255,0.3)]">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div className="flex flex-col gap-6 items-center flex-1">
          {phases.map(p => (
            <div 
              key={p.id}
              className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all cursor-pointer relative ${
                activePhase === p.id 
                  ? 'bg-accent text-white shadow-[0_0_15px_rgba(0,122,255,0.5)]' 
                  : 'bg-white/5 text-white/40 hover:bg-white/10'
              }`}
              title={p.name}
            >
              {p.icon}
            </div>
          ))}
          <div className="h-px w-8 bg-white/10 my-2" />
          <div 
            onClick={() => setShowPatterns(!showPatterns)}
            className={`w-8 h-8 rounded-lg flex items-center justify-center transition-all cursor-pointer ${
              showPatterns ? 'bg-warning text-white' : 'bg-white/5 text-white/40 hover:bg-white/10'
            }`}
            title="Pattern Database"
          >
            <History className="w-4 h-4" />
          </div>
        </div>
        <div className="mt-auto w-8 h-8 bg-white/10 rounded-lg flex items-center justify-center text-white/40 hover:bg-accent hover:text-white transition-all cursor-pointer">
          <Settings className="w-4 h-4" />
        </div>
      </nav>

      <div className="flex-1 flex flex-col pl-16">
        {/* Header */}
        <header className="h-14 bg-panel border-b border-border flex items-center justify-between px-6 sticky top-0 z-40">
          <div className="flex items-center gap-3">
            <h1 className="text-base font-semibold tracking-tight">Synapse Autonomous SIEM</h1>
            <span className="text-[9px] uppercase tracking-widest bg-accent text-white px-2 py-0.5 rounded-full font-black">
              Deterministic Mode
            </span>
          </div>
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 text-success font-bold text-[10px] uppercase tracking-wider">
              <div className="w-2 h-2 bg-success rounded-full animate-pulse" />
              <span>Engine Status: Synchronized</span>
            </div>
            <div className="flex items-center gap-4 border-l border-border pl-4">
              <button 
                onClick={toggleTheme}
                className="p-1.5 rounded-md hover:bg-bg transition-all text-text-muted hover:text-accent"
                title={theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
              >
                {theme === 'light' ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
              </button>
              <button 
                onClick={() => setShowManualInput(!showManualInput)}
                className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest text-text-muted hover:text-accent transition-all"
              >
                <FileUp className="w-4 h-4" />
                Manual Ingest
              </button>
              <div className="w-6 h-6 rounded-md bg-accent/10 flex items-center justify-center text-accent text-[10px] font-black">AI</div>
            </div>
          </div>
        </header>

        {/* Dashboard Content */}
        <main className="p-5 flex-1 grid grid-cols-1 xl:grid-cols-[1fr_380px] gap-5 min-h-0 overflow-auto">
          
          <div className="space-y-5">
            {/* Manual Input Overlay */}
            <AnimatePresence>
              {showManualInput && (
                <motion.section 
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="bg-panel border border-border rounded-lg p-4 shadow-lg overflow-hidden"
                >
                  <h3 className="text-xs font-black uppercase text-text-muted mb-3 flex items-center gap-2">
                    <FileUp className="w-3 h-3" /> Manual Log Source
                  </h3>
                  <textarea 
                    value={manualLogs}
                    onChange={(e) => setManualLogs(e.target.value)}
                    placeholder='[{"timestamp": "2023-10-01T10:00:00Z", "user": "admin", "action": "LOGIN", "status": "FAILURE"}]'
                    className="w-full h-32 bg-bg border border-border rounded p-3 font-mono text-xs focus:ring-1 focus:ring-accent outline-none mb-3"
                  />
                  <div className="flex justify-end gap-2">
                    <button onClick={() => setShowManualInput(false)} className="px-4 py-1.5 text-[10px] font-bold uppercase text-text-muted">Cancel</button>
                    <button onClick={handleManualIngest} className="px-4 py-1.5 bg-accent text-white rounded text-[10px] font-bold uppercase shadow-md">Start Scan</button>
                  </div>
                </motion.section>
              )}
            </AnimatePresence>

            {/* Pattern Database Overlay */}
            <AnimatePresence>
              {showPatterns && (
                <motion.section 
                  initial={{ opacity: 0, y: -20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  className="bg-panel border border-border rounded-lg p-4 shadow-md"
                >
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-xs font-black uppercase text-text-muted flex items-center gap-2">
                      <History className="w-3 h-3" /> Known Attack Patterns (SQLite)
                    </h3>
                    <button onClick={handleAddPattern} className="p-1.5 bg-accent/10 text-accent rounded hover:bg-accent hover:text-white transition-all">
                      <Plus className="w-3 h-3" />
                    </button>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    {patterns.map(p => (
                      <div key={p.id} className="p-3 bg-bg border border-border rounded">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-black uppercase text-accent leading-none">{p.type}</span>
                          <span className="text-[9px] font-bold bg-panel px-1.5 py-0.5 rounded border border-border uppercase text-text-main">{p.severity}</span>
                        </div>
                        <p className="text-[10px] text-text-muted line-clamp-1">{p.description}</p>
                      </div>
                    ))}
                  </div>
                </motion.section>
              )}
            </AnimatePresence>

            {/* Top Toolbar */}
            <section className="bg-panel border border-border rounded-lg p-4 flex items-center justify-between shadow-sm">
              <div className="flex items-center gap-6">
                <div>
                  <h2 className="text-xs font-black uppercase text-text-muted tracking-widest mb-1">Pipeline Control</h2>
                  <p className="text-[11px] text-text-muted font-medium">Multi-phase security orchestration engine v2.0</p>
                </div>
                <div className="h-8 w-px bg-border" />
                <div className="flex items-center gap-2">
                  <button 
                    onClick={() => setAutoPilot(!autoPilot)}
                    className={`px-3 py-1.5 rounded-md text-[10px] font-bold transition-all border ${
                      autoPilot ? 'bg-accent text-white border-accent shadow-lg' : 'bg-panel border-border text-text-muted hover:bg-bg'
                    }`}
                  >
                    AUTOPILOT: {autoPilot ? 'ENGAGED' : 'STANDBY'}
                  </button>
                  <button 
                    onClick={() => runPipeline()}
                    disabled={isProcessing}
                    className="px-4 py-1.5 bg-text-main text-white rounded-md text-[10px] font-bold hover:bg-black transition-all flex items-center gap-2 shadow-md disabled:opacity-50"
                  >
                    <Play className="w-3 h-3 fill-current" />
                    FORCE INGESTION
                  </button>
                </div>
              </div>
              
              <div className="hidden lg:flex items-center gap-1">
                {phases.map((p, idx) => (
                  <React.Fragment key={p.id}>
                    <div className={`w-2 h-2 rounded-full transition-all duration-500 ${
                      activePhase && p.id <= activePhase ? 'bg-accent' : 'bg-border'
                    }`} />
                    {idx < phases.length - 1 && <div className={`w-4 h-[1px] ${
                      activePhase && p.id < activePhase ? 'bg-accent' : 'bg-border'
                    }`} />}
                  </React.Fragment>
                ))}
              </div>
            </section>

            {/* Pending Approvals (New Phase 6 Feature) */}
            <AnimatePresence>
              {pendingActions.length > 0 && (
                <motion.section 
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="bg-panel border-2 border-accent border-dashed rounded-lg p-5 shadow-xl"
                >
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-accent/20 rounded-full animate-pulse">
                        <ShieldQuestion className="w-5 h-5 text-accent" />
                      </div>
                      <div>
                        <h3 className="text-xs font-black uppercase text-accent tracking-widest">Pending SOAR Confirmation</h3>
                        <p className="text-[10px] text-text-muted">High-confidence actions require human validation before execution.</p>
                      </div>
                    </div>
                  </div>
                  <div className="space-y-4">
                    {pendingActions.map(action => (
                      <div key={action.id} className="p-4 bg-bg rounded-lg border border-border flex flex-col md:flex-row gap-4 items-start md:items-center">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="text-xs font-black uppercase text-text-main">{action.action}</span>
                            <span className="w-1 h-1 bg-border rounded-full" />
                            <span className="text-[10px] font-mono font-bold text-accent">{action.target}</span>
                          </div>
                          <p className="text-[11px] font-medium text-text-muted mb-2">{action.reason}</p>
                          <div className="p-2 bg-panel/50 rounded border border-border border-dashed font-mono text-[9px] text-text-muted">
                            <strong className="text-accent uppercase">Audit Proof:</strong> {action.proof}
                          </div>
                        </div>
                        <div className="flex gap-2 w-full md:w-auto">
                          <button 
                            onClick={() => handleConfirmAction(action.id, 'rejected')}
                            className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2 border border-danger/30 text-danger rounded hover:bg-danger hover:text-text-inverse transition-all text-[10px] font-black"
                          >
                            <UserX className="w-4 h-4" /> REJECT
                          </button>
                          <button 
                            onClick={() => handleConfirmAction(action.id, 'approved')}
                            className="flex-1 md:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-accent text-white rounded hover:bg-accent-hover transition-all text-[10px] font-black shadow-lg"
                          >
                            <UserCheck className="w-4 h-4" /> APPROVE
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.section>
              )}
            </AnimatePresence>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 min-h-0 flex-1">
              {/* Behavioral Graph Summary (Phase 3) */}
              <section className="bg-panel border border-border rounded-lg flex flex-col shadow-sm overflow-hidden">
                <div className="px-4 py-3 bg-bg-secondary border-b border-border flex items-center justify-between">
                  <h3 className="text-[10px] uppercase tracking-widest font-black text-text-muted">Behavioral Graph Engine</h3>
                  <Share2 className="w-3 h-3 text-text-muted" />
                </div>
                <div className="p-4 flex-1 overflow-auto">
                  {pipelineResult?.graph ? (
                    <div className="space-y-4">
                      <div className="flex gap-4">
                        <div className="flex-1 p-3 bg-bg rounded border border-border text-center">
                          <span className="block text-xl font-black">{pipelineResult.graph.nodes.length}</span>
                          <span className="text-[9px] uppercase font-bold text-text-muted italic">Entity Nodes</span>
                        </div>
                        <div className="flex-1 p-3 bg-bg rounded border border-border text-center">
                          <span className="block text-xl font-black">{pipelineResult.graph.edges.length}</span>
                          <span className="text-[9px] uppercase font-bold text-text-muted italic">Interaction Edges</span>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <h4 className="text-[10px] font-bold text-text-muted uppercase">Recent Relationships</h4>
                        {pipelineResult.graph.edges.slice(0, 4).map((edge, i) => (
                           <div key={i} className="text-[11px] p-2 bg-bg-secondary/50 border border-border/50 rounded flex items-center gap-2">
                             <span className="font-bold text-accent">{edge.source}</span>
                             <span className="text-text-muted">→</span>
                             <span className="font-bold text-text-main">{edge.target}</span>
                             <span className="ml-auto text-[9px] bg-panel px-1 rounded border border-border text-text-main">{edge.action}</span>
                           </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="h-full flex flex-col items-center justify-center text-center p-8 opacity-40">
                      <Share2 className="w-12 h-12 mb-3" />
                      <p className="text-xs font-medium text-text-main">Awaiting normalization to build relationships.</p>
                    </div>
                  )}
                </div>
              </section>

              {/* Detections (Phase 4) */}
              <section className="bg-panel border border-border rounded-lg flex flex-col shadow-sm overflow-hidden">
                <div className="px-4 py-3 bg-bg-secondary border-b border-border flex items-center justify-between">
                  <h3 className="text-[10px] uppercase tracking-widest font-black text-text-muted">Logic Core: Detections</h3>
                  <ShieldAlert className="w-3 h-3 text-danger" />
                </div>
                <div className="p-4 flex-1 overflow-auto">
                   <div className="space-y-3">
                    <AnimatePresence mode="popLayout">
                      {!pipelineResult?.detections.length ? (
                        <div className="p-8 text-center text-text-muted italic text-[11px] border border-dashed border-border rounded">
                          No active threat patterns detected in sequence.
                        </div>
                      ) : (
                        pipelineResult.detections.map((det, i) => (
                          <motion.div 
                            key={i}
                            layout
                            initial={{ opacity: 0, scale: 0.95 }}
                            animate={{ opacity: 1, scale: 1 }}
                            className="p-3 bg-panel border border-border rounded flex items-start gap-3 hover:border-accent transition-colors group"
                          >
                            <div className="p-1.5 bg-danger/10 rounded-sm text-danger shrink-0">
                               <ShieldAlert className="w-4 h-4" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-[10px] font-black uppercase text-danger tracking-tighter">{det.type.replace('_', ' ')}</span>
                                <span className="text-[10px] font-mono font-bold">Conf: {Math.round(det.confidence * 100)}%</span>
                              </div>
                              <p className="text-[11px] font-medium text-text-main leading-tight mb-2">Evidence link to {det.evidence.length} correlated events.</p>
                              <div className="flex flex-wrap gap-1">
                                {det.entities.map(e => <span key={e} className="text-[9px] bg-bg px-1.5 py-0.5 rounded border border-border font-mono">{e}</span>)}
                              </div>
                            </div>
                          </motion.div>
                        ))
                      )}
                    </AnimatePresence>
                   </div>
                </div>
              </section>
            </div>

            {/* AI Explanation & Analysis (Phase 5) */}
            <section className="bg-panel border border-border rounded-lg flex flex-col shadow-sm overflow-hidden">
               <div className="px-4 py-3 bg-bg-secondary border-b border-border flex items-center justify-between">
                  <h3 className="text-[10px] uppercase tracking-widest font-black text-text-muted">AI Neural Explanation (Non-Decision)</h3>
                  <div className={`px-2 py-0.5 rounded-full text-[9px] font-black uppercase text-white ${
                    pipelineResult?.ai_report.risk === 'HIGH' ? 'bg-danger' : 'bg-success'
                  }`}>
                    Risk: {pipelineResult?.ai_report.risk || 'NONE'}
                  </div>
                </div>
                <div className="p-5 flex gap-6">
                  <div className="flex-1 space-y-4">
                    <div>
                      <h4 className="text-[10px] font-black uppercase text-text-muted mb-2 tracking-widest flex items-center gap-2">
                        <FileSearch className="w-3 h-3" /> System Logic translation
                      </h4>
                      <p className="text-sm font-semibold leading-relaxed text-text-main line-clamp-3 italic">
                        {pipelineResult?.ai_report.explanation || "System is idle. Run pipeline ingestion to begin AI-driven threat contextualization."}
                      </p>
                    </div>
                  </div>
                  <div className="w-[200px] shrink-0 p-4 bg-bg rounded-lg border border-border flex flex-col items-center justify-center text-center">
                    <h5 className="text-[10px] font-bold text-text-muted uppercase mb-2">Recommended State</h5>
                    <div className="text-xs font-black text-accent mb-1 underline underline-offset-4">
                      {pipelineResult?.ai_report.recommended_action || "CONTINUE_LOG_WATCH"}
                    </div>
                    <p className="text-[9px] text-text-muted italic leading-tight">Suggested by Neural Layer based on graph context.</p>
                  </div>
                </div>
            </section>
          </div>

          {/* Right Column: SOAR & Audit Log (Phases 6 & 7) */}
          <div className="flex flex-col gap-5 h-full min-h-0">
             {/* SOAR Engine (Phase 6) */}
             <section className="bg-panel border border-border rounded-lg flex flex-col shadow-sm shrink-0">
                <div className="px-4 py-3 bg-bg-secondary border-b border-border flex items-center justify-between">
                  <h3 className="text-[10px] uppercase tracking-widest font-black text-text-muted font-mono">SOAR Playbook Execution</h3>
                  <Zap className="w-3 h-3 text-warning fill-current" />
                </div>
                <div className="p-4 space-y-3 max-h-[200px] overflow-auto">
                   <AnimatePresence mode="popLayout">
                    {!pipelineResult?.soar_actions.length ? (
                      <div className="p-4 text-center text-text-muted border border-dashed border-border rounded text-[10px] italic">
                         Waiting for high-confidence detections...
                      </div>
                    ) : (
                      pipelineResult.soar_actions.map((act, i) => (
                        <motion.div 
                          key={i}
                          initial={{ x: 20, opacity: 0 }}
                          animate={{ x: 0, opacity: 1 }}
                          className={`p-3 bg-bg border border-border border-l-4 rounded-r-md flex items-center justify-between group ${
                            act.status === 'pending' ? 'border-l-warning' : 'border-l-success'
                          }`}
                        >
                          <div>
                            <div className="text-[10px] font-black tracking-tighter text-text-main uppercase mb-0.5">{act.action}</div>
                            <div className="text-[9px] text-text-muted font-bold truncate max-w-[180px]">{act.target}</div>
                          </div>
                          <div className={`text-[8px] p-1 rounded font-black ${
                            act.status === 'pending' ? 'bg-warning/20 text-warning' : 'bg-success/20 text-success'
                          }`}>
                            {act.status.toUpperCase()}
                          </div>
                        </motion.div>
                      ))
                    )}
                   </AnimatePresence>
                </div>
             </section>

             {/* Detailed Logs Integrated (Final State / Audit) */}
             <section className="bg-sidebar border border-border rounded-lg flex-1 min-h-0 overflow-hidden shadow-xl flex flex-col">
               <LogViewer />
             </section>
          </div>
        </main>
      </div>

      {/* Neural Reasoning Toast Overlay */}
      <AnimatePresence>
        {isProcessing && (
          <motion.div 
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0, scale: 0.95 }}
            className="fixed bottom-6 right-6 bg-accent text-white px-6 py-3 rounded-xl shadow-[0_10px_30px_rgba(0,122,255,0.4)] flex items-center gap-4 z-[100] border border-white/20"
          >
            <div className="flex gap-1.5">
              {[0, 1, 2].map(i => (
                <motion.div 
                  key={i}
                  animate={{ scale: [1, 1.4, 1], opacity: [0.3, 1, 0.3] }}
                  transition={{ repeat: Infinity, duration: 1, delay: i * 0.2 }}
                  className="w-2 h-2 bg-white rounded-full shadow-sm"
                />
              ))}
            </div>
            <div className="flex flex-col">
              <span className="text-[11px] font-black uppercase tracking-[0.2em]">Neural Engine v2.0</span>
              <span className="text-[9px] font-mono text-white/70">Executing Phase {activePhase || 1}...</span>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}


