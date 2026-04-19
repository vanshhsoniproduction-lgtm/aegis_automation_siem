import React, { useState, useEffect, useCallback, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Shield, Activity, Terminal, Globe, Clock, ChevronRight,
  Ban, Plus, Search, Filter, X, User, Zap, AlertTriangle,
  CheckCircle, XCircle, Eye, Cpu, Network, Radar,
  BarChart3, TrendingUp, Lock, Unlock, FileText, Play, StopCircle,
  Settings, LayoutDashboard, History, ChevronDown
} from 'lucide-react';
import { PipelineResult, SOARAction, SIEMLog, LogType } from './types';
import { GeminiService } from './services/geminiService';
import { PipelineService } from './services/pipelineService';
import { SOARService } from './services/soarService';
import { SecurityGraphView } from './components/SecurityGraph';
import { loggingService } from './services/loggingService';

type Page = 'dashboard' | 'firewall' | 'history' | 'logs' | 'settings';

// ─── Terminal Pipeline Component ───
const PipelineTerminal: React.FC<{ lines: string[]; isRunning: boolean }> = ({ lines, isRunning }) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  useEffect(() => { scrollRef.current?.scrollTo(0, scrollRef.current.scrollHeight); }, [lines]);

  return (
    <div className="bg-[#0A0A0C] border border-border/60 rounded-xl overflow-hidden font-mono text-[11px]">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border/40 bg-[#111114]">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-[#F28B82]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#FDD663]" />
          <div className="w-2.5 h-2.5 rounded-full bg-[#81C995]" />
        </div>
        <span className="text-text-muted text-[10px] ml-2 tracking-wider">aegis — neural-pipeline</span>
        {isRunning && <span className="ml-auto text-accent text-[9px] font-bold animate-pulse tracking-widest">● LIVE</span>}
      </div>
      <div ref={scrollRef} className="p-4 max-h-[280px] overflow-y-auto space-y-0.5">
        {lines.map((line, i) => (
          <div key={i} className="flex gap-2 leading-relaxed">
            <span className="text-text-muted/40 select-none w-6 text-right shrink-0">{String(i+1).padStart(3)}</span>
            <span className={
              line.startsWith('[OK]') ? 'text-success' :
              line.startsWith('[!]') ? 'text-danger' :
              line.startsWith('[→]') ? 'text-accent' :
              line.startsWith('[◆]') ? 'text-warning' :
              line.startsWith('[✓]') ? 'text-success font-bold' :
              'text-text-muted/70'
            }>{line}</span>
          </div>
        ))}
        {isRunning && (
          <div className="flex gap-2">
            <span className="text-text-muted/40 select-none w-6 text-right shrink-0">{String(lines.length+1).padStart(3)}</span>
            <span className="text-accent">
              <span className="animate-terminal-blink">▊</span>
            </span>
          </div>
        )}
      </div>
    </div>
  );
};

// ─── Stat Card ───
const StatCard: React.FC<{ label: string; value: string | number; icon: React.ReactNode; accent?: string; onClick?: () => void }> = ({ label, value, icon, accent, onClick }) => (
  <div onClick={onClick} className={`bg-panel border border-border/60 rounded-xl p-5 flex items-center gap-4 hover:border-accent/40 transition-all ${onClick ? 'cursor-pointer' : ''}`}>
    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${accent || 'bg-accent/10 text-accent'}`}>
      {icon}
    </div>
    <div className="flex-1">
      <div className="text-xl font-black tracking-tight">{value}</div>
      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest">{label}</div>
    </div>
    {onClick && <ChevronRight size={14} className="text-text-muted/40" />}
  </div>
);

export default function App() {
  const [page, setPage] = useState<Page>('dashboard');
  const [result, setResult] = useState<PipelineResult | null>(null);
  const [isProcessing, setIsProcessing] = useState(false);
  const isProcessingRef = useRef(false);
  const [agentStatus, setAgentStatus] = useState({ isRunning: false, output: [] as string[] });
  const [terminalLines, setTerminalLines] = useState<string[]>(['[→] Aegis Neural Pipeline v2.1 initialized', '[OK] Awaiting ingestion command...']);
  const [pendingActions, setPendingActions] = useState<SOARAction[]>([]);
  const [blockedIPs, setBlockedIPs] = useState<any[]>([]);
  const [allBlocked, setAllBlocked] = useState<any[]>([]);
  const [auditHistory, setAuditHistory] = useState<any[]>([]);
  const [patterns, setPatterns] = useState<any[]>([]);
  const [stats, setStats] = useState<any>({});
  const [logs, setLogs] = useState<SIEMLog[]>([]);
  const [logFilter, setLogFilter] = useState('');
  const [logTypeFilter, setLogTypeFilter] = useState<string>('ALL');
  const [profile, setProfile] = useState({ username: 'Operator', role: 'Security Analyst' });
  const [editingName, setEditingName] = useState('');
  const [isEditingName, setIsEditingName] = useState(false);
  const [threshold, setThreshold] = useState(3);
  const [blockIpInput, setBlockIpInput] = useState('');
  const [blockReasonInput, setBlockReasonInput] = useState('');
  const [showManualIngest, setShowManualIngest] = useState(false);
  const [manualLogText, setManualLogText] = useState('');
  const [expandedHistoryItem, setExpandedHistoryItem] = useState<string | null>(null);
  const [firewallTab, setFirewallTab] = useState<'active' | 'all'>('active');
  const [statPopup, setStatPopup] = useState<string | null>(null);
  const [scanHistory, setScanHistory] = useState<Array<{ id: string; timestamp: string; result: PipelineResult; terminalLog: string[] }>>([]);
  const [historyTab, setHistoryTab] = useState<'timeline' | 'scans'>('timeline');
  const [expandedScan, setExpandedScan] = useState<string | null>(null);

  const fetchAll = useCallback(async () => {
    const [p, pts, active, all, hist, prof, st, lg, scans, agentSt] = await Promise.all([
      SOARService.getPendingActions(), SOARService.getPatterns(),
      SOARService.getActiveBlocks(), SOARService.getBlockedIPs(),
      SOARService.getAuditLog(), SOARService.getProfile(),
      SOARService.getStats(), loggingService.getLogs(),
      SOARService.getScans(), SOARService.getAgentStatus()
    ]);
    setPendingActions(p); setPatterns(pts);
    setBlockedIPs(active); setAllBlocked(all);
    setAuditHistory(hist); setStats(st);
    setLogs(lg.reverse());
    setScanHistory(scans);
    setAgentStatus(agentSt || { isRunning: false, output: [] });
    if (prof?.username) {
      setProfile(prof);
    }
  }, []);

  const runPipelineRef = useRef<any>(null);

  useEffect(() => {
    fetchAll();
    const tick = async () => {
      await fetchAll();
      if (!isProcessingRef.current) {
        const buffered = await SOARService.getBufferedAgentLogs();
        if (buffered && buffered.length > 0 && runPipelineRef.current) {
          await SOARService.clearBufferedAgentLogs();
          runPipelineRef.current(buffered);
        }
      }
    };
    const i = setInterval(tick, 1500);
    if ("Notification" in window && Notification.permission === "default") {
      Notification.requestPermission();
    }
    return () => clearInterval(i);
  }, [fetchAll]);

  const addTermLine = (line: string) => setTerminalLines(prev => [...prev, line]);

  const runPipeline = useCallback(async (customLogs?: any[]) => {
    isProcessingRef.current = true;
    setIsProcessing(true);
    setTerminalLines(['[→] Aegis Neural Pipeline v2.1 — Scan Initiated']);

    const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));
    
    // Check if we have logs buffered from the live Mac Agent/Attacker process
    let logs = customLogs;
    if (!logs) {
      const buffered = await SOARService.getBufferedAgentLogs();
      if (buffered && buffered.length > 0) {
        logs = buffered;
        await SOARService.clearBufferedAgentLogs();
      } else {
        logs = GeminiService.generateSampleRawLogs();
      }
    }

    addTermLine(`[→] Phase 1: INGESTION — Loading ${logs.length} raw events`);
    await sleep(500);
    addTermLine(`[OK] Ingested ${logs.length} log entries from source buffer`);

    addTermLine(`[→] Phase 2: NORMALIZATION — Mapping heterogeneous fields`);
    await sleep(400);
    addTermLine(`[OK] Fields mapped: src_ip → source_ip, usr → user`);
    addTermLine(`[OK] Schema validation passed — 0 null fields`);

    addTermLine(`[→] Phase 3: GRAPH ENGINE — Building entity relationships`);
    await sleep(500);

    addTermLine(`[→] Phase 4: DETECTION — Applying ${threshold}-attempt brute force rule`);
    await sleep(400);

    addTermLine(`[→] Phase 5: NEURAL REASONING — Querying Gemini for contextual analysis`);
    addTermLine(`[◆] Model: gemini-3-flash-preview | Schema: AIReport`);
    await sleep(300);

    try {
      const pipelineResult = await PipelineService.runFullPipeline(logs, threshold);
      setResult(pipelineResult);

      addTermLine(`[OK] Graph: ${pipelineResult.graph.nodes.length} nodes, ${pipelineResult.graph.edges.length} edges`);
      addTermLine(`[OK] Detections: ${pipelineResult.detections.length} threat(s) identified`);

      if (pipelineResult.detections.length > 0 && "Notification" in window && Notification.permission === "granted") {
        const topThreat = pipelineResult.detections[0];
        new Notification("⚠️ Aegis: Threat Detected!", {
          body: `Detected ${pipelineResult.detections.length} threat(s). Top threat: ${topThreat.type.toUpperCase()} (${Math.round(topThreat.confidence * 100)}% confidence).`,
        });
      }

      pipelineResult.detections.forEach(det => {
        addTermLine(`[!] THREAT: ${det.type.toUpperCase()} — ${Math.round(det.confidence * 100)}% confidence`);
        addTermLine(`    Entities: ${det.entities.join(', ')}`);
      });

      addTermLine(`[→] Phase 6: SOAR — Generating automated response playbooks`);
      await sleep(300);
      pipelineResult.soar_actions.forEach(act => {
        addTermLine(`[◆] Action: ${act.action} → ${act.target} [${act.status}]`);
      });

      addTermLine(`[→] Phase 7: AUDIT — Writing results to persistent store`);
      await sleep(200);
      addTermLine(`[✓] Pipeline complete — ${pipelineResult.detections.length} threats, ${pipelineResult.soar_actions.length} actions queued`);

      // Save to scan history
      const scanEntry = {
        id: `SCAN-${Date.now()}`,
        timestamp: new Date().toISOString(),
        result: pipelineResult,
        terminalLog: [...terminalLines, `[✓] Pipeline complete — ${pipelineResult.detections.length} threats, ${pipelineResult.soar_actions.length} actions queued`]
      };
      
      await SOARService.saveScan(scanEntry);
      
      addTermLine(`[✓] Pipeline complete — ${pipelineResult.detections.length} threats, ${pipelineResult.soar_actions.length} actions queued`);
    } catch (err) {
      addTermLine(`[!] PIPELINE FAILURE: ${err}`);
    }

    isProcessingRef.current = false;
    setIsProcessing(false);
    fetchAll();
  }, [threshold, fetchAll]);

  useEffect(() => {
    runPipelineRef.current = runPipeline;
  }, [runPipeline]);

  const handleConfirm = async (id: string, status: 'approved' | 'rejected') => {
    if (await SOARService.confirmAction(id, status)) fetchAll();
  };

  const handleBlock = async () => {
    if (!blockIpInput.trim()) return;
    if (await SOARService.blockIP(blockIpInput.trim(), blockReasonInput.trim() || 'Manually blocked')) {
      setBlockIpInput(''); setBlockReasonInput(''); fetchAll();
    }
  };

  const handleUnblock = async (ip: string) => {
    if (await SOARService.unblockIP(ip)) fetchAll();
  };

  const handleSaveName = async () => {
    if (editingName.trim() && editingName !== profile.username) {
      await SOARService.updateProfile(editingName.trim());
      setProfile(prev => ({ ...prev, username: editingName.trim() }));
    }
    setIsEditingName(false);
  };

  const handleClearLogs = async () => {
    await SOARService.clearSystemLogs();
    fetchAll();
  };

  const handleManualIngest = () => {
    try {
      const parsed = JSON.parse(manualLogText);
      runPipeline(Array.isArray(parsed) ? parsed : [parsed]);
      setShowManualIngest(false);
      setManualLogText('');
    } catch { alert('Invalid JSON'); }
  };

  // Aggregations for history
  const threatCounts = auditHistory.reduce((acc: Record<string, number>, e) => {
    acc[e.action] = (acc[e.action] || 0) + 1; return acc;
  }, {});

  const filteredLogs = logs.filter(l => {
    const matchesType = logTypeFilter === 'ALL' || l.type === logTypeFilter;
    const matchesSearch = !logFilter || JSON.stringify(l).toLowerCase().includes(logFilter.toLowerCase());
    return matchesType && matchesSearch;
  });

  const nav = [
    { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
    { id: 'firewall', label: 'Firewall', icon: <Shield size={18} />, badge: blockedIPs.length },
    { id: 'history', label: 'History', icon: <History size={18} /> },
    { id: 'logs', label: 'Logs', icon: <Terminal size={18} /> },
    { id: 'settings', label: 'Settings', icon: <Settings size={18} /> },
  ];

  return (
    <div className="min-h-screen bg-bg text-text-main font-sans flex">
      {/* ═══ SIDEBAR ═══ */}
      <aside className="w-[260px] bg-sidebar border-r border-border/50 flex flex-col h-screen sticky top-0 shrink-0">
        {/* Logo */}
        <div className="px-6 py-6 flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-accent/15 flex items-center justify-center">
            <Radar size={20} className="text-accent" />
          </div>
          <div>
            <div className="text-sm font-black tracking-tight">AEGIS</div>
            <div className="text-[9px] font-bold text-text-muted tracking-[0.3em]">SIEM PLATFORM</div>
          </div>
        </div>

        {/* Nav */}
        <nav className="flex-1 px-3 py-2 space-y-0.5">
          <div className="px-3 py-2 text-[9px] font-bold text-text-muted/60 uppercase tracking-[0.25em]">Navigation</div>
          {nav.map(item => (
            <button
              key={item.id}
              onClick={() => setPage(item.id as Page)}
              className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-[13px] font-semibold transition-all group ${
                page === item.id ? 'bg-accent/12 text-accent' : 'text-text-muted hover:text-text-main hover:bg-white/[0.03]'
              }`}
            >
              <span className={page === item.id ? 'text-accent' : 'text-text-muted/70 group-hover:text-text-main'}>{item.icon}</span>
              <span>{item.label}</span>
              {item.badge ? <span className="ml-auto text-[9px] font-black bg-danger/20 text-danger px-1.5 py-0.5 rounded">{item.badge}</span> : null}
            </button>
          ))}
        </nav>

        {/* Profile */}
        <div className="p-4 border-t border-border/30">
          <div className="flex items-center gap-3 px-2">
            <div className="w-8 h-8 rounded-full bg-accent/10 flex items-center justify-center text-accent text-sm font-black">
              {profile.username.charAt(0).toUpperCase()}
            </div>
            <div className="min-w-0">
              <div className="text-xs font-bold truncate">{profile.username}</div>
              <div className="text-[9px] text-text-muted truncate">{profile.role}</div>
            </div>
          </div>
        </div>
      </aside>

      {/* ═══ MAIN ═══ */}
      <div className="flex-1 flex flex-col min-h-screen">
        {/* Header */}
        <header className="h-14 border-b border-border/40 bg-bg flex items-center justify-between px-8 sticky top-0 z-40 backdrop-blur-xl">
          <div className="flex items-center gap-4">
            <h1 className="text-[15px] font-bold capitalize">{page}</h1>
            <div className="flex items-center gap-1.5 text-[10px] font-bold text-success">
              <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
              <span className="tracking-wider">Synchronized</span>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => setShowManualIngest(!showManualIngest)} className="flex items-center gap-2 px-3 py-1.5 border border-border/60 rounded-lg text-[11px] font-bold text-text-muted hover:border-accent hover:text-accent transition-all">
              <FileText size={13} /> Ingest
            </button>
            <button onClick={() => runPipeline()} disabled={isProcessing} className="flex items-center gap-2 px-4 py-1.5 bg-accent text-text-inverse rounded-lg text-[11px] font-bold hover:bg-accent-hover transition-all disabled:opacity-40 shadow-sm shadow-accent/20">
              <Play size={13} /> Scan
            </button>
          </div>
        </header>

        {/* Content */}
        <main className="flex-1 overflow-y-auto">
          <div className="max-w-[1400px] mx-auto p-6 md:p-8">
            <AnimatePresence mode="wait">
              {/* ═══════════════ DASHBOARD ═══════════════ */}
              {page === 'dashboard' && (
                <motion.div key="dash" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-6">
                  {/* Stats */}
                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                    <StatCard label="Total Events" value={stats.totalEvents || 0} icon={<Activity size={18} />} onClick={() => setStatPopup('events')} />
                    <StatCard label="Active Blocks" value={stats.activeBlocks || 0} icon={<Ban size={18} />} accent="bg-danger/10 text-danger" onClick={() => setStatPopup('blocks')} />
                    <StatCard label="Detections" value={result?.detections.length || 0} icon={<AlertTriangle size={18} />} accent="bg-warning/10 text-warning" onClick={() => setStatPopup('detections')} />
                    <StatCard label="Patterns" value={patterns.length} icon={<Radar size={18} />} accent="bg-success/10 text-success" onClick={() => setStatPopup('patterns')} />
                  </div>

                  {/* Stat Detail Popup */}
                  <AnimatePresence>
                    {statPopup && (
                      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 bg-black/60 backdrop-blur-sm z-[100] flex items-center justify-center p-8" onClick={() => setStatPopup(null)}>
                        <motion.div initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }} exit={{ scale: 0.95, opacity: 0 }} onClick={e => e.stopPropagation()} className="bg-panel border border-border/60 rounded-2xl w-full max-w-2xl max-h-[80vh] overflow-hidden shadow-2xl">
                          <div className="px-6 py-4 border-b border-border/40 flex items-center justify-between">
                            <h3 className="text-sm font-bold capitalize">
                              {statPopup === 'events' && 'All Audit Events'}
                              {statPopup === 'blocks' && 'Active Blocked IPs'}
                              {statPopup === 'detections' && 'Current Detections'}
                              {statPopup === 'patterns' && 'Known Attack Patterns'}
                            </h3>
                            <button onClick={() => setStatPopup(null)} className="p-1 hover:bg-white/5 rounded-lg transition-all"><X size={16} className="text-text-muted" /></button>
                          </div>
                          <div className="p-5 max-h-[60vh] overflow-y-auto space-y-2">
                            {statPopup === 'events' && auditHistory.map((e, i) => (
                              <div key={i} className="flex items-center gap-3 p-3 bg-bg border border-border/30 rounded-lg text-[11px]">
                                <span className={`w-2 h-2 rounded-full shrink-0 ${e.status === 'approved' ? 'bg-success' : e.status === 'rejected' ? 'bg-danger' : 'bg-warning'}`} />
                                <span className="font-mono text-text-muted w-[130px] shrink-0">{new Date(e.timestamp).toLocaleString()}</span>
                                <span className="font-bold text-accent w-[90px] shrink-0">{e.action}</span>
                                <span className="font-mono truncate flex-1">{e.target}</span>
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${e.status === 'approved' ? 'bg-success/15 text-success' : e.status === 'rejected' ? 'bg-danger/15 text-danger' : 'bg-warning/15 text-warning'}`}>{e.status}</span>
                              </div>
                            ))}
                            {statPopup === 'blocks' && (blockedIPs.length === 0 ? (
                              <div className="py-10 text-center text-text-muted/40 text-xs">No active blocks</div>
                            ) : blockedIPs.map((ip, i) => (
                              <div key={i} className="flex items-center gap-3 p-3 bg-bg border border-danger/20 rounded-lg text-[11px]">
                                <Lock size={13} className="text-danger shrink-0" />
                                <span className="font-mono font-bold flex-1">{ip.ip}</span>
                                <span className="text-text-muted truncate max-w-[200px]">{ip.reason}</span>
                                <button onClick={() => { handleUnblock(ip.ip); setStatPopup(null); }} className="text-[9px] font-bold text-success px-2 py-1 border border-success/30 rounded hover:bg-success hover:text-white transition-all">Unblock</button>
                              </div>
                            )))}
                            {statPopup === 'detections' && (!result?.detections.length ? (
                              <div className="py-10 text-center text-text-muted/40 text-xs">Run a scan to see detections</div>
                            ) : result.detections.map((det, i) => (
                              <div key={i} className="p-4 bg-bg border border-border/30 rounded-lg border-l-2 border-l-danger space-y-2">
                                <div className="flex justify-between">
                                  <span className="text-xs font-bold text-danger uppercase">{det.type.replace('_', ' ')}</span>
                                  <span className="text-[10px] font-mono">{Math.round(det.confidence * 100)}% confidence</span>
                                </div>
                                <div className="text-[11px] text-text-muted">Evidence: {det.evidence.length} correlated events</div>
                                <div className="flex flex-wrap gap-1.5">
                                  {det.entities.map(e => (
                                    <span key={e} className="text-[9px] font-mono bg-panel px-2 py-1 rounded border border-border/40 flex items-center gap-1.5">
                                      {e}
                                      {/^\d+\.\d+\.\d+\.\d+$/.test(e) && (
                                        <button onClick={() => { SOARService.blockIP(e, `Blocked from detection: ${det.type}`).then(() => fetchAll()); }} className="text-[8px] font-black text-danger bg-danger/10 px-1 py-0.5 rounded hover:bg-danger hover:text-white transition-all">BLOCK</button>
                                      )}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )))}
                            {statPopup === 'patterns' && patterns.map((p, i) => (
                              <div key={i} className="flex items-center justify-between p-3 bg-bg border border-border/30 rounded-lg">
                                <div>
                                  <div className="text-xs font-bold">{p.type}</div>
                                  <div className="text-[10px] text-text-muted truncate max-w-[350px]">{p.description}</div>
                                </div>
                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${p.severity === 'Critical' ? 'bg-danger/15 text-danger' : p.severity === 'High' ? 'bg-warning/15 text-warning' : 'bg-accent/15 text-accent'}`}>{p.severity}</span>
                              </div>
                            ))}
                          </div>
                        </motion.div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Manual Ingest */}
                  <AnimatePresence>
                    {showManualIngest && (
                      <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                        <div className="bg-panel border border-border/60 rounded-xl p-5">
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-bold text-text-muted">Raw JSON Log Ingestion</span>
                            <button onClick={() => setShowManualIngest(false)}><X size={14} className="text-text-muted" /></button>
                          </div>
                          <textarea value={manualLogText} onChange={e => setManualLogText(e.target.value)} placeholder='[{"ip":"1.2.3.4","action":"LOGIN","status":"FAILURE","user":"root"}]' className="w-full h-28 bg-bg border border-border/40 rounded-lg p-3 font-mono text-[11px] focus:ring-1 focus:ring-accent outline-none resize-none mb-3" />
                          <button onClick={handleManualIngest} className="px-5 py-2 bg-accent text-text-inverse rounded-lg text-[11px] font-bold">Process</button>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  {/* Pending */}
                  {pendingActions.length > 0 && (
                    <div className="bg-panel border border-accent/30 rounded-xl p-5 space-y-3">
                      <div className="flex items-center gap-3 mb-1">
                        <Zap size={18} className="text-accent" />
                        <span className="text-sm font-bold">Pending Authorization</span>
                        <span className="text-[10px] font-bold text-accent bg-accent/10 px-2 py-0.5 rounded">{pendingActions.length}</span>
                      </div>
                      {pendingActions.map(a => (
                        <div key={a.id} className="flex items-center gap-4 p-4 bg-bg border border-border/40 rounded-xl">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="text-[11px] font-bold text-accent bg-accent/10 px-2 py-0.5 rounded">{a.action}</span>
                              <span className="text-xs font-mono truncate">{a.target}</span>
                            </div>
                            <p className="text-[11px] text-text-muted truncate">{a.reason}</p>
                          </div>
                          <div className="flex gap-2 shrink-0">
                            <button onClick={() => handleConfirm(a.id, 'rejected')} className="p-2 rounded-lg border border-danger/30 text-danger hover:bg-danger hover:text-white transition-all"><XCircle size={16} /></button>
                            <button onClick={() => handleConfirm(a.id, 'approved')} className="p-2 rounded-lg bg-accent text-text-inverse hover:bg-accent-hover transition-all"><CheckCircle size={16} /></button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Terminal + Graph row */}
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-[10px] font-bold text-text-muted uppercase tracking-widest px-1">
                        <Terminal size={12} /> Pipeline Output
                      </div>
                      <PipelineTerminal lines={terminalLines} isRunning={isProcessing} />
                    </div>
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-[10px] font-bold text-text-muted uppercase tracking-widest px-1">
                        <Network size={12} /> Entity Relationship Map
                      </div>
                      <SecurityGraphView graph={result?.graph || null} height={312} />
                    </div>
                  </div>

                  {/* Detections + AI */}
                  <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
                    {/* Detections */}
                    <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                      <div className="px-5 py-3 border-b border-border/40 flex items-center justify-between">
                        <span className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-2"><AlertTriangle size={13} className="text-danger" /> Detections</span>
                      </div>
                      <div className="p-4 space-y-2 max-h-[300px] overflow-y-auto">
                        {!result?.detections.length ? (
                          <div className="py-10 text-center text-text-muted/40 text-xs italic">No active threats</div>
                        ) : result.detections.map((det, i) => (
                          <div key={i} className="p-3 bg-bg border border-border/30 rounded-lg border-l-2 border-l-danger">
                            <div className="flex justify-between mb-1.5">
                              <span className="text-[11px] font-bold text-danger uppercase">{det.type.replace('_', ' ')}</span>
                              <span className="text-[10px] font-mono text-text-muted">{Math.round(det.confidence * 100)}%</span>
                            </div>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {det.entities.map(e => (
                                <span key={e} className="text-[9px] font-mono bg-panel px-1.5 py-0.5 rounded border border-border/40 flex items-center gap-1.5">
                                  {e}
                                  {/^\d+\.\d+\.\d+\.\d+$/.test(e) && (
                                    <button
                                      onClick={() => SOARService.blockIP(e, `Blocked from detection: ${det.type}`).then(() => { fetchAll(); addTermLine(`[!] MANUAL BLOCK: ${e} added to firewall denylist`); })}
                                      className="text-[8px] font-black text-danger bg-danger/10 px-1 py-0.5 rounded hover:bg-danger hover:text-white transition-all ml-0.5"
                                    >BLOCK</button>
                                  )}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* AI Report */}
                    <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                      <div className="px-5 py-3 border-b border-border/40 flex items-center justify-between">
                        <span className="text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-2"><Cpu size={13} className="text-accent" /> Neural Analysis</span>
                        <div className="flex items-center gap-2">
                          {result?.ai_report.mitre_id && <span className="text-[9px] font-bold text-accent bg-accent/10 px-1.5 py-0.5 rounded border border-accent/20">{result.ai_report.mitre_id}</span>}
                          <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${result?.ai_report.risk === 'HIGH' ? 'bg-danger/15 text-danger' : 'bg-success/15 text-success'}`}>{result?.ai_report.risk || 'IDLE'}</span>
                        </div>
                      </div>
                      <div className="p-5 space-y-4 max-h-[300px] overflow-y-auto">
                        <p className="text-[13px] font-medium text-text-main/80 italic leading-relaxed">
                          {result?.ai_report.explanation || 'Awaiting pipeline execution for contextual threat analysis.'}
                        </p>
                        {result?.ai_report.remediation_code && (
                          <div>
                            <label className="text-[9px] font-bold text-accent uppercase tracking-widest mb-1.5 block">Remediation</label>
                            <pre className="p-3 bg-[#0A0A0C] border border-accent/15 rounded-lg text-[10px] font-mono text-accent/70 overflow-x-auto">{result.ai_report.remediation_code}</pre>
                          </div>
                        )}
                        <div className="pt-2 border-t border-border/30 text-[11px] text-text-muted">
                          <span className="font-bold text-accent">{result?.ai_report.recommended_action || 'IDLE_MONITOR'}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </motion.div>
              )}

              {/* ═══════════════ FIREWALL ═══════════════ */}
              {page === 'firewall' && (
                <motion.div key="fw" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-6">
                  {/* Block custom IP */}
                  <div className="bg-panel border border-border/60 rounded-xl p-5">
                    <div className="flex items-center gap-2 mb-4 text-xs font-bold text-text-muted uppercase tracking-wider">
                      <Plus size={14} className="text-accent" /> Block Custom IP
                    </div>
                    <div className="flex gap-3">
                      <input value={blockIpInput} onChange={e => setBlockIpInput(e.target.value)} placeholder="192.168.1.100" className="flex-1 bg-bg border border-border/40 rounded-lg px-4 py-2.5 text-sm font-mono focus:ring-1 focus:ring-accent outline-none" />
                      <input value={blockReasonInput} onChange={e => setBlockReasonInput(e.target.value)} placeholder="Reason (optional)" className="flex-[2] bg-bg border border-border/40 rounded-lg px-4 py-2.5 text-sm focus:ring-1 focus:ring-accent outline-none" />
                      <button onClick={handleBlock} className="px-6 py-2.5 bg-danger text-white rounded-lg text-xs font-bold hover:bg-danger/80 transition-all flex items-center gap-2"><Ban size={14} /> Block</button>
                    </div>
                  </div>

                  {/* Tabs */}
                  <div className="flex gap-1 bg-panel border border-border/60 rounded-lg p-1 w-fit">
                    {(['active', 'all'] as const).map(tab => (
                      <button key={tab} onClick={() => setFirewallTab(tab)}
                        className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${firewallTab === tab ? 'bg-accent/15 text-accent' : 'text-text-muted hover:text-text-main'}`}>
                        {tab === 'active' ? `Active (${blockedIPs.length})` : `All (${allBlocked.length})`}
                      </button>
                    ))}
                  </div>

                  {/* IP list */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {(firewallTab === 'active' ? blockedIPs : allBlocked).map(ip => (
                      <div key={ip.id} className={`bg-panel border rounded-xl p-4 group transition-all ${ip.active ? 'border-danger/20 hover:border-danger/40' : 'border-border/30 opacity-60'}`}>
                        <div className="flex items-start justify-between mb-2">
                          <div className="flex items-center gap-2">
                            {ip.active ? <Lock size={14} className="text-danger" /> : <Unlock size={14} className="text-success" />}
                            <span className="text-sm font-mono font-bold">{ip.ip}</span>
                          </div>
                          {ip.active && (
                            <button onClick={() => handleUnblock(ip.ip)} className="text-[10px] font-bold text-success px-2.5 py-1 border border-success/30 rounded-lg opacity-0 group-hover:opacity-100 hover:bg-success hover:text-white transition-all">
                              Unblock
                            </button>
                          )}
                        </div>
                        <p className="text-[11px] text-text-muted mb-1">{ip.reason}</p>
                        <span className="text-[9px] font-mono text-text-muted/60">{new Date(ip.blocked_at).toLocaleString()}</span>
                        {!ip.active && <span className="ml-2 text-[9px] font-bold text-success bg-success/10 px-1.5 py-0.5 rounded">Released</span>}
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}

              {/* ═══════════════ HISTORY ═══════════════ */}
              {page === 'history' && (
                <motion.div key="hist" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-6">
                  {/* Summary counts */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(threatCounts).map(([action, count]) => (
                      <div key={action} className="bg-panel border border-border/60 rounded-xl p-4">
                        <div className="text-xl font-black">{count as number}</div>
                        <div className="text-[10px] font-bold text-text-muted uppercase tracking-wider">{action}</div>
                        <div className="mt-2 h-1.5 bg-bg rounded-full overflow-hidden">
                          <div className={`h-full rounded-full ${
                            action === 'BLOCK_IP' ? 'bg-danger' : action === 'ALERT' ? 'bg-warning' : 'bg-accent'
                          }`} style={{ width: `${Math.min(((count as number) / auditHistory.length) * 100, 100)}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Tabs */}
                  <div className="flex gap-1 bg-panel border border-border/60 rounded-lg p-1 w-fit">
                    {(['timeline', 'scans'] as const).map(tab => (
                      <button key={tab} onClick={() => setHistoryTab(tab)}
                        className={`px-4 py-1.5 rounded-md text-xs font-bold transition-all ${
                          historyTab === tab ? 'bg-accent/15 text-accent' : 'text-text-muted hover:text-text-main'
                        }`}>
                        {tab === 'timeline' ? `Timeline (${auditHistory.length})` : `Scan Results (${scanHistory.length})`}
                      </button>
                    ))}
                  </div>

                  {historyTab === 'timeline' && (
                    <>
                      {/* Graph */}
                      {result?.graph && (
                        <div className="space-y-2">
                          <div className="flex items-center gap-2 text-[10px] font-bold text-text-muted uppercase tracking-widest px-1">
                            <Network size={12} /> Historical Entity Map
                          </div>
                          <SecurityGraphView graph={result.graph} height={240} />
                        </div>
                      )}

                      {/* Event Timeline */}
                      <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                        <div className="px-5 py-3 border-b border-border/40 text-[11px] font-bold text-text-muted uppercase tracking-wider flex items-center gap-2">
                          <Clock size={13} /> Event Timeline — {auditHistory.length} total
                        </div>
                        <div className="divide-y divide-border/20">
                          {auditHistory.map((e, idx) => {
                            const isExpanded = expandedHistoryItem === e.id;
                            const duplicateCount = auditHistory.filter(x => x.target === e.target && x.action === e.action).length;
                            return (
                              <div key={idx} className="group">
                                <button onClick={() => setExpandedHistoryItem(isExpanded ? null : e.id)} className="w-full flex items-center gap-4 px-5 py-3 hover:bg-white/[0.02] transition-all text-left">
                                  <span className={`w-2 h-2 rounded-full shrink-0 ${e.status === 'approved' ? 'bg-success' : e.status === 'rejected' ? 'bg-danger' : 'bg-warning'}`} />
                                  <span className="text-[11px] font-mono text-text-muted w-[140px] shrink-0">{new Date(e.timestamp).toLocaleString()}</span>
                                  <span className="text-[11px] font-bold text-accent w-[100px] shrink-0">{e.action}</span>
                                  <span className="text-[11px] font-mono flex-1 truncate">{e.target}</span>
                                  {duplicateCount > 1 && <span className="text-[9px] font-bold bg-warning/15 text-warning px-1.5 py-0.5 rounded">{duplicateCount}x</span>}
                                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${e.status === 'approved' ? 'bg-success/15 text-success' : e.status === 'rejected' ? 'bg-danger/15 text-danger' : 'bg-warning/15 text-warning'}`}>{e.status}</span>
                                  <ChevronDown size={13} className={`text-text-muted transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                                </button>
                                <AnimatePresence>
                                  {isExpanded && (
                                    <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                                      <div className="px-5 pb-4 pt-1 ml-6 border-l-2 border-accent/20 pl-4 space-y-2">
                                        <div className="text-[11px] text-text-muted"><strong className="text-text-main">Reason:</strong> {e.reason}</div>
                                        <div className="text-[11px] text-text-muted"><strong className="text-text-main">Confidence:</strong> {Math.round((e.confidence || 0) * 100)}%</div>
                                        <div className="text-[11px] text-text-muted"><strong className="text-text-main">Proof:</strong> {e.proof}</div>
                                        {duplicateCount > 1 && <div className="text-[10px] font-bold text-warning">⚠ This target has been flagged {duplicateCount} time(s) total</div>}
                                      </div>
                                    </motion.div>
                                  )}
                                </AnimatePresence>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </>
                  )}

                  {historyTab === 'scans' && (
                    <div className="space-y-4">
                      {scanHistory.length === 0 ? (
                        <div className="bg-panel border border-border/60 rounded-xl py-20 text-center">
                          <Radar size={36} className="mx-auto text-text-muted/30 mb-3" />
                          <p className="text-xs text-text-muted/50">No scans recorded yet. Run a pipeline scan to populate results.</p>
                        </div>
                      ) : scanHistory.map(scan => {
                        const isOpen = expandedScan === scan.id;
                        return (
                          <div key={scan.id} className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                            <button onClick={() => setExpandedScan(isOpen ? null : scan.id)} className="w-full flex items-center gap-4 px-6 py-4 hover:bg-white/[0.02] transition-all text-left">
                              <Radar size={16} className="text-accent shrink-0" />
                              <div className="flex-1">
                                <div className="text-xs font-bold">Scan {scan.id}</div>
                                <div className="text-[10px] text-text-muted font-mono">{new Date(scan.timestamp).toLocaleString()}</div>
                              </div>
                              <div className="flex items-center gap-3">
                                <span className="text-[9px] font-bold bg-accent/15 text-accent px-2 py-0.5 rounded">{scan.result.graph.nodes.length} nodes</span>
                                <span className="text-[9px] font-bold bg-danger/15 text-danger px-2 py-0.5 rounded">{scan.result.detections.length} threats</span>
                                <span className="text-[9px] font-bold bg-warning/15 text-warning px-2 py-0.5 rounded">{scan.result.soar_actions.length} actions</span>
                                <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${scan.result.ai_report.risk === 'HIGH' ? 'bg-danger/15 text-danger' : 'bg-success/15 text-success'}`}>{scan.result.ai_report.risk}</span>
                              </div>
                              <ChevronDown size={14} className={`text-text-muted transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                            </button>
                            <AnimatePresence>
                              {isOpen && (
                                <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                                  <div className="border-t border-border/30 p-6 space-y-6">
                                    {/* Phase breakdown grid */}
                                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                                      <div className="bg-bg border border-border/30 rounded-lg p-3 text-center">
                                        <div className="text-lg font-black">{scan.result.graph.nodes.length}</div>
                                        <div className="text-[9px] font-bold text-text-muted uppercase">Graph Nodes</div>
                                      </div>
                                      <div className="bg-bg border border-border/30 rounded-lg p-3 text-center">
                                        <div className="text-lg font-black">{scan.result.graph.edges.length}</div>
                                        <div className="text-[9px] font-bold text-text-muted uppercase">Graph Edges</div>
                                      </div>
                                      <div className="bg-bg border border-border/30 rounded-lg p-3 text-center">
                                        <div className="text-lg font-black text-danger">{scan.result.detections.length}</div>
                                        <div className="text-[9px] font-bold text-text-muted uppercase">Detections</div>
                                      </div>
                                      <div className="bg-bg border border-border/30 rounded-lg p-3 text-center">
                                        <div className="text-lg font-black text-accent">{scan.result.soar_actions.length}</div>
                                        <div className="text-[9px] font-bold text-text-muted uppercase">SOAR Actions</div>
                                      </div>
                                    </div>

                                    {/* Entity Graph */}
                                    <div className="space-y-2">
                                      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest flex items-center gap-2"><Network size={12} /> Entity Map</div>
                                      <SecurityGraphView graph={scan.result.graph} height={200} />
                                    </div>

                                    {/* Detections */}
                                    <div className="space-y-2">
                                      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest flex items-center gap-2"><AlertTriangle size={12} /> Detections</div>
                                      {scan.result.detections.map((det, i) => (
                                        <div key={i} className="p-3 bg-bg border border-border/30 rounded-lg border-l-2 border-l-danger">
                                          <div className="flex justify-between mb-1">
                                            <span className="text-[11px] font-bold text-danger uppercase">{det.type.replace('_', ' ')}</span>
                                            <span className="text-[10px] font-mono text-text-muted">{Math.round(det.confidence * 100)}%</span>
                                          </div>
                                          <div className="flex flex-wrap gap-1">
                                            {det.entities.map(e => <span key={e} className="text-[9px] font-mono bg-panel px-1.5 py-0.5 rounded border border-border/40">{e}</span>)}
                                          </div>
                                        </div>
                                      ))}
                                    </div>

                                    {/* AI Report */}
                                    <div className="space-y-2">
                                      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest flex items-center gap-2"><Cpu size={12} /> AI Neural Report</div>
                                      <div className="p-4 bg-bg border border-border/30 rounded-lg space-y-3">
                                        <div className="flex items-center gap-2">
                                          {scan.result.ai_report.mitre_id && <span className="text-[9px] font-bold bg-accent/15 text-accent px-1.5 py-0.5 rounded">{scan.result.ai_report.mitre_id}</span>}
                                          <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${scan.result.ai_report.risk === 'HIGH' ? 'bg-danger/15 text-danger' : 'bg-success/15 text-success'}`}>{scan.result.ai_report.risk}</span>
                                          <span className="text-[9px] font-bold bg-warning/15 text-warning px-1.5 py-0.5 rounded">{scan.result.ai_report.attack_type}</span>
                                        </div>
                                        <p className="text-[12px] italic text-text-main/80 leading-relaxed">{scan.result.ai_report.explanation}</p>
                                        {scan.result.ai_report.remediation_code && (
                                          <pre className="p-3 bg-[#0A0A0C] border border-accent/15 rounded-lg text-[10px] font-mono text-accent/70 overflow-x-auto">{scan.result.ai_report.remediation_code}</pre>
                                        )}
                                      </div>
                                    </div>

                                    {/* SOAR Actions */}
                                    <div className="space-y-2">
                                      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest flex items-center gap-2"><Zap size={12} /> SOAR Actions</div>
                                      {scan.result.soar_actions.map((act, i) => (
                                        <div key={i} className="flex items-center gap-3 p-3 bg-bg border border-border/30 rounded-lg text-[11px]">
                                          <span className={`w-2 h-2 rounded-full ${act.status === 'approved' ? 'bg-success' : act.status === 'pending' ? 'bg-warning' : 'bg-danger'}`} />
                                          <span className="font-bold text-accent w-[100px]">{act.action}</span>
                                          <span className="font-mono flex-1 truncate">{act.target}</span>
                                          <span className="text-text-muted truncate max-w-[200px]">{act.reason}</span>
                                          <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${act.status === 'approved' ? 'bg-success/15 text-success' : 'bg-warning/15 text-warning'}`}>{act.status}</span>
                                        </div>
                                      ))}
                                    </div>

                                    {/* Terminal Log */}
                                    <div className="space-y-2">
                                      <div className="text-[10px] font-bold text-text-muted uppercase tracking-widest flex items-center gap-2"><Terminal size={12} /> Pipeline Log</div>
                                      <div className="bg-[#0A0A0C] border border-border/40 rounded-xl p-4 max-h-[200px] overflow-y-auto font-mono text-[10px] space-y-0.5">
                                        {scan.terminalLog.map((line, i) => (
                                          <div key={i} className={`${line.startsWith('[OK]') ? 'text-success' : line.startsWith('[!]') ? 'text-danger' : line.startsWith('[→]') ? 'text-accent' : line.startsWith('[◆]') ? 'text-warning' : line.startsWith('[✓]') ? 'text-success font-bold' : 'text-text-muted/70'}`}>
                                            {line}
                                          </div>
                                        ))}
                                      </div>
                                    </div>
                                  </div>
                                </motion.div>
                              )}
                            </AnimatePresence>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </motion.div>
              )}

              {/* ═══════════════ LOGS ═══════════════ */}
              {page === 'logs' && (
                <motion.div key="logs" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="space-y-4">
                  
                  {/* Virtual Terminal & Agent Control */}
                  <div className="bg-panel border border-border/60 rounded-xl p-5 mb-4 shadow-xl">
                    <div className="flex items-center justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <Terminal size={18} className="text-accent" />
                        <h3 className="text-sm font-bold">Virtual Environment Interface</h3>
                        {agentStatus?.isRunning && <span className="text-[10px] font-bold text-success bg-success/10 px-2 py-0.5 rounded border border-success/30 animate-pulse">Running</span>}
                      </div>
                      <div className="flex gap-2">
                        <button onClick={() => SOARService.startAgent().then(fetchAll)} disabled={agentStatus?.isRunning} className="px-5 py-2 bg-success text-white rounded-lg text-[11px] font-bold disabled:opacity-50 hover:bg-success/80 transition-all flex items-center gap-2">
                          <Play size={14} /> Activate Live Logs
                        </button>
                        <button onClick={() => SOARService.stopAgent().then(fetchAll)} disabled={!agentStatus?.isRunning} className="px-5 py-2 bg-danger text-white rounded-lg text-[11px] font-bold disabled:opacity-50 hover:bg-danger/80 transition-all flex items-center gap-2">
                          <StopCircle size={14} /> Stop
                        </button>
                      </div>
                    </div>
                    <div className="bg-[#0A0A0C] border border-border/40 rounded-xl p-4 h-[250px] overflow-y-auto font-mono text-[11px] space-y-1">
                      {(!agentStatus?.output || agentStatus.output.length === 0) ? (
                        <div className="text-text-muted/40 text-center py-10 italic">Agent offline. Terminal ready...</div>
                      ) : (
                        agentStatus.output.map((line: string, i: number) => (
                          <div key={i} className={`flex gap-2 ${line.includes('[ERR]') ? 'text-danger' : line.includes('🔥') || line.includes('💀') ? 'text-warning font-bold' : 'text-success/90'}`}>
                            <span className="text-text-muted/30 select-none">{String(i+1).padStart(3)}</span> {line}
                          </div>
                        ))
                      )}
                    </div>
                  </div>

                  {/* Filters */}
                  <div className="flex gap-3 items-center">
                    <div className="relative flex-1">
                      <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                      <input value={logFilter} onChange={e => setLogFilter(e.target.value)} placeholder="Search logs..." className="w-full bg-panel border border-border/40 rounded-lg pl-9 pr-4 py-2.5 text-sm focus:ring-1 focus:ring-accent outline-none" />
                    </div>
                    <select value={logTypeFilter} onChange={e => setLogTypeFilter(e.target.value)} className="bg-panel border border-border/40 rounded-lg px-4 py-2.5 text-sm font-mono focus:ring-1 focus:ring-accent outline-none appearance-none cursor-pointer">
                      <option value="ALL">All Types</option>
                      {Object.values(LogType).map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                    <span className="text-[10px] font-bold text-text-muted bg-panel border border-border/40 px-3 py-2.5 rounded-lg">{filteredLogs.length} entries</span>
                    <button onClick={handleClearLogs} className="px-4 py-2.5 bg-danger/10 text-danger border border-danger/30 hover:bg-danger/20 rounded-lg text-sm font-bold ml-auto transition-all">Clear Logs</button>
                  </div>

                  {/* Log terminal */}
                  <div className="bg-[#0A0A0C] border border-border/60 rounded-xl overflow-hidden font-mono">
                    <div className="flex items-center gap-2 px-4 py-2.5 border-b border-border/30 bg-[#111114]">
                      <div className="flex gap-1.5">
                        <div className="w-2.5 h-2.5 rounded-full bg-[#F28B82]" />
                        <div className="w-2.5 h-2.5 rounded-full bg-[#FDD663]" />
                        <div className="w-2.5 h-2.5 rounded-full bg-[#81C995]" />
                      </div>
                      <span className="text-[10px] text-text-muted ml-2 tracking-wider">aegis — system-logs</span>
                      <span className="text-[9px] text-accent font-bold ml-auto animate-pulse">● LIVE STREAM</span>
                    </div>
                    <div className="max-h-[600px] overflow-y-auto divide-y divide-white/[0.03]">
                      {filteredLogs.length === 0 ? (
                        <div className="py-16 text-center text-text-muted/30 text-xs">No log entries match filters</div>
                      ) : filteredLogs.map(log => (
                        <div key={log.id} className="px-4 py-2 hover:bg-white/[0.02] transition-all text-[11px] flex items-start gap-3 group cursor-default">
                          <span className="text-text-muted/40 w-[75px] shrink-0 text-[10px]">{new Date(log.timestamp).toLocaleTimeString()}</span>
                          <span className={`w-[90px] shrink-0 font-bold ${
                            log.type === LogType.DETECTION ? 'text-danger' :
                            log.type === LogType.SOAR ? 'text-success' :
                            log.type === LogType.EXPLANATION ? 'text-warning' :
                            log.type === LogType.GRAPH ? 'text-accent' :
                            'text-text-muted'
                          }`}>{log.type}</span>
                          <span className="text-text-muted/50 w-[120px] shrink-0 truncate">{log.source}</span>
                          <span className="text-text-main/60 truncate flex-1 group-hover:text-text-main/90 transition-colors">{JSON.stringify(log.details).slice(0, 120)}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </motion.div>
              )}

              {/* ═══════════════ SETTINGS ═══════════════ */}
              {page === 'settings' && (
                <motion.div key="set" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="max-w-3xl space-y-6">
                  {/* Profile */}
                  <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                    <div className="px-6 py-4 border-b border-border/30 flex items-center gap-4">
                      <div className="w-12 h-12 rounded-xl bg-accent/15 flex items-center justify-center text-accent text-xl font-black">
                        {profile.username.charAt(0).toUpperCase()}
                      </div>
                      <div>
                        <h3 className="text-sm font-bold">Profile</h3>
                        <p className="text-[11px] text-text-muted">Identity & access management</p>
                      </div>
                    </div>
                    <div className="p-6 space-y-5">
                      <div>
                        <label className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-2 block">Display Name</label>
                        {isEditingName ? (
                          <div className="flex gap-3">
                            <input value={editingName} onChange={e => setEditingName(e.target.value)} autoFocus className="flex-1 bg-bg border border-accent/40 rounded-lg px-4 py-2.5 text-sm font-medium focus:ring-1 focus:ring-accent outline-none" />
                            <button onClick={handleSaveName} className="px-5 py-2 bg-accent text-text-inverse rounded-lg text-xs font-bold">Save</button>
                            <button onClick={() => { setIsEditingName(false); setEditingName(profile.username); }} className="px-4 py-2 border border-border rounded-lg text-xs font-bold text-text-muted">Cancel</button>
                          </div>
                        ) : (
                          <div className="flex items-center gap-3">
                            <span className="text-sm font-medium">{profile.username}</span>
                            <button onClick={() => { setEditingName(profile.username); setIsEditingName(true); }} className="text-[10px] font-bold text-accent hover:underline">Edit</button>
                          </div>
                        )}
                      </div>
                      <div>
                        <label className="text-[10px] font-bold text-text-muted uppercase tracking-wider mb-2 block">Role</label>
                        <span className="text-sm font-medium text-text-muted">{profile.role}</span>
                      </div>
                    </div>
                  </div>

                  {/* Detection */}
                  <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                    <div className="px-6 py-4 border-b border-border/30">
                      <h3 className="text-sm font-bold">Detection Engine</h3>
                      <p className="text-[11px] text-text-muted">Tune sensitivity thresholds</p>
                    </div>
                    <div className="p-6 space-y-4">
                      <div>
                        <div className="flex justify-between mb-2">
                          <label className="text-[10px] font-bold text-text-muted uppercase tracking-wider">Brute Force Threshold</label>
                          <span className="text-xs font-bold">{threshold} attempts</span>
                        </div>
                        <input type="range" min="2" max="10" value={threshold} onChange={e => setThreshold(parseInt(e.target.value))} className="w-full" />
                        <p className="text-[10px] text-text-muted mt-2 italic">Lower = more sensitive (more false positives). Higher = fewer alerts.</p>
                      </div>
                    </div>
                  </div>

                  {/* Known Patterns */}
                  <div className="bg-panel border border-border/60 rounded-xl overflow-hidden">
                    <div className="px-6 py-4 border-b border-border/30 flex items-center justify-between">
                      <div>
                        <h3 className="text-sm font-bold">Known Threat Patterns</h3>
                        <p className="text-[11px] text-text-muted">Stored in SQLite — persistent across restarts</p>
                      </div>
                      <span className="text-[10px] font-bold text-text-muted bg-bg px-2.5 py-1 rounded border border-border/40">{patterns.length} patterns</span>
                    </div>
                    <div className="divide-y divide-border/20">
                      {patterns.map(p => (
                        <div key={p.id} className="px-6 py-3 flex items-center justify-between hover:bg-white/[0.02] transition-all">
                          <div>
                            <span className="text-xs font-bold">{p.type}</span>
                            <p className="text-[10px] text-text-muted truncate max-w-[400px]">{p.description}</p>
                          </div>
                          <span className={`text-[9px] font-bold px-2 py-0.5 rounded ${
                            p.severity === 'Critical' ? 'bg-danger/15 text-danger' : p.severity === 'High' ? 'bg-warning/15 text-warning' : 'bg-accent/15 text-accent'
                          }`}>{p.severity}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </main>
      </div>

      {/* Processing Toast */}
      <AnimatePresence>
        {isProcessing && (
          <motion.div initial={{ opacity: 0, y: 80 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: 80 }}
            className="fixed bottom-6 right-6 bg-panel border border-accent/30 px-5 py-3 rounded-xl shadow-2xl shadow-black/40 flex items-center gap-4 z-50">
            <div className="flex gap-1.5">
              {[0,1,2].map(i => (
                <motion.div key={i} animate={{ scale: [1, 1.3, 1], opacity: [0.4, 1, 0.4] }} transition={{ repeat: Infinity, duration: 0.7, delay: i * 0.12 }}
                  className="w-2 h-2 rounded-full bg-accent" />
              ))}
            </div>
            <div>
              <div className="text-[10px] font-bold tracking-wider">Processing Pipeline</div>
              <div className="text-[9px] text-text-muted font-mono">Neural analysis in progress...</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}