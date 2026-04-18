import React, { useEffect, useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Terminal, Code, Activity, AlertCircle, ChevronDown, ChevronUp } from 'lucide-react';
import { SIEMLog, LogType } from '../types';
import { loggingService } from '../services/loggingService';

export const LogViewer: React.FC = () => {
  const [logs, setLogs] = useState<SIEMLog[]>([]);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  useEffect(() => {
    const fetchLogs = async () => {
      const data = await loggingService.getLogs();
      setLogs(data.reverse()); // Show newest first
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 3000);
    return () => clearInterval(interval);
  }, []);

  const getLogTypeColor = (type: LogType) => {
    switch (type) {
      case LogType.INGESTION: return 'text-blue-400';
      case LogType.NORMALIZATION: return 'text-purple-400';
      case LogType.GRAPH: return 'text-accent';
      case LogType.DETECTION: return 'text-danger';
      case LogType.EXPLANATION: return 'text-warning';
      case LogType.SOAR: return 'text-success';
      case LogType.AUDIT: return 'text-white';
      case LogType.ERROR: return 'text-danger';
      default: return 'text-text-muted';
    }
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-sidebar">
      <div className="px-4 py-3 bg-[#F9F9F9] border-b border-border flex items-center justify-between shrink-0">
        <h3 className="text-[11px] uppercase tracking-widest font-bold text-text-muted">API & Transformation Logs</h3>
        <span className="text-[9px] font-mono text-text-muted bg-border/20 px-1.5 py-0.5 rounded">
          {logs.length} ENTRIES
        </span>
      </div>

      <div className="flex-1 overflow-y-auto font-mono text-[11px] text-white p-2">
        {logs.length === 0 && (
          <div className="p-8 text-center text-text-muted italic opacity-50">
            Awaiting pipeline data...
          </div>
        )}
        
        {logs.map((log) => (
          <div key={log.id} className="border-b border-white/5 last:border-0">
            <div 
              className="py-1.5 px-2 hover:bg-white/5 transition-colors cursor-pointer flex items-center justify-between group"
              onClick={() => setExpandedLogId(expandedLogId === log.id ? null : log.id)}
            >
              <div className="flex items-center gap-2 truncate">
                <span className={`font-bold shrink-0 w-16 ${getLogTypeColor(log.type)}`}>
                  {log.type.split('_').pop()}
                </span>
                <span className="text-white/40 shrink-0">
                  {new Date(log.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </span>
                <span className="text-white/80 truncate opacity-70 group-hover:opacity-100 transition-opacity">
                  {log.source}: {JSON.stringify(log.details).slice(0, 80)}
                </span>
              </div>
              <span className="text-success font-bold shrink-0 ml-2">200 OK</span>
            </div>

            <AnimatePresence>
              {expandedLogId === log.id && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="overflow-hidden bg-black/40 p-4 border-y border-white/10"
                >
                  <pre className="text-accent/80 text-[10px] whitespace-pre-wrap leading-relaxed">
                    {JSON.stringify(log.details, null, 2)}
                  </pre>
                  {log.metadata && (
                    <div className="mt-3 pt-3 border-t border-white/10">
                      <p className="text-[9px] uppercase text-text-muted mb-1">Context Metadata</p>
                      <pre className="text-white/40 text-[10px]">
                        {JSON.stringify(log.metadata, null, 2)}
                      </pre>
                    </div>
                  )}
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}
      </div>
    </div>
  );
};
