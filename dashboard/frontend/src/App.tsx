/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Activity,
  ShieldAlert,
  Gauge,
  Settings,
  Terminal,
  HelpCircle,
  Power,
  Cpu,
  Radio,
  ChevronRight,
  AlertTriangle,
  Ban,
  Clock,
  FileText,
  Filter,
  Shield,
  Zap,
  HardDrive,
  Network,
  Lock,
  Unlock,
  Eye,
  Trash2,
  RefreshCw,
  WifiOff,
  CheckCircle2,
  XCircle,
  Loader2
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// ── Types ─────────────────────────────────────────────────────────────────────

type Screen = 'Live' | 'Threats' | 'Performance' | 'System' | 'Logs';

interface LiveStats {
  packet_count: number;
  pps: number;
  avg_pps: number;
  block_count: number;
  alert_count: number;
  runtime_secs: number;
  normal_logging_enabled: boolean;
  normal_sample_divisor: number;
  heartbeat: string;
  top_procs: ProcessInfo[];
  recent_logs: LogEntry[];
  normal_logs: LogEntry[];
  recent_threats: ThreatInfo[];
}

interface ProcessInfo {
  pid: number;
  name: string;
  packets: number;
  bytes: number;
  alerted: number;
  blocked: number;
  protocol_cnt: number;
  unique_dsts: number;
}

interface LogEntry {
  time: string;
  level: 'normal' | 'alert' | 'critical';
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  proto: string;
  process: string;
  detail: string;
}

interface ThreatInfo {
  id: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  source: string;
  timestamp: string;
  description: string;
  action: string;
}

interface BlockedIP {
  ip: string;
  blocked_at: string;
  expires_at?: string;
  reason?: string;
  rule_id?: string;
}

interface RuleInfo {
  id: string;
  name: string;
  enabled: boolean;
  action: 'block' | 'alert' | 'log';
  protocol?: string;
  ports?: number[];
}

// ── Constants ─────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8080/ws';
const RECONNECT_INTERVAL = 3000;
const MAX_RECONNECT_ATTEMPTS = 10;
const STATS_POLL_INTERVAL = 1000;

// ── Utility Hooks ─────────────────────────────────────────────────────────────

function useWebSocket<T>(url: string, onMessage: (data: T) => void) {
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectCount = useRef(0);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const isManualClose = useRef(false);

  const connect = useCallback(() => {
    if (isManualClose.current) return;
    if (reconnectCount.current >= MAX_RECONNECT_ATTEMPTS) {
      setError('Max reconnection attempts reached');
      return;
    }

    try {
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setError(null);
        reconnectCount.current = 0;
      };

      ws.onmessage = (ev) => {
        try {
          const parsed = JSON.parse(ev.data);
          onMessage(parsed);
        } catch (e) {
          console.error('WS parse error:', e);
        }
      };

      ws.onerror = () => {
        setError('WebSocket error');
      };

      ws.onclose = () => {
        setConnected(false);
        wsRef.current = null;
        if (!isManualClose.current) {
          reconnectCount.current++;
          reconnectTimer.current = setTimeout(connect, RECONNECT_INTERVAL);
        }
      };
    } catch (e) {
      setError('Failed to create WebSocket');
    }
  }, [url, onMessage]);

  useEffect(() => {
    isManualClose.current = false;
    connect();
    return () => {
      isManualClose.current = true;
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { connected, error };
}

function useApi<T>(endpoint: string, interval?: number) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const fetchData = useCallback(async () => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        signal: controller.signal,
        headers: { Accept: 'application/json' },
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setError(null);
    } catch (e: any) {
      if (e.name !== 'AbortError') setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  useEffect(() => {
    fetchData();
    if (!interval) return;
    const timer = setInterval(fetchData, interval);
    return () => {
      clearInterval(timer);
      abortRef.current?.abort();
    };
  }, [fetchData, interval]);

  return { data, loading, error, refetch: fetchData };
}

function usePost<T = any>() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<T | null>(null);

  const post = useCallback(async (endpoint: string, body: object) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify(body),
      });
      const json = await res.json();
      if (!res.ok || !json.success) throw new Error(json.message || `HTTP ${res.status}`);
      setData(json);
      return json;
    } catch (e: any) {
      setError(e.message);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  return { post, loading, error, data };
}

// ── Formatters ────────────────────────────────────────────────────────────────

const fmtNum = (n: number) => n?.toLocaleString?.() ?? '0';
const fmtBytes = (b: number) => {
  if (!b) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (b >= 1024 && i < units.length - 1) { b /= 1024; i++; }
  return `${b.toFixed(1)} ${units[i]}`;
};
const fmtDuration = (s: number) => {
  if (!s) return '00:00:00';
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = Math.floor(s % 60);
  return `${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${sec.toString().padStart(2, '0')}`;
};

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [activeScreen, setActiveScreen] = useState<Screen>('Live');
  const [stats, setStats] = useState<LiveStats | null>(null);

  const handleWsMessage = useCallback((data: LiveStats) => {
    setStats(data);
  }, []);

  const { connected: wsConnected } = useWebSocket<LiveStats>(WS_URL, handleWsMessage);

  const navigation = useMemo(() => [
    { name: 'Live', icon: Activity, id: 'Live' as Screen },
    { name: 'Threats', icon: ShieldAlert, id: 'Threats' as Screen },
    { name: 'Performance', icon: Gauge, id: 'Performance' as Screen },
    { name: 'System', icon: Settings, id: 'System' as Screen },
    { name: 'Logs', icon: Terminal, id: 'Logs' as Screen },
  ], []);

  return (
    <div className="flex h-screen w-full bg-surface-dim text-on-surface font-sans overflow-hidden">
      <header className="fixed top-0 z-50 flex h-12 w-full items-center justify-between border-b border-outline-variant bg-surface-dim px-4">
        <div className="flex items-center gap-4">
          <span className="text-2xl font-black tracking-tighter text-primary">RUBIX</span>
          <div className="h-4 w-px bg-outline-variant" />
          <span className="text-[10px] font-bold tracking-widest text-on-surface-variant uppercase font-mono">
            Security Operations Center
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-4 mr-4 px-4 border-r border-outline-variant">
            <div className="flex items-center gap-2">
              <div className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-primary animate-pulse' : 'bg-error'}`} />
              <span className={`text-[10px] font-bold font-mono ${wsConnected ? 'text-primary' : 'text-error'}`}>
                {wsConnected ? 'LIVE' : 'OFFLINE'}
              </span>
            </div>
            <span className="text-[10px] text-outline font-mono">127.0.0.1:9876</span>
          </div>
          <ConnectionStatus connected={wsConnected} />
          <button className="p-2 transition-colors hover:bg-surface-variant active:opacity-80 rounded">
            <Settings className="w-4 h-4 text-primary" />
          </button>
          <button className="p-2 transition-colors hover:bg-surface-variant active:opacity-80 rounded">
            <Power className="w-4 h-4 text-error" />
          </button>
        </div>
      </header>

      <aside className="group fixed left-0 top-12 z-40 flex h-[calc(100vh-48px)] w-[56px] flex-col border-r border-outline-variant bg-surface-container transition-all hover:w-[180px]">
        <nav className="flex-1 space-y-1 py-4">
          {navigation.map((item) => (
            <button
              key={item.name}
              onClick={() => setActiveScreen(item.id)}
              className={`flex h-10 w-full items-center px-4 transition-all hover:bg-surface-variant ${
                activeScreen === item.id
                  ? 'border-l-2 border-primary bg-surface-variant text-primary'
                  : 'text-outline hover:text-on-surface-variant'
              }`}
            >
              <item.icon className="min-w-[24px] h-4 w-4" />
              <span className="ml-6 text-[10px] font-bold uppercase tracking-wider opacity-0 transition-opacity group-hover:opacity-100 whitespace-nowrap">
                {item.name}
              </span>
            </button>
          ))}
        </nav>
        <div className="mt-auto border-t border-outline-variant py-4">
          <button className="flex h-10 w-full items-center px-4 text-outline transition-all hover:bg-surface-variant hover:text-on-surface-variant">
            <HelpCircle className="min-w-[24px] h-4 w-4" />
            <span className="ml-6 text-[10px] font-bold uppercase tracking-wider opacity-0 transition-opacity group-hover:opacity-100 whitespace-nowrap">
              Support
            </span>
          </button>
          <div className="px-4 mt-2">
            <span className="text-[9px] font-mono text-outline opacity-50 whitespace-nowrap opacity-0 group-hover:opacity-100">
              V2.4.0-STABLE
            </span>
          </div>
        </div>
      </aside>

      <main className="ml-[56px] mt-12 flex-1 h-[calc(100vh-48px)] bg-surface-dim overflow-hidden relative">
        <AnimatePresence mode="wait">
          <motion.div
            key={activeScreen}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            transition={{ duration: 0.2 }}
            className="h-full w-full overflow-y-auto"
          >
            {activeScreen === 'Live' && <LiveScreen stats={stats} connected={wsConnected} />}
            {activeScreen === 'Threats' && <ThreatsScreen />}
            {activeScreen === 'Performance' && <PerformanceScreen stats={stats} />}
            {activeScreen === 'System' && <SystemScreen />}
            {activeScreen === 'Logs' && <LogsScreen />}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

// ── Connection Status Badge ───────────────────────────────────────────────────

function ConnectionStatus({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-surface-container border border-outline-variant">
      {connected ? (
        <>
          <CheckCircle2 className="w-3 h-3 text-primary" />
          <span className="text-[10px] font-mono text-primary">WS</span>
        </>
      ) : (
        <>
          <WifiOff className="w-3 h-3 text-error" />
          <span className="text-[10px] font-mono text-error">WS</span>
        </>
      )}
    </div>
  );
}

// ── Live Screen ───────────────────────────────────────────────────────────────

function LiveScreen({ stats, connected }: { stats: LiveStats | null; connected: boolean }) {
  const { data: apiStats } = useApi<{ ok: boolean; stats: LiveStats }>('/api/stats', STATS_POLL_INTERVAL);
  const current = stats || apiStats?.stats;

  const metrics = useMemo(() => {
    if (!current) return [
      { label: 'Packets/sec', value: '--', sub: 'Connecting...', color: 'text-outline', status: 'loading' as const },
      { label: 'Total Packets', value: '--', sub: '...', color: 'text-outline', status: 'loading' as const },
      { label: 'Active Blocks', value: '--', sub: '...', color: 'text-outline', status: 'loading' as const },
      { label: 'Security Alerts', value: '--', sub: '...', color: 'text-outline', status: 'loading' as const },
    ];
    return [
      {
        label: 'Packets/sec',
        value: fmtNum(Math.round(current.pps || 0)),
        sub: `${fmtNum(Math.round(current.avg_pps || 0))} avg`,
        color: 'text-primary',
        status: 'ok' as const,
        icon: Network
      },
      {
        label: 'Total Packets',
        value: fmtNum(current.packet_count || 0),
        sub: connected ? 'Real-time' : 'Stale',
        color: connected ? 'text-primary' : 'text-tertiary',
        status: connected ? 'ok' : 'warning',
        icon: FileText
      },
      {
        label: 'Active Blocks',
        value: fmtNum(current.block_count || 0),
        sub: current.block_count > 0 ? 'ACTION REQUIRED' : 'CLEAR',
        color: current.block_count > 0 ? 'text-error' : 'text-primary',
        status: current.block_count > 0 ? 'error' : 'ok',
        icon: Ban
      },
      {
        label: 'Security Alerts',
        value: fmtNum(current.alert_count || 0),
        sub: current.alert_count > 0 ? `${current.alert_count} active` : 'No alerts',
        color: current.alert_count > 0 ? 'text-tertiary' : 'text-primary',
        status: current.alert_count > 0 ? 'warning' : 'ok',
        icon: AlertTriangle
      },
    ];
  }, [current, connected]);

  const procs = current?.top_procs || [];
  const logs = current?.normal_logs?.slice(0, 50) || [];

  return (
    <div className="flex h-full flex-col">
      <div className="grid grid-cols-4 border-b border-outline-variant bg-surface-container shrink-0">
        {metrics.map((m, i) => (
          <div key={i} className="p-4 border-r border-outline-variant flex flex-col justify-between h-[100px] last:border-r-0">
            <div className="flex justify-between items-start">
              <span className="text-[10px] font-bold text-outline uppercase tracking-wider">{m.label}</span>
              {m.status === 'loading' ? (
                <Loader2 className="w-3 h-3 text-outline animate-spin" />
              ) : m.status === 'error' ? (
                <XCircle className="w-3 h-3 text-error" />
              ) : m.status === 'warning' ? (
                <AlertTriangle className="w-3 h-3 text-tertiary" />
              ) : (
                <CheckCircle2 className="w-3 h-3 text-primary" />
              )}
            </div>
            <div className="flex items-end justify-between">
              <span className={`text-2xl font-bold ${m.color}`}>{m.value}</span>
              <div className="flex flex-col items-end gap-0.5">
                <span className="text-[9px] font-mono text-outline">{m.sub}</span>
                {m.icon && <m.icon className={`w-3 h-3 ${m.color} opacity-50`} />}
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="flex-1 flex min-h-0 bg-surface-dim">
        <div className="flex-1 flex flex-col overflow-hidden">
          <div className="h-8 border-b border-outline-variant bg-surface-container flex items-center px-4 shrink-0 font-mono text-[10px] text-outline uppercase tracking-widest font-bold">
            <div className="grid grid-cols-[100px_40px_160px_160px_80px_80px_1fr] w-full items-center">
              <div>Time</div>
              <div className="text-center">LVL</div>
              <div>Source IP</div>
              <div>Dest IP</div>
              <div>Proto</div>
              <div>Port</div>
              <div>Process</div>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto font-mono text-[11px]">
            {logs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-outline">
                <Loader2 className="w-4 h-4 animate-spin mr-2" />
                <span>Waiting for packet data...</span>
              </div>
            ) : (
              logs.map((log, i) => (
                <div
                  key={`${log.time}-${i}`}
                  className={`grid grid-cols-[100px_40px_160px_160px_80px_80px_1fr] h-8 items-center px-4 border-b border-outline-variant hover:bg-surface-variant group cursor-pointer transition-colors ${
                    log.level === 'alert' ? 'border-l-2 border-error' : log.level === 'critical' ? 'border-l-2 border-tertiary' : ''
                  }`}
                >
                  <div className="text-outline">{log.time}</div>
                  <div className="flex justify-center">
                    <div className={`w-1.5 h-1.5 rounded-full ${
                      log.level === 'critical' ? 'bg-error' : log.level === 'alert' ? 'bg-tertiary' : 'bg-primary'
                    }`} />
                  </div>
                  <div className={log.level === 'alert' ? 'text-error font-bold' : log.level === 'critical' ? 'text-tertiary font-bold' : ''}>
                    {log.src_ip}
                  </div>
                  <div className="text-on-surface">{log.dst_ip}</div>
                  <div className="text-on-surface-variant">{log.proto}</div>
                  <div className="text-on-surface-variant">{log.dst_port}</div>
                  <div className="text-outline truncate">{log.process}</div>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="w-[320px] border-l border-outline-variant bg-surface-container flex flex-col shrink-0 overflow-hidden">
          <div className="p-4 border-b border-outline-variant bg-surface-container-high flex justify-between items-center">
            <span className="text-sm font-bold uppercase tracking-wide">Top Processes</span>
            <Cpu className="w-3 h-3 text-outline" />
          </div>
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {procs.length === 0 ? (
              <div className="text-center text-outline text-[10px] py-8">No process data</div>
            ) : (
              procs.map((proc) => (
                <div key={proc.pid} className="bg-surface-container-lowest border border-outline-variant p-3">
                  <div className="flex justify-between items-start mb-2">
                    <div>
                      <div className="text-xs font-bold text-on-surface">{proc.name}</div>
                      <div className="text-[10px] font-mono text-outline">PID: {proc.pid}</div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs font-mono font-bold text-primary">{fmtNum(proc.packets)}</div>
                      <div className="text-[9px] text-outline">pkts</div>
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-[9px] font-mono">
                    <div><span className="text-outline">Bytes:</span> <span className="text-on-surface">{fmtBytes(proc.bytes)}</span></div>
                    <div><span className="text-outline">Alerts:</span> <span className={proc.alerted > 0 ? 'text-error' : 'text-primary'}>{proc.alerted}</span></div>
                    <div><span className="text-outline">Blocked:</span> <span className={proc.blocked > 0 ? 'text-error' : 'text-primary'}>{proc.blocked}</span></div>
                  </div>
                </div>
              ))
            )}
          </div>
          <div className="p-4 border-t border-outline-variant bg-surface-container">
            <div className="text-[10px] font-mono text-outline">
              Runtime: {fmtDuration(current?.runtime_secs || 0)}
            </div>
            <div className="text-[10px] font-mono text-outline mt-1">
              Sample: 1/{current?.normal_sample_divisor || 100}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Threats Screen ────────────────────────────────────────────────────────────

function ThreatsScreen() {
  const { data: logsData } = useApi<{ security: LogEntry[]; threats: ThreatInfo[] }>('/api/logs', STATS_POLL_INTERVAL);
  const threats = logsData?.threats || [];
  const securityLogs = logsData?.security || [];

  const [selectedThreat, setSelectedThreat] = useState<ThreatInfo | null>(null);
  const { post: blockIP, loading: blocking } = usePost();

  const handleBlock = useCallback(async (ip: string) => {
    try {
      await blockIP('/api/block', { ip, duration_secs: 3600, reason: 'Manual block from dashboard' });
    } catch (e) {
      // Error handled by hook
    }
  }, [blockIP]);

  return (
    <div className="flex h-full flex-col">
      <div className="h-[60px] shrink-0 border-b border-outline-variant bg-surface-container-lowest flex items-center px-4 gap-4 sticky top-0 z-30">
        <div className="shrink-0 flex flex-col justify-center">
          <span className="text-[10px] font-bold text-outline leading-none">THREAT</span>
          <span className="text-[10px] font-bold text-outline leading-none">TIMELINE</span>
        </div>
        <div className="flex-1 flex items-end h-8 gap-[2px]">
          {Array.from({ length: 60 }).map((_, i) => {
            const h = Math.random() * 10;
            const isError = h > 7;
            const isWarning = h > 4 && h <= 7;
            return (
              <div
                key={i}
                className={`flex-1 ${isError ? 'bg-error' : isWarning ? 'bg-tertiary' : 'bg-outline-variant opacity-20'}`}
                style={{ height: `${h * 10}%` }}
              />
            );
          })}
        </div>
        <span className="text-[11px] font-mono text-primary shrink-0">60S WINDOW</span>
      </div>

      <div className="flex-1 p-4 grid grid-cols-12 gap-4 h-full min-h-0">
        <div className="col-span-12 lg:col-span-7 flex flex-col bg-surface-container border border-outline-variant overflow-hidden">
          <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant flex justify-between items-center">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-error" />
              <span className="text-sm font-bold uppercase tracking-wide">Active Threats</span>
              <span className="bg-error-container text-on-error-container px-2 py-0.5 text-[11px] font-mono rounded">
                {threats.length} Detected
              </span>
            </div>
            <span className="text-[11px] font-mono text-outline">SORT: SEVERITY ↓</span>
          </div>
          <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-2">
            {threats.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full text-outline gap-2">
                <Shield className="w-8 h-8 opacity-30" />
                <span className="text-sm">No active threats detected</span>
                <span className="text-[10px] font-mono">System is secure</span>
              </div>
            ) : (
              threats.map((threat) => (
                <ThreatCard
                  key={threat.id}
                  threat={threat}
                  selected={selectedThreat?.id === threat.id}
                  onSelect={() => setSelectedThreat(threat)}
                  onBlock={() => handleBlock(threat.source)}
                  blocking={blocking}
                />
              ))
            )}
          </div>
        </div>

        <div className="col-span-12 lg:col-span-5 flex flex-col gap-4 min-h-0">
          <section className="bg-surface-container border border-outline-variant flex flex-col flex-1 overflow-hidden">
            <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant uppercase">
              <span className="text-sm font-bold tracking-wide">Threat Details</span>
            </div>
            <div className="flex-1 p-4 bg-surface-dim overflow-y-auto">
              {selectedThreat ? (
                <div className="space-y-4">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                      selectedThreat.severity === 'CRITICAL' ? 'bg-error text-on-error' :
                      selectedThreat.severity === 'HIGH' ? 'bg-tertiary text-on-tertiary' :
                      'bg-secondary text-on-secondary'
                    }`}>
                      {selectedThreat.severity}
                    </span>
                    <span className="text-xs font-mono text-outline">{selectedThreat.id}</span>
                  </div>
                  <h3 className="text-lg font-bold">{selectedThreat.title}</h3>
                  <p className="text-xs text-on-surface-variant leading-relaxed">{selectedThreat.description}</p>
                  <div className="space-y-2 text-[11px] font-mono">
                    <div className="flex justify-between"><span className="text-outline">Source:</span><span>{selectedThreat.source}</span></div>
                    <div className="flex justify-between"><span className="text-outline">Detected:</span><span>{selectedThreat.timestamp}</span></div>
                    <div className="flex justify-between"><span className="text-outline">Action:</span><span className={selectedThreat.action === 'BLOCKED' ? 'text-error' : 'text-tertiary'}>{selectedThreat.action}</span></div>
                  </div>
                  <div className="flex gap-2 pt-2">
                    <button
                      onClick={() => handleBlock(selectedThreat.source)}
                      disabled={blocking}
                      className="flex-1 px-3 py-2 bg-error text-on-error text-[10px] font-bold uppercase transition-transform active:scale-95 disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                      {blocking ? <Loader2 className="w-3 h-3 animate-spin" /> : <Ban className="w-3 h-3" />}
                      Block Source
                    </button>
                    <button className="flex-1 px-3 py-2 bg-surface-variant border border-outline-variant text-[10px] font-bold uppercase transition-transform active:scale-95 flex items-center justify-center gap-2">
                      <Eye className="w-3 h-3" /> Investigate
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-outline gap-2">
                  <Shield className="w-8 h-8 opacity-30" />
                  <span className="text-sm">Select a threat to view details</span>
                </div>
              )}
            </div>
          </section>

          <section className="bg-surface-container border border-outline-variant h-[35%] flex flex-col overflow-hidden">
            <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant flex justify-between items-center">
              <span className="text-sm font-bold uppercase tracking-wide">Security Log</span>
              <Terminal className="w-3 h-3 text-outline" />
            </div>
            <div className="flex-1 overflow-auto bg-surface-dim">
              <table className="w-full text-left border-collapse font-mono text-[11px]">
                <thead className="sticky top-0 bg-surface-container-high z-10 border-b border-outline-variant">
                  <tr>
                    <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Time</th>
                    <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Event</th>
                    <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Source</th>
                    <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {securityLogs.length === 0 ? (
                    <tr><td colSpan={4} className="px-4 py-4 text-center text-outline">No security events</td></tr>
                  ) : (
                    securityLogs.slice(0, 20).map((log, i) => (
                      <LogTableRow key={`${log.time}-${i}`} log={log} />
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}

function ThreatCard({ threat, selected, onSelect, onBlock, blocking }: {
  threat: ThreatInfo;
  selected: boolean;
  onSelect: () => void;
  onBlock: () => void;
  blocking: boolean;
}) {
  const color = threat.severity === 'CRITICAL' ? 'bg-error' : threat.severity === 'HIGH' ? 'bg-tertiary' : 'bg-secondary';
  const textColor = threat.severity === 'CRITICAL' ? 'text-on-error' : 'text-on-surface';

  return (
    <div
      onClick={onSelect}
      className={`group relative border border-outline-variant bg-surface-container-low p-4 flex gap-4 transition-colors cursor-pointer ${
        selected ? 'bg-surface-variant border-primary' : 'hover:bg-surface-variant'
      }`}
    >
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${color}`} />
      <div className="flex-1">
        <div className="flex justify-between items-start mb-2">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${color} ${textColor} ${threat.severity === 'CRITICAL' ? 'status-pulse' : ''}`}>
                {threat.severity}
              </span>
              <span className="text-md font-bold">{threat.title}</span>
            </div>
            <span className="text-[11px] font-mono text-outline">{threat.id} • {threat.source}</span>
          </div>
          <div className="flex gap-2">
            <button
              onClick={(e) => { e.stopPropagation(); onBlock(); }}
              disabled={blocking}
              className={`px-3 py-1 ${color} ${textColor} text-[10px] font-bold uppercase transition-transform active:scale-95 disabled:opacity-50`}
            >
              {blocking ? '...' : 'Block IP'}
            </button>
            <button
              onClick={(e) => e.stopPropagation()}
              className="px-3 py-1 bg-surface-variant border border-outline-variant text-[10px] font-bold uppercase transition-transform active:scale-95"
            >
              Investigate
            </button>
          </div>
        </div>
        <p className="text-xs text-on-surface-variant leading-relaxed">{threat.description}</p>
      </div>
    </div>
  );
}

function LogTableRow({ log }: { log: LogEntry }) {
  const isAlert = log.level === 'alert';
  const isCritical = log.level === 'critical';
  return (
    <tr className="border-b border-outline-variant hover:bg-surface-variant transition-colors h-8">
      <td className="px-4 text-outline">{log.time}</td>
      <td className={`px-4 font-bold ${isCritical ? 'text-error' : isAlert ? 'text-tertiary' : 'text-primary'}`}>
        {log.detail?.toUpperCase?.() || log.level?.toUpperCase?.()}
      </td>
      <td className="px-4">{log.src_ip}</td>
      <td className="px-4 font-bold italic">{log.detail || 'LOGGED'}</td>
    </tr>
  );
}

// ── Performance Screen ──────────────────────────────────────────────────────────

function PerformanceScreen({ stats }: { stats: LiveStats | null }) {
  const procs = stats?.top_procs || [];
  const runtime = stats?.runtime_secs || 0;
  const packetCount = stats?.packet_count || 0;

  const throughput = useMemo(() => {
    if (!runtime || !packetCount) return '0 B/s';
    const avgBytesPerPacket = 500; // Estimate
    const bps = (packetCount * avgBytesPerPacket) / runtime;
    return fmtBytes(bps) + '/s';
  }, [runtime, packetCount]);

  return (
    <div className="p-6 h-full flex flex-col gap-6 overflow-y-auto">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <MetricCard title="Throughput (TX/RX)" value={throughput} icon={Network} color="primary" />
        <MetricCard title="Packet Block Rate" value={`${stats?.block_count ? ((stats.block_count / Math.max(stats.packet_count, 1)) * 100).toFixed(2) : '0.00'}%`} icon={Ban} color="error" />
        <MetricCard title="Alert Frequency" value={`${fmtNum(stats?.alert_count || 0)}/session`} icon={AlertTriangle} color="tertiary" />
        <MetricCard title="Total Packets" value={fmtNum(packetCount)} icon={FileText} color="primary" />
        <MetricCard title="Avg PPS" value={fmtNum(Math.round(stats?.avg_pps || 0))} icon={Zap} color="primary" />
        <MetricCard title="Runtime" value={fmtDuration(runtime)} icon={Clock} color="outline" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[400px]">
        <section className="bg-surface-container border border-outline-variant flex flex-col">
          <div className="h-8 border-b border-outline-variant bg-surface-container-high px-4 flex items-center justify-between text-[10px] font-bold text-on-surface uppercase tracking-widest">
            <span>Top Processes</span>
            <Cpu className="w-3 h-3 text-outline" />
          </div>
          <div className="flex-1 overflow-auto bg-surface-dim font-mono text-[11px]">
            <table className="w-full text-left">
              <thead className="bg-surface-container border-b border-outline-variant text-outline">
                <tr>
                  <th className="px-4 py-1">PID</th>
                  <th className="px-2 py-1">Name</th>
                  <th className="px-2 py-1 text-right">Packets</th>
                  <th className="px-2 py-1">Bytes</th>
                  <th className="px-2 py-1 text-center">Alerts</th>
                </tr>
              </thead>
              <tbody>
                {procs.length === 0 ? (
                  <tr><td colSpan={5} className="px-4 py-4 text-center text-outline">No process data</td></tr>
                ) : (
                  procs.map((p) => (
                    <tr key={p.pid} className="border-b border-outline-variant h-8 hover:bg-surface-variant">
                      <td className="px-4 text-primary">{p.pid}</td>
                      <td className="px-2">{p.name}</td>
                      <td className="px-2 text-right">{fmtNum(p.packets)}</td>
                      <td className="px-2">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-full max-w-[80px] bg-outline-variant rounded-full overflow-hidden">
                            <div className="bg-primary h-full" style={{ width: `${Math.min((p.bytes / Math.max(procs[0]?.bytes || 1, 1)) * 100, 100)}%` }} />
                          </div>
                          <span>{fmtBytes(p.bytes)}</span>
                        </div>
                      </td>
                      <td className="px-2 text-center">
                        <span className={p.alerted > 0 ? 'text-error' : 'text-primary'}>{p.alerted}</span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>

        <section className="bg-surface-container border border-outline-variant flex flex-col p-4 gap-4">
          <div className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-2">System Health</div>
          <HealthMetric label="Packet Capture" value={stats ? 'Active' : 'Inactive'} status={stats ? 'ok' : 'error'} />
          <HealthMetric label="Logging" value={stats?.normal_logging_enabled ? 'Enabled' : 'Disabled'} status={stats?.normal_logging_enabled ? 'ok' : 'warning'} />
          <HealthMetric label="Sampling" value={`1/${stats?.normal_sample_divisor || 100}`} status="ok" />
          <HealthMetric label="Heartbeat" value={stats?.heartbeat || 'None'} status={stats?.heartbeat ? 'ok' : 'warning'} />
        </section>
      </div>
    </div>
  );
}

function MetricCard({ title, value, icon: Icon, color }: { title: string; value: string; icon: any; color: string }) {
  const colorMap: Record<string, string> = {
    primary: 'text-primary',
    error: 'text-error',
    tertiary: 'text-tertiary',
    outline: 'text-outline',
  };
  return (
    <div className="bg-surface-container border border-outline-variant p-4 h-[120px] flex flex-col justify-between">
      <div className="flex justify-between items-start">
        <span className="text-[10px] font-bold text-outline uppercase tracking-widest">{title}</span>
        <Icon className={`w-4 h-4 ${colorMap[color] || 'text-outline'} opacity-50`} />
      </div>
      <div className={`text-2xl font-bold ${colorMap[color] || 'text-on-surface'}`}>{value}</div>
    </div>
  );
}

function HealthMetric({ label, value, status }: { label: string; value: string; status: 'ok' | 'warning' | 'error' }) {
  const icons = { ok: CheckCircle2, warning: AlertTriangle, error: XCircle };
  const colors = { ok: 'text-primary', warning: 'text-tertiary', error: 'text-error' };
  const Icon = icons[status];
  return (
    <div className="flex items-center justify-between p-3 bg-surface-container-low border border-outline-variant">
      <span className="text-xs font-bold text-outline">{label}</span>
      <div className="flex items-center gap-2">
        <span className="text-xs font-mono font-bold">{value}</span>
        <Icon className={`w-4 h-4 ${colors[status]}`} />
      </div>
    </div>
  );
}

// ── System Screen ─────────────────────────────────────────────────────────────

function SystemScreen() {
  const { data: blockedData, refetch: refetchBlocked } = useApi<{ success: boolean; blocked_ips?: BlockedIP[] }>('/api/blocked', 5000);
  const { data: rulesData } = useApi<{ success: boolean; rules?: RuleInfo[] }>('/api/rules', 10000);
  const { post: blockIP, loading: blocking } = usePost();
  const { post: unblockIP, loading: unblocking } = usePost();

  const [ipInput, setIpInput] = useState('');
  const [duration, setDuration] = useState('3600');
  const [reason, setReason] = useState('');

  const blockedIPs = blockedData?.blocked_ips || [];
  const rules = rulesData?.rules || [];

  const handleBlock = useCallback(async () => {
    if (!ipInput) return;
    try {
      await blockIP('/api/block', { ip: ipInput, duration_secs: parseInt(duration) || undefined, reason: reason || undefined });
      setIpInput('');
      setReason('');
      refetchBlocked();
    } catch (e) {}
  }, [ipInput, duration, reason, blockIP, refetchBlocked]);

  const handleUnblock = useCallback(async (ip: string) => {
    try {
      await unblockIP('/api/unblock', { ip });
      refetchBlocked();
    } catch (e) {}
  }, [unblockIP, refetchBlocked]);

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 border-b border-outline-variant bg-surface-container-low flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-2 bg-surface-container p-2 border border-outline-variant rounded">
          <input
            className="bg-surface-dim border border-outline text-on-surface px-2 h-8 w-40 text-xs font-mono outline-none focus:border-primary transition-colors"
            placeholder="Target IP (e.g. 1.2.3.4)"
            value={ipInput}
            onChange={(e) => setIpInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleBlock()}
          />
          <select
            className="bg-surface-dim border border-outline-variant text-on-surface px-2 h-8 text-xs font-mono outline-none"
            value={duration}
            onChange={(e) => setDuration(e.target.value)}
          >
            <option value="300">5m</option>
            <option value="900">15m</option>
            <option value="3600">1h</option>
            <option value="86400">24h</option>
            <option value="604800">7d</option>
            <option value="">Permanent</option>
          </select>
          <input
            className="bg-surface-dim border border-outline-variant text-on-surface px-2 h-8 w-32 text-xs font-mono outline-none"
            placeholder="Reason (opt)"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
          <button
            onClick={handleBlock}
            disabled={blocking || !ipInput}
            className="bg-error text-on-error font-bold px-4 h-8 text-[10px] hover:opacity-90 uppercase disabled:opacity-50 flex items-center gap-1"
          >
            {blocking ? <Loader2 className="w-3 h-3 animate-spin" /> : <Ban className="w-3 h-3" />}
            Block IP
          </button>
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        <div className="w-1/2 p-6 border-r border-outline-variant overflow-y-auto space-y-6">
          <h2 className="text-lg font-bold flex items-center gap-2 uppercase tracking-widest">
            <ShieldAlert className="w-5 h-5 text-primary" /> Active Blocks
          </h2>

          <div className="border border-outline-variant rounded bg-surface-container-low overflow-hidden">
            <div className="bg-surface-container px-3 py-2 border-b border-outline-variant flex justify-between items-center text-[10px] font-bold text-outline tracking-widest uppercase">
              <span>Blocked IP Addresses ({blockedIPs.length})</span>
              <div className="flex items-center gap-2">
                <button onClick={refetchBlocked} className="hover:text-primary transition-colors">
                  <RefreshCw className="w-3 h-3" />
                </button>
                <div className={`w-2 h-2 rounded-full ${blockedIPs.length > 0 ? 'bg-error animate-pulse' : 'bg-primary'}`} />
              </div>
            </div>
            <table className="w-full text-[11px] font-mono">
              <thead className="bg-surface-container text-outline uppercase border-b border-outline-variant">
                <tr className="h-8">
                  <th className="px-4 font-normal text-left">IP Address</th>
                  <th className="px-4 font-normal text-left">Blocked</th>
                  <th className="px-4 font-normal text-left">Expires</th>
                  <th className="px-4 font-normal text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {blockedIPs.length === 0 ? (
                  <tr><td colSpan={4} className="px-4 py-4 text-center text-outline">No blocked IPs</td></tr>
                ) : (
                  blockedIPs.map((b) => (
                    <tr key={b.ip} className="h-8 border-b border-outline-variant hover:bg-surface-variant">
                      <td className="px-4 text-error font-bold">{b.ip}</td>
                      <td className="px-4 text-outline">{b.blocked_at}</td>
                      <td className="px-4 text-outline">{b.expires_at || 'Never'}</td>
                      <td className="px-4 text-right">
                        <button
                          onClick={() => handleUnblock(b.ip)}
                          disabled={unblocking}
                          className="text-primary hover:underline font-bold disabled:opacity-50 flex items-center justify-end gap-1"
                        >
                          {unblocking ? <Loader2 className="w-3 h-3 animate-spin" /> : <Unlock className="w-3 h-3" />}
                          Unblock
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="w-1/2 p-6 bg-surface-container-lowest overflow-y-auto space-y-6">
          <h2 className="text-lg font-bold flex items-center gap-2 uppercase tracking-widest">
            <Filter className="w-5 h-5 text-primary" /> Active Rules
          </h2>
          <div className="space-y-2">
            {rules.length === 0 ? (
              <div className="text-center text-outline py-8">No rules loaded</div>
            ) : (
              rules.map((rule) => (
                <div key={rule.id} className="bg-surface-container border border-outline-variant p-3 flex items-center justify-between">
                  <div>
                    <div className="text-xs font-bold text-on-surface">{rule.name}</div>
                    <div className="text-[10px] font-mono text-outline">{rule.id} • {rule.protocol || 'ALL'} • {rule.action.toUpperCase()}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                      rule.enabled ? 'bg-primary/10 text-primary' : 'bg-outline-variant text-outline'
                    }`}>
                      {rule.enabled ? 'ENABLED' : 'DISABLED'}
                    </span>
                    <span className={`text-[9px] px-2 py-0.5 rounded font-bold ${
                      rule.action === 'block' ? 'bg-error/10 text-error' :
                      rule.action === 'alert' ? 'bg-tertiary/10 text-tertiary' :
                      'bg-primary/10 text-primary'
                    }`}>
                      {rule.action.toUpperCase()}
                    </span>
                  </div>
                </div>
              ))
            )}
          </div>

          <h2 className="text-lg font-bold flex items-center gap-2 uppercase tracking-widest">
            <HardDrive className="w-5 h-5 text-primary" /> System Status
          </h2>
          <div className="grid grid-cols-2 gap-4">
            <StatusCard label="Version" value="V2.4.0-STABLE" color="text-primary" />
            <StatusCard label="Platform" value="Windows 11" />
            <StatusCard label="Engine" value="WFP-Enforced" badge="ACTIVE" />
            <StatusCard label="Daemon" value="127.0.0.1:9876" badge="ONLINE" />
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusCard({ label, value, color = '', badge = '' }: { label: string; value: string; color?: string; badge?: string }) {
  return (
    <div className="p-3 bg-surface-container border border-outline-variant rounded-md">
      <div className="text-[9px] font-bold text-outline uppercase mb-1 tracking-widest">{label}</div>
      <div className="flex items-center gap-2">
        <div className={`text-xs font-mono font-bold ${color}`}>{value}</div>
        {badge && <span className="bg-primary/10 text-primary text-[8px] px-1 font-bold rounded">{badge}</span>}
      </div>
    </div>
  );
}

// ── Logs Screen ───────────────────────────────────────────────────────────────

function LogsScreen() {
  const { data, loading } = useApi<{ security: LogEntry[]; normal: LogEntry[] }>('/api/logs', 2000);
  const [filter, setFilter] = useState<'all' | 'security' | 'normal'>('all');
  const [search, setSearch] = useState('');

  const allLogs = useMemo(() => {
    const sec = (data?.security || []).map(l => ({ ...l, _type: 'security' as const }));
    const norm = (data?.normal || []).map(l => ({ ...l, _type: 'normal' as const }));
    let combined = [...sec, ...norm].sort((a, b) => b.time.localeCompare(a.time));
    if (filter !== 'all') combined = combined.filter(l => l._type === filter);
    if (search) {
      const s = search.toLowerCase();
      combined = combined.filter(l =>
        l.src_ip?.toLowerCase().includes(s) ||
        l.dst_ip?.toLowerCase().includes(s) ||
        l.process?.toLowerCase().includes(s) ||
        l.detail?.toLowerCase().includes(s)
      );
    }
    return combined.slice(0, 200);
  }, [data, filter, search]);

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center gap-4 mb-4">
        <div className="flex items-center gap-2 bg-surface-container border border-outline-variant rounded p-1">
          {(['all', 'security', 'normal'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1 text-[10px] font-bold uppercase transition-colors ${
                filter === f ? 'bg-primary text-on-primary' : 'text-outline hover:text-on-surface'
              }`}
            >
              {f}
            </button>
          ))}
        </div>
        <input
          className="bg-surface-container border border-outline-variant text-on-surface px-3 py-1 h-8 w-64 text-xs font-mono outline-none focus:border-primary"
          placeholder="Search IP, process, detail..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <div className="ml-auto text-[10px] font-mono text-outline">
          {loading && <Loader2 className="w-3 h-3 animate-spin inline mr-1" />}
          {allLogs.length} entries
        </div>
      </div>

      <div className="flex-1 overflow-auto bg-surface-container border border-outline-variant">
        <table className="w-full text-left font-mono text-[11px]">
          <thead className="sticky top-0 bg-surface-container-high z-10 border-b border-outline-variant">
            <tr className="h-8">
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Time</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Type</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Level</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Source</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Destination</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Proto</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Process</th>
              <th className="px-4 py-1 font-bold text-outline text-[10px] uppercase">Detail</th>
            </tr>
          </thead>
          <tbody>
            {allLogs.map((log, i) => (
              <tr key={`${log.time}-${i}`} className="border-b border-outline-variant hover:bg-surface-variant h-8">
                <td className="px-4 text-outline">{log.time}</td>
                <td className="px-4">
                  <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${
                    log._type === 'security' ? 'bg-error/10 text-error' : 'bg-primary/10 text-primary'
                  }`}>
                    {log._type}
                  </span>
                </td>
                <td className="px-4">
                  <span className={`text-[9px] font-bold ${
                    log.level === 'critical' ? 'text-error' : log.level === 'alert' ? 'text-tertiary' : 'text-primary'
                  }`}>
                    {log.level?.toUpperCase?.()}
                  </span>
                </td>
                <td className="px-4">{log.src_ip}:{log.src_port}</td>
                <td className="px-4">{log.dst_ip}:{log.dst_port}</td>
                <td className="px-4 text-outline">{log.proto}</td>
                <td className="px-4 text-outline">{log.process}</td>
                <td className="px-4 text-on-surface-variant">{log.detail}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}