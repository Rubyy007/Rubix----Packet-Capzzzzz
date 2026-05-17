/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { useState } from 'react';
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
  ChevronRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

// Types
type Screen = 'Live' | 'Threats' | 'Performance' | 'System' | 'Logs';

export default function App() {
  const [activeScreen, setActiveScreen] = useState<Screen>('Threats');

  const navigation = [
    { name: 'Live', icon: Activity, id: 'Live' as Screen },
    { name: 'Threats', icon: ShieldAlert, id: 'Threats' as Screen },
    { name: 'Performance', icon: Gauge, id: 'Performance' as Screen },
    { name: 'System', icon: Settings, id: 'System' as Screen },
    { name: 'Logs', icon: Terminal, id: 'Logs' as Screen },
  ];

  return (
    <div className="flex h-screen w-full bg-surface-dim text-on-surface font-sans overflow-hidden">
      {/* Top Navigation Bar */}
      <header className="fixed top-0 z-50 flex h-12 w-full items-center justify-between border-b border-outline-variant bg-surface-dim px-4">
        <div className="flex items-center gap-4">
          <span className="text-2xl font-black tracking-tighter text-primary">RUBIX</span>
          <div className="h-4 w-px bg-outline-variant"></div>
          <span className="text-[10px] font-bold tracking-widest text-on-surface-variant uppercase font-mono">
            Security Operations Center
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-4 mr-4 px-4 border-r border-outline-variant">
             <div className="flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                <span className="text-[10px] font-bold text-primary font-mono">LIVE</span>
             </div>
             <span className="text-[10px] text-outline font-mono">127.0.0.1:9876</span>
          </div>
          <button className="p-2 transition-colors hover:bg-surface-variant active:opacity-80 rounded">
            <Radio className="w-4 h-4 text-primary" />
          </button>
          <button className="p-2 transition-colors hover:bg-surface-variant active:opacity-80 rounded">
            <Settings className="w-4 h-4 text-primary" />
          </button>
          <button className="p-2 transition-colors hover:bg-surface-variant active:opacity-80 rounded">
            <Power className="w-4 h-4 text-error" />
          </button>
        </div>
      </header>

      {/* Side Navigation Bar */}
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

      {/* Main Content Area */}
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
            {activeScreen === 'Threats' && <ThreatsScreen />}
            {activeScreen === 'Live' && <LiveScreen />}
            {activeScreen === 'Performance' && <PerformanceScreen />}
            {activeScreen === 'System' && <SystemScreen />}
            {activeScreen === 'Logs' && <div className="p-8 text-center opacity-50 font-mono">LOG_STREAM_INITIALIZING...</div>}
          </motion.div>
        </AnimatePresence>
      </main>
    </div>
  );
}

// Components for each screen would go here or be imported

function ThreatsScreen() {
  return (
    <div className="flex h-full flex-col">
       {/* Timeline */}
       <div className="h-[60px] shrink-0 border-b border-outline-variant bg-surface-container-lowest flex items-center px-4 gap-4 sticky top-0 z-30">
          <div className="shrink-0 flex flex-col justify-center">
            <span className="text-[10px] font-bold text-outline leading-none">THREAT</span>
            <span className="text-[10px] font-bold text-outline leading-none">TIMELINE</span>
          </div>
          <div className="flex-1 flex items-end h-8 gap-[2px]">
            {/* Generating mock bars */}
            {Array.from({ length: 60 }).map((_, i) => {
              const heights = [2, 3, 6, 4, 5, 1, 8, 3, 2, 2, 7, 1, 4, 5, 2, 3, 6, 1, 4, 2, 2, 8, 1, 3, 2, 5, 6, 1, 2, 3, 7, 4, 2, 8, 3, 1, 2, 5, 6, 2, 4, 7, 1, 2, 3, 8, 2, 5, 1, 6, 2, 4, 1, 7, 3, 2, 3, 5, 8, 8];
              const h = heights[i % heights.length];
              const isError = h > 5;
              const isWarning = h > 3 && h <= 5;
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
          {/* Threats List */}
          <div className="col-span-12 lg:col-span-7 flex flex-col bg-surface-container border border-outline-variant overflow-hidden">
             <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant flex justify-between items-center">
                <div className="flex items-center gap-2">
                   <ShieldAlert className="w-4 h-4 text-error" />
                   <span className="text-sm font-bold uppercase tracking-wide">Active Threats</span>
                   <span className="bg-error-container text-on-error-container px-2 py-0.5 text-[11px] font-mono rounded">4 Detected</span>
                </div>
                <span className="text-[11px] font-mono text-outline">SORT: SEVERITY ↓</span>
             </div>
             <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-2">
                <ThreatCard 
                  severity="CRITICAL" 
                  title="DDoS SYN Flood" 
                  details="ID: TX-9022 • Source: 192.168.1.104 • Dest: Internal_LB_01"
                  description="Multiple half-open connections detected from external gateway node. Traffic spike exceeding 4.2Gbps. Automated mitigation threshold at 90%."
                />
                <ThreatCard 
                  severity="HIGH" 
                  title="Brute Force Attempt" 
                  details="ID: TX-8911 • Target: LDAP_AUTH_SRV • Failed: 142"
                  description="Rapid sequence of failed authentication attempts detected for 'root' and 'sysadmin' accounts from 203.0.113.42."
                />
                <ThreatCard 
                  severity="MEDIUM" 
                  title="Large Exfiltration Flow" 
                  details="ID: TX-8750 • Path: FILE_SRV_02 -> Unknown_Ext_IP"
                  description="Sustained outbound encrypted connection detected transferring 4.8GB over the last 12 minutes to an unlisted cloud endpoint."
                />
             </div>
          </div>

          {/* Details & Logs */}
          <div className="col-span-12 lg:col-span-5 flex flex-col gap-4 min-h-0">
            <section className="bg-surface-container border border-outline-variant flex flex-col flex-1 overflow-hidden">
               <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant uppercase">
                 <span className="text-sm font-bold tracking-wide">Flow Reconstruction</span>
               </div>
               <div className="flex-1 p-4 bg-surface-dim relative overflow-hidden flex flex-col items-center justify-center">
                  <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(#30363D 1px, transparent 1px)', backgroundSize: '16px 16px' }} />
                  <div className="relative z-10 w-full px-8 flex flex-col items-center gap-8">
                     <div className="w-full flex items-center justify-between">
                        <div className="flex flex-col items-center gap-2">
                           <div className="w-12 h-12 bg-surface-variant border border-outline flex items-center justify-center rounded">
                              <Radio className="w-6 h-6 text-outline" />
                           </div>
                           <span className="text-[10px] font-mono text-outline">SOURCE: EXTERNAL</span>
                        </div>
                        <div className="flex-1 h-px bg-error relative flex items-center justify-center">
                           <div className="absolute w-4 h-4 rounded-full bg-error status-pulse" />
                           <div className="absolute -top-6 text-[10px] font-mono font-bold text-error">SYN PACKETS</div>
                        </div>
                        <div className="flex flex-col items-center gap-2">
                           <div className="w-12 h-12 bg-surface-variant border border-error flex items-center justify-center rounded">
                              <Cpu className="w-6 h-6 text-error" />
                           </div>
                           <span className="text-[10px] font-mono text-error">TARGET: GATEWAY</span>
                        </div>
                        <div className="flex-1 h-px bg-outline-variant border-dashed mx-2" />
                        <div className="flex flex-col items-center gap-2 opacity-50 grayscale">
                          <div className="w-12 h-12 bg-surface-variant border border-outline flex items-center justify-center rounded">
                             <Terminal className="w-6 h-6 text-outline" />
                          </div>
                          <span className="text-[10px] font-mono text-outline">DATABASE_NODE</span>
                        </div>
                     </div>
                     <div className="w-full bg-surface-container-lowest border border-outline-variant p-4">
                        <div className="text-[10px] font-bold text-primary mb-2 uppercase tracking-widest">Packet Analysis</div>
                        <div className="space-y-1 font-mono text-[11px] text-outline">
                           <div className="flex justify-between"><span>TCP Flags:</span><span className="text-error">SYN, ECE, CWR</span></div>
                           <div className="flex justify-between"><span>Payload size:</span><span>0 Bytes</span></div>
                           <div className="flex justify-between"><span>PPS rate:</span><span className="text-error">128,400 pps</span></div>
                           <div className="flex justify-between"><span>TTL distribution:</span><span>Uniform (64)</span></div>
                        </div>
                     </div>
                  </div>
               </div>
            </section>
            
            <section className="bg-surface-container border border-outline-variant h-[40%] flex flex-col overflow-hidden">
               <div className="bg-surface-container-high px-4 py-2 border-b border-outline-variant flex justify-between items-center">
                 <span className="text-sm font-bold uppercase tracking-wide">Threat Log</span>
                 <Terminal className="w-3 h-3 text-outline cursor-pointer hover:text-white" />
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
                        <LogEntry time="14:20:01.04" event="SYNC_FLOOD" source="192.168.1.104" action="PENDING" isAlert />
                        <LogEntry time="14:19:58.42" event="AUTH_FAILURE" source="203.0.113.42" action="LOGGED" />
                        <LogEntry time="14:19:45.11" event="DATA_EXFIL" source="10.0.0.122" action="THROTTLED" isSecondary />
                        <LogEntry time="14:18:22.09" event="PORT_SCAN" source="45.33.22.11" action="DROPPED" />
                     </tbody>
                  </table>
               </div>
            </section>
          </div>
       </div>
    </div>
  );
}

function ThreatCard({ severity, title, details, description }: { severity: string, title: string, details: string, description: string }) {
  const color = severity === 'CRITICAL' ? 'bg-error' : severity === 'HIGH' ? 'bg-tertiary' : 'bg-secondary';
  const textColor = severity === 'CRITICAL' ? 'text-on-error' : 'text-on-surface';
  
  return (
    <div className="group relative border border-outline-variant bg-surface-container-low p-4 flex gap-4 transition-colors hover:bg-surface-variant">
       <div className={`absolute left-0 top-0 bottom-0 w-1 ${color}`} />
       <div className="flex-1">
          <div className="flex justify-between items-start mb-2">
             <div className="flex flex-col gap-1">
                <div className="flex items-center gap-2">
                   <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${color} ${textColor} ${severity === 'CRITICAL' ? 'status-pulse' : ''}`}>
                      {severity}
                   </span>
                   <span className="text-md font-bold">{title}</span>
                </div>
                <span className="text-[11px] font-mono text-outline">{details}</span>
             </div>
             <div className="flex gap-2">
                <button className={`px-3 py-1 ${color} ${textColor} text-[10px] font-bold uppercase transition-transform active:scale-95`}>Block IP</button>
                <button className="px-3 py-1 bg-surface-variant border border-outline-variant text-[10px] font-bold uppercase transition-transform active:scale-95">Investigate</button>
             </div>
          </div>
          <p className="text-xs text-on-surface-variant leading-relaxed">
             {description}
          </p>
       </div>
    </div>
  );
}

function LogEntry({ time, event, source, action, isAlert = false, isSecondary = false }: { time: string, event: string, source: string, action: string, isAlert?: boolean, isSecondary?: boolean }) {
  return (
    <tr className="border-b border-outline-variant hover:bg-surface-variant transition-colors h-8">
       <td className="px-4 text-outline">{time}</td>
       <td className={`px-4 font-bold ${isAlert ? 'text-error' : isSecondary ? 'text-secondary' : 'text-tertiary'}`}>{event}</td>
       <td className="px-4">{source}</td>
       <td className="px-4 font-bold italic">{action}</td>
    </tr>
  );
}

function LiveScreen() {
  const metrics = [
    { label: 'Packets per sec', value: '2,847', trend: '+2.4%', color: 'text-primary' },
    { label: 'Active Blocks', value: '12', trend: 'CRITICAL', color: 'text-error' },
    { label: 'Security Alerts', value: '3', trend: 'WARNING', color: 'text-tertiary' },
    { label: 'System Runtime', value: '04:12:33', detail: 'Uptime 99.9%', color: 'text-on-surface' },
  ];

  return (
    <div className="flex h-full flex-col">
       <div className="grid grid-cols-4 border-b border-outline-variant bg-surface-container shrink-0">
          {metrics.map((m, i) => (
            <div key={i} className={`p-4 border-r border-outline-variant flex flex-col justify-between h-[100px] last:border-r-0`}>
               <div className="flex justify-between items-start">
                  <span className="text-[10px] font-bold text-outline uppercase tracking-wider">{m.label}</span>
                  {m.trend && <span className={`text-[10px] font-mono font-bold ${i === 1 ? 'text-error' : i===2 ? 'text-tertiary' : 'text-primary'}`}>{m.trend}</span>}
                  {m.detail && <span className="text-[10px] font-mono text-secondary">{m.detail}</span>}
               </div>
               <div className="flex items-end justify-between">
                  <span className={`text-2xl font-bold ${m.color}`}>{m.value}</span>
                  <div className="flex items-end gap-0.5 h-6">
                    {[3, 5, 2, 8, 4, 10, 6, 12, 4].map((h, j) => (
                      <div key={j} className={`w-0.5 ${i === 1 ? 'bg-error' : i === 2 ? 'bg-tertiary' : 'bg-primary'}`} style={{ height: `${h * 2}px` }} />
                    ))}
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
                {Array.from({ length: 40 }).map((_, i) => (
                  <div key={i} className={`grid grid-cols-[100px_40px_160px_160px_80px_80px_1fr] h-8 items-center px-4 border-b border-outline-variant hover:bg-surface-variant group cursor-pointer transition-colors ${i === 0 ? 'border-l-2 border-error' : ''}`}>
                     <div className="text-outline">04:12:33.{402 - i * 5}</div>
                     <div className="flex justify-center">
                        <div className={`w-1.5 h-1.5 rounded-full ${i % 3 === 0 ? 'bg-error' : i % 5 === 0 ? 'bg-secondary' : 'bg-tertiary'}`} />
                     </div>
                     <div className={i % 3 === 0 ? 'text-error font-bold' : ''}>{192}.168.{1}.{104 + i}</div>
                     <div className="text-on-surface">10.0.0.{52 + i}</div>
                     <div className="text-on-surface-variant">TCP</div>
                     <div className="text-on-surface-variant">{443 + i}</div>
                     <div className="text-outline truncate">nginx/proxy_svc</div>
                  </div>
                ))}
                <div className="py-8 text-center text-[10px] text-outline font-bold tracking-[0.2em]">... CONTINUOUS STREAM (BUFFERING 12,000 EVENTS) ...</div>
             </div>
          </div>

          <div className="w-[300px] border-l border-outline-variant bg-surface-container flex flex-col shrink-0 overflow-hidden">
             <div className="p-4 border-b border-outline-variant bg-surface-container-high flex justify-between items-center">
                <span className="text-sm font-bold uppercase tracking-wide">Event Analysis</span>
                <button className="text-outline hover:text-white"><Terminal className="w-3 h-3" /></button>
             </div>
             <div className="flex-1 p-4 space-y-4 overflow-y-auto">
                <div className="bg-surface-container-lowest p-4 border border-outline-variant">
                   <div className="text-[10px] font-bold text-error mb-2 tracking-widest">CRITICAL THREAT DETECTED</div>
                   <div className="space-y-4">
                      <div>
                         <div className="text-[10px] font-bold text-outline mb-1 uppercase">Signature ID</div>
                         <div className="text-xs font-mono font-bold text-on-surface">ET-P022-XPL-SYSCALL</div>
                      </div>
                      <div>
                         <div className="text-[10px] font-bold text-outline mb-1 uppercase">Description</div>
                         <p className="text-[11px] text-on-surface-variant leading-relaxed">Unexpected syscall from internal IP targeting sensitive directory /etc/shadow. Packet payload contains shellcode pattern.</p>
                      </div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                           <div className="text-[10px] font-bold text-outline mb-1 uppercase">Confidence</div>
                           <div className="text-xs font-mono font-bold text-primary">98.2%</div>
                        </div>
                        <div>
                           <div className="text-[10px] font-bold text-outline mb-1 uppercase">Recurrence</div>
                           <div className="text-xs font-mono font-bold">12/min</div>
                        </div>
                      </div>
                   </div>
                </div>
                <div className="space-y-2">
                   <div className="text-[10px] font-bold text-outline uppercase border-b border-outline-variant pb-1 tracking-widest">Raw Packet Header</div>
                   <div className="bg-surface-container-lowest p-2 font-mono text-[10px] text-primary leading-relaxed break-all">
                      0000 00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00<br/>
                      0010 00 28 00 00 40 00 40 06 00 00 ac 10 00 2c ac 10<br/>
                      0020 00 01 00 50 00 50 00 00 00 00 00 00 00 00 50 02<br/>
                      0030 20 00 00 00 00 00
                   </div>
                </div>
             </div>
             <div className="p-4 border-t border-outline-variant bg-surface-container grid grid-cols-2 gap-2">
                <button className="px-3 py-1 bg-error text-on-error text-[10px] font-bold uppercase transition-transform active:scale-95">Block SRC IP</button>
                <button className="px-3 py-1 bg-surface-variant border border-outline-variant text-[10px] font-bold uppercase transition-transform active:scale-95">Dismiss</button>
             </div>
          </div>
       </div>
    </div>
  );
}

function PerformanceScreen() {
  return (
    <div className="p-6 h-full flex flex-col gap-6 overflow-y-auto">
       <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <ChartPanel title="Throughput (TX/RX)" value="1.2 GB/s" type="area" />
          <ChartPanel title="Packet Block Rate" value="4.2%" type="bar" color="error" />
          <ChartPanel title="Alert Frequency" value="12/min" type="bar" color="tertiary" />
          <ChartPanel title="Memory RSS" value="14.8 GB" type="line" />
          <ChartPanel title="Queue Depth" value="75%" type="gauge" />
          <ChartPanel title="System Heatmap" value="0.05ms LAT" type="heatmap" />
       </div>
       
       <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-[400px]">
          <section className="bg-surface-container border border-outline-variant flex flex-col">
             <div className="h-8 border-b border-outline-variant bg-surface-container-high px-4 flex items-center justify-between text-[10px] font-bold text-on-surface uppercase tracking-widest">
                <span>Top Processes</span>
                <Settings className="w-3 h-3 text-outline" />
             </div>
             <div className="flex-1 overflow-auto bg-surface-dim font-mono text-[11px]">
                <table className="w-full text-left">
                   <thead className="bg-surface-container border-b border-outline-variant text-outline">
                      <tr>
                         <th className="px-4 py-1">PID</th>
                         <th className="px-2 py-1">Name</th>
                         <th className="px-2 py-1 text-right">Packets</th>
                         <th className="px-2 py-1">Bytes</th>
                      </tr>
                   </thead>
                   <tbody>
                      {['rubix_core.bin', 'ingress_proxy', 'suricata_ids', 'postgres_main'].map((p, i) => (
                        <tr key={i} className="border-b border-outline-variant h-8 hover:bg-surface-variant">
                           <td className="px-4 text-primary">102{i}</td>
                           <td className="px-2">{p}</td>
                           <td className="px-2 text-right">{8.4 - i * 1.2}M</td>
                           <td className="px-2">
                             <div className="flex items-center gap-2">
                                <div className="h-1.5 w-full max-w-[100px] bg-outline-variant rounded-full overflow-hidden">
                                   <div className="bg-primary h-full" style={{ width: `${85 - i * 15}%` }} />
                                </div>
                                <span>{1.2 - i * 0.2}GB</span>
                             </div>
                           </td>
                        </tr>
                      ))}
                   </tbody>
                </table>
             </div>
          </section>
          
          <section className="bg-surface-container border border-outline-variant flex flex-col p-4 gap-4">
             <div className="text-[10px] font-bold text-on-surface uppercase tracking-widest mb-2">Interface Status</div>
             <InterfaceCard name="eth0" status="UP" drops="1,242 pkts/hr" filter="tcp port 443" color="primary" />
             <InterfaceCard name="eth1" status="UP" drops="0 pkts/hr" filter="udp and dst port 514" color="primary" />
             <InterfaceCard name="lo" status="LOCAL" drops="0 pkts/hr" filter="none" color="outline" opacity="opacity-50" />
          </section>
       </div>
    </div>
  );
}

function ChartPanel({ title, value, type, color = 'primary' }: { title: string, value: string, type: string, color?: string }) {
  return (
    <div className="bg-surface-container border border-outline-variant p-4 h-[180px] flex flex-col">
       <div className="flex justify-between items-start mb-4">
          <span className="text-[10px] font-bold text-outline uppercase tracking-widest">{title}</span>
          <span className={`text-xs font-mono font-bold text-${color}`}>{value}</span>
       </div>
       <div className="flex-1 relative flex items-end justify-between gap-1">
          {type === 'bar' && Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className={`flex-1 bg-${color} opacity-${20 + (i * 10)}`} style={{ height: `${Math.random() * 100}%` }} />
          ))}
          {type === 'area' && (
             <div className="w-full h-full bg-gradient-to-t from-primary/10 to-transparent border-t border-primary/50 relative overflow-hidden">
                <div className="absolute inset-x-0 top-0 h-[2px] bg-primary/20 blur-sm" />
             </div>
          )}
          {type === 'heatmap' && (
             <div className="grid grid-cols-8 grid-rows-3 gap-1 w-full h-full">
                {Array.from({ length: 24 }).map((_, i) => (
                  <div key={i} className={`rounded-sm bg-${i % 7 === 0 ? 'error' : 'primary'} opacity-${20 + (i * 3) % 80}`} />
                ))}
             </div>
          )}
          {type === 'gauge' && (
             <div className="relative w-24 h-24 mx-auto flex items-center justify-center">
                <svg className="w-full h-full transform -rotate-90">
                   <circle className="text-surface-variant" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeWidth="6" />
                   <circle className="text-primary" cx="48" cy="48" fill="transparent" r="40" stroke="currentColor" strokeDasharray="251.2" strokeDashoffset="62.8" strokeWidth="6" />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center font-bold text-xl">{value}</div>
             </div>
          )}
       </div>
    </div>
  );
}

function InterfaceCard({ name, status, drops, filter, color, opacity = '' }: any) {
  return (
    <div className={`bg-surface-container-low border border-outline-variant p-3 rounded-md ${opacity}`}>
       <div className="flex justify-between items-center mb-2">
          <div className="flex items-center gap-2">
             <div className={`text-${color} text-xs font-bold uppercase`}>{name}</div>
             <span className={`bg-${color}/10 text-${color} text-[9px] px-1 border border-${color}/20 rounded uppercase font-bold`}>{status}</span>
          </div>
       </div>
       <div className="grid grid-cols-2 gap-4 text-[11px] font-mono">
          <div>
             <div className="text-[9px] text-outline uppercase font-bold mb-1">Drops</div>
             <div className="text-error">{drops}</div>
          </div>
          <div className="truncate">
             <div className="text-[9px] text-outline uppercase font-bold mb-1">Filter</div>
             <div className="text-on-surface-variant truncate">{filter}</div>
          </div>
       </div>
    </div>
  );
}

function SystemScreen() {
  return (
    <div className="h-full flex flex-col">
       <div className="p-4 border-b border-outline-variant bg-surface-container-low flex items-center gap-4">
          <div className="flex items-center gap-2 bg-surface-container p-1 border border-outline-variant rounded">
             <input className="bg-surface-dim border border-error text-on-surface px-2 h-7 w-36 text-xs font-mono outline-none" placeholder="Target IP" value="10.42.0." readOnly />
             <select className="bg-surface-dim border border-outline-variant text-on-surface px-2 h-7 text-xs font-mono outline-none">
                <option>1h</option>
             </select>
             <button className="bg-primary text-surface-dim font-bold px-3 h-7 text-[10px] hover:opacity-90 uppercase">Block IP</button>
          </div>
          <div className="flex items-center gap-2 bg-surface-container p-1 border border-outline-variant rounded">
             <input className="bg-surface-dim border border-primary text-on-surface px-2 h-7 w-24 text-xs font-mono outline-none" placeholder="PID" value="8421" readOnly />
             <button className="bg-primary text-surface-dim font-bold px-3 h-7 text-[10px] hover:opacity-90 uppercase">Block PID</button>
          </div>
       </div>

       <div className="flex-1 flex overflow-hidden">
          <div className="w-1/2 p-6 border-r border-outline-variant overflow-y-auto space-y-6">
             <h2 className="text-lg font-bold flex items-center gap-2 uppercase tracking-widest"><ShieldAlert className="w-5 h-5 text-primary" /> Active System Blocks</h2>
             
             <div className="border border-outline-variant rounded bg-surface-container-low overflow-hidden">
                <div className="bg-surface-container px-3 py-2 border-b border-outline-variant flex justify-between items-center text-[10px] font-bold text-outline tracking-widest uppercase">
                   <span>Network: IP Addresses</span>
                   <div className="w-2 h-2 rounded-full bg-error animate-pulse" />
                </div>
                <table className="w-full text-[11px] font-mono">
                   <thead className="bg-surface-container text-outline uppercase border-b border-outline-variant">
                      <tr className="h-8">
                         <th className="px-4 font-normal text-left">Target</th>
                         <th className="px-4 font-normal text-left">TTL</th>
                         <th className="px-4 font-normal text-right">Action</th>
                      </tr>
                   </thead>
                   <tbody>
                      <tr className="h-8 border-b border-outline-variant hover:bg-surface-variant">
                         <td className="px-4 text-error font-bold">192.168.1.104</td>
                         <td className="px-4 text-outline">00:42:12</td>
                         <td className="px-4 text-right"><button className="text-primary hover:underline font-bold">UNBLOCK</button></td>
                      </tr>
                   </tbody>
                </table>
             </div>
          </div>

          <div className="w-1/2 p-6 bg-surface-container-lowest overflow-y-auto space-y-6">
             <h2 className="text-lg font-bold flex items-center gap-2 uppercase tracking-widest">System Status</h2>
             <div className="grid grid-cols-2 gap-4">
                <StatusCard label="Version" value="V2.4.0-STABLE" color="text-primary" />
                <StatusCard label="Platform" value="Debian 12" />
                <StatusCard label="Uptime" value="14d 06h 22m" />
                <StatusCard label="Engine" value="eBPF-Enforced" badge="ACTIVE" />
             </div>

             <div className="space-y-2">
                <div className="text-[10px] font-bold text-outline uppercase tracking-widest">Current BPF Runtime String</div>
                <div className="bg-surface-dim border border-outline-variant p-4 font-mono text-[11px] text-on-surface-variant overflow-x-auto whitespace-pre leading-relaxed rounded-md">
(ip.src == 192.168.0.0/16 || ip.src == 10.0.0.0/8) &&
(tcp.port == 443 || tcp.port == 80) &&
!(eth.addr == 00:0c:29:43:52:11) &&
action.drop_persistent(active_blacklist)</div>
             </div>
          </div>
       </div>
    </div>
  );
}

function StatusCard({ label, value, color = '', badge = '' }: any) {
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

