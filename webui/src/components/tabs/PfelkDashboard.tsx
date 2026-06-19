// ═══════════════════════════════════════════════════
// PFELK Dashboard Tab - Network Traffic Analytics
// ═══════════════════════════════════════════════════

import { useEffect, useState } from 'react';
import { api } from '@/api';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer, PieChart,
  Pie, Cell, BarChart, Bar,
} from 'recharts';

const COLORS = ['#00E5FF', '#FF00FF', '#FFFF00', '#00FF88', '#FF8800', '#8800FF'];

function cyberColor(i: number) {
  const colors = ['text-cyber-accent', 'text-cyber-purple', 'text-cyber-green', 'text-yellow-400', 'text-pink-400', 'text-orange-400'];
  return colors[i % colors.length];
}

function CyberCard({ title, value, icon, color = 'cyan' }: {
  title: string; value: string | number; icon?: string; color?: string;
}) {
  const cm: Record<string, string> = { cyan: 'text-cyber-accent', green: 'text-cyber-green', magenta: 'text-cyber-purple', yellow: 'text-yellow-400' };
  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm">
      <div className="text-xs text-cyber-textMuted mb-1">{title}</div>
      <div className={`text-2xl font-bold ${cm[color] || 'text-cyber-accent'}`}>{value}</div>
      {icon && <div className="text-lg mt-1">{icon}</div>}
    </div>
  );
}

// ── Traffic Flow ──
function TrafficFlowSection() {
  const [flow, setFlow] = useState<any[]>([]);
  useEffect(() => { api.trafficFlow().then(d => setFlow(d?.flow || [])).catch(() => {}); }, []);
  if (!flow.length) return null;

  const nodeMap = new Map<string, number>();
  flow.forEach(f => { nodeMap.set(f.source, (nodeMap.get(f.source) || 0) + f.value); nodeMap.set(f.target, (nodeMap.get(f.target) || 0) + f.value); });
  const nodes = Array.from(nodeMap.entries()).map(([id, size]) => ({ id, size })).sort((a, b) => b.size - a.size).slice(0, 15);
  const edges = flow.filter(f => nodes.some(n => n.id === f.source) && nodes.some(n => n.id === f.target)).slice(0, 30);

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm">
      <h3 className="text-sm font-bold text-cyber-accent mb-3 flex items-center gap-2"><span>🔀</span> Traffic Flow — Top Connections</h3>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4" style={{ minHeight: 200 }}>
        <div className="lg:col-span-2" style={{ height: 200 }}>
          <svg className="w-full h-full" viewBox="0 0 600 200">
            {edges.map((edge, i) => {
              const si = nodes.findIndex(n => n.id === edge.source), ti = nodes.findIndex(n => n.id === edge.target);
              if (si === -1 || ti === -1) return null;
              return (<path key={i} d={`M${60 + (si%3)*160},${30+Math.floor(si/3)*60} Q${(120+si*160+540-ti*160)/2},${60+Math.floor((si+ti)/6)*60-30} ${540-(ti%3)*160},${30+Math.floor(ti/3)*60}`} stroke={COLORS[i%COLORS.length]} strokeWidth={Math.max(1,Math.min(4,edge.value/1000))} fill="none" opacity={0.6} />);
            })}
            {nodes.map((node, i) => (<g key={node.id}><circle cx={60+(i%3)*160} cy={30+Math.floor(i/3)*60} r={Math.max(4,Math.min(12,node.size/20000))} fill={COLORS[i%COLORS.length]} opacity={0.8} /><text x={60+(i%3)*160} y={30+Math.floor(i/3)*60+18} textAnchor="middle" style={{fill:'#888',fontSize:8}}>{node.id.length>12?node.id.substring(0,12)+'…':node.id}</text></g>))}
          </svg>
        </div>
        <div className="space-y-1 overflow-y-auto" style={{maxHeight:200}}>
          {nodes.map((node, i) => (<div key={node.id} className="flex items-center justify-between text-xs px-2 py-1 rounded bg-cyber-darker/50"><span className="text-cyber-text font-mono truncate max-w-[120px]" title={node.id}>{node.id.length>12?node.id.substring(0,12)+'…':node.id}</span><span className={`font-bold ${cyberColor(i)}`}>{(node.size/1000).toFixed(1)}k</span></div>))}
        </div>
      </div>
    </div>
  );
}

// ── Protocol Distribution ──
function ProtocolDistributionSection() {
  const [data, setData] = useState<{protocols:any[];total:number}>({protocols:[],total:0});
  useEffect(() => { api.protocolDistribution().then(d => setData(d||{protocols:[],total:0})).catch(() => {}); }, []);
  if (!data.protocols.length) return null;
  const chartData = data.protocols.map(p => ({ name: p.protocol, value: p.count, count: p.count, percent: p.percent }));

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:200}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>📊</span> Protocol Distribution</h3>
      <div className="flex items-center gap-4 h-[140px]">
        <div className="w-32 h-32 flex-shrink-0"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartData} cx="50%" cy="50%" innerRadius={25} outerRadius={45} paddingAngle={2} dataKey="value">{chartData.map((_,i) => <Cell key={i} fill={COLORS[i%COLORS.length]} />)}</Pie></PieChart></ResponsiveContainer></div>
        <div className="flex-1 space-y-1 overflow-y-auto">{chartData.map((p,i) => (<div key={p.name} className="flex items-center justify-between text-xs"><div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm" style={{backgroundColor:COLORS[i%COLORS.length]}}/><span className="text-cyber-text">{p.name}</span></div><div className="flex items-center gap-3"><span className="text-cyber-textMuted font-mono">{(p.count/1000).toFixed(1)}k</span><span className={`font-bold ${cyberColor(i)}`}>{p.percent}%</span></div></div>))}</div>
      </div>
    </div>
  );
}

// ── Action Distribution ──
function ActionDistributionSection() {
  const [data, setData] = useState<{actions:any[];total:number}>({actions:[],total:0});
  useEffect(() => { api.actionDistribution().then(d => setData(d||{actions:[],total:0})).catch(() => {}); }, []);
  if (!data.actions.length) return null;
  const chartData = data.actions.map(a => ({ name: a.action, value: a.count, count: a.count, percent: a.percent }));
  const aColors: Record<string,string> = { PASS: '#00FF88', BLOCK: '#FF4444', LOG: '#888888' };

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:200}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>🛡️</span> Action Distribution</h3>
      <div className="flex items-center gap-4 h-[140px]">
        <div className="w-32 h-32 flex-shrink-0"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartData} cx="50%" cy="50%" innerRadius={25} outerRadius={45} paddingAngle={2} dataKey="value">{chartData.map((_,i) => <Cell key={i} fill={aColors[data.actions[i]?.action]||'#888888'} />)}</Pie></PieChart></ResponsiveContainer></div>
        <div className="flex-1 space-y-1 overflow-y-auto">{chartData.map((a,i) => (<div key={a.name} className="flex items-center justify-between text-xs"><div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm" style={{backgroundColor:aColors[a.action]||'#888888'}}/><span className="text-cyber-text">{a.action}</span></div><div className="flex items-center gap-3"><span className="text-cyber-textMuted font-mono">{(a.count/1000).toFixed(1)}k</span><span className="font-bold text-cyber-green">{a.percent}%</span></div></div>))}</div>
      </div>
    </div>
  );
}

// ── Traffic Timeline ──
function TimelineSection() {
  const [data, setData] = useState<{timeline:any[];blocked_timeline:any[]}>({timeline:[],blocked_timeline:[]});
  useEffect(() => { api.timeline().then(d => setData(d||{timeline:[],blocked_timeline:[]})).catch(() => {}); }, []);
  if (!data.timeline.length) return null;

  const timeMap = new Map<string, {total:number;blocked:number}>();
  data.timeline.forEach(t => { const k=t.time.substring(0,16); const ex=timeMap.get(k)||{total:0,blocked:0}; ex.total+=t.count; timeMap.set(k,ex); });
  data.blocked_timeline.forEach(t => { const k=t.time.substring(0,16); const ex=timeMap.get(k)||{total:0,blocked:0}; ex.blocked+=t.count; timeMap.set(k,ex); });
  const chartData = Array.from(timeMap.entries()).sort(([a],[b])=>a.localeCompare(b)).map(([time,vals])=>({time:time.substring(5),total:vals.total,blocked:vals.blocked}));

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:220}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>📈</span> Traffic Timeline (Last 7 Days)</h3>
      <ResponsiveContainer width="100%" height="170">
        <AreaChart data={chartData}>
          <defs><linearGradient id="gT" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#00E5FF" stopOpacity={0.3}/><stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/></linearGradient><linearGradient id="gB" x1="0" y1="0" x2="0" y2="1"><stop offset="5%" stopColor="#FF4444" stopOpacity={0.3}/><stop offset="95%" stopColor="#FF4444" stopOpacity={0}/></linearGradient></defs>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,229,255,0.1)"/>
          <XAxis dataKey="time" stroke="#666" fontSize={10} tick={{fill:'#888'}}/>
          <YAxis stroke="#666" fontSize={10} tick={{fill:'#888'}}/>
          <Tooltip contentStyle={{backgroundColor:'rgba(10,15,30,0.95)',border:'1px solid rgba(0,229,255,0.3)',borderRadius:'8px',color:'#fff'}}/>
          <Legend wrapperStyle={{fontSize:'11px'}}/>
          <Area type="monotone" dataKey="total" name="Total Events" stroke="#00E5FF" fill="url(#gT)" strokeWidth={2}/>
          <Area type="monotone" dataKey="blocked" name="Blocked" stroke="#FF4444" fill="url(#gB)" strokeWidth={1}/>
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}

// ── Top Blocked IPs ──
function BlockedIpsSection() {
  const [data, setData] = useState<{blocked_ips:any[];total_blocked:number}>({blocked_ips:[],total_blocked:0});
  useEffect(() => { api.blockedIps().then(d => setData(d||{blocked_ips:[],total_blocked:0})).catch(() => {}); }, []);
  if (!data.blocked_ips.length) return null;
  const chartData = data.blocked_ips.map(ip => ({name:ip.ip.length>10?ip.ip.substring(0,10)+'…':ip.ip,count:ip.count})).slice(0,12);

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:220}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>🚫</span> Top Blocked IPs (24h)</h3>
      <ResponsiveContainer width="100%" height="170"><BarChart data={chartData} layout="vertical" margin={{top:5,right:30,left:20,bottom:5}}><CartesianGrid strokeDasharray="3 3" stroke="rgba(0,229,255,0.1)"/><XAxis type="number" stroke="#666" fontSize={10} tick={{fill:'#888'}}/><YAxis type="category" dataKey="name" width={90} stroke="#666" fontSize={9} tick={{fill:'#aaa'}}/><Tooltip contentStyle={{backgroundColor:'rgba(10,15,30,0.95)',border:'1px solid rgba(255,68,68,0.3)',borderRadius:'8px',color:'#fff'}}/><Bar dataKey="count" name="Blocked Events" fill="#FF4444" radius={[0,4,4,0]}/></BarChart></ResponsiveContainer>
      <div className="mt-2 text-xs text-cyber-textMuted text-center">Total blocked: <span className="text-red-400 font-bold">{(data.total_blocked/1000).toFixed(1)}k</span></div>
    </div>
  );
}

// ── Top Ports ──
function TopPortsSection() {
  const [data, setData] = useState<{ports:any[];total:number}>({ports:[],total:0});
  useEffect(() => { api.topPorts().then(d => setData(d||{ports:[],total:0})).catch(() => {}); }, []);
  if (!data.ports.length) return null;
  const chartData = data.ports.map(p => ({name:p.name,count:p.count,blockCount:p.block_count}));

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:220}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>🔌</span> Top Destination Ports</h3>
      <ResponsiveContainer width="100%" height="170"><BarChart data={chartData} margin={{top:5,right:30,left:20,bottom:5}}><CartesianGrid strokeDasharray="3 3" stroke="rgba(0,229,255,0.1)"/><XAxis dataKey="name" stroke="#666" fontSize={10} tick={{fill:'#aaa'}} interval={0} angle={-45} textAnchor="end" height={50}/><YAxis stroke="#666" fontSize={10} tick={{fill:'#888'}}/><Tooltip contentStyle={{backgroundColor:'rgba(10,15,30,0.95)',border:'1px solid rgba(0,229,255,0.3)',borderRadius:'8px',color:'#fff'}}/><Legend wrapperStyle={{fontSize:'11px'}}/><Bar dataKey="count" name="Total" fill="#00E5FF" radius={[2,2,0,0]}/><Bar dataKey="blockCount" name="Blocked" fill="#FF4444" radius={[2,2,0,0]}/></BarChart></ResponsiveContainer>
    </div>
  );
}

// ── Direction ──
function DirectionSection() {
  const [data, setData] = useState<{directions:any[];total:number}>({directions:[],total:0});
  useEffect(() => { api.directionDistribution().then(d => setData(d||{directions:[],total:0})).catch(() => {}); }, []);
  if (!data.directions.length) return null;
  const chartData = data.directions.map(d => ({name:d.direction,value:d.count}));
  const dColors: Record<string,string> = {'in':'#00E5FF','out':'#FF00FF','external':'#00FF88','internal':'#FFFF00'};

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm" style={{height:200}}>
      <h3 className="text-sm font-bold text-cyber-accent mb-2 flex items-center gap-2"><span>🔄</span> Network Direction</h3>
      <div className="flex items-center gap-4 h-[140px]">
        <div className="w-32 h-32 flex-shrink-0"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={chartData} cx="50%" cy="50%" innerRadius={25} outerRadius={45} paddingAngle={2} dataKey="value">{chartData.map((_,i) => <Cell key={i} fill={dColors[data.directions[i]?.direction]||COLORS[i%COLORS.length]} />)}</Pie></PieChart></ResponsiveContainer></div>
        <div className="flex-1 space-y-1 overflow-y-auto">{chartData.map((d,i) => (<div key={d.name} className="flex items-center justify-between text-xs"><div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm" style={{backgroundColor:dColors[d.name]||COLORS[i%COLORS.length]}}/><span className="text-cyber-text">{d.name}</span></div><span className={`font-bold ${cyberColor(i)}`}>{d.value>0?(d.value/data.total*100).toFixed(1):0}%</span></div>))}</div>
      </div>
    </div>
  );
}

// ── Rule Heatmap ──
function RuleHeatmapSection() {
  const [data, setData] = useState<{heatmap:any[];rules:string[]}>({heatmap:[],rules:[]});
  useEffect(() => { api.ruleHeatmap().then(d => setData(d||{heatmap:[],rules:[]}) ).catch(() => {}); }, []);
  if (!data.heatmap.length) return null;
  const maxCount = Math.max(...data.heatmap.flatMap(h => h.hourly.map(h2 => h2.count)), 1);

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm">
      <h3 className="text-sm font-bold text-cyber-accent mb-3 flex items-center gap-2"><span>🔥</span> Rule Activity Heatmap (Last 24h)</h3>
      <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="border-b border-cyber-border"><th className="py-1 px-2 text-left text-cyber-textMuted">Rule</th><th className="py-1 px-2 text-cyber-textMuted text-right">Total</th><th className="py-1 px-2 text-cyber-textMuted" colSpan={24}>Hourly →</th></tr></thead><tbody>{data.heatmap.slice(0,15).map(rule => { const hours:number[] = new Array(24).fill(0); rule.hourly.forEach(h => { const hour = parseInt(h.time.split(' ')[1]?.split(':')[0] || '0'); if (hour >= 0 && hour < 24) hours[hour] = h.count; }); const total = hours.reduce((a,b) => a+b, 0); return (<tr key={rule.rule} className="border-b border-cyber-border/50 hover:bg-cyber-panelHover/30"><td className="py-1 px-2 font-mono text-cyber-text truncate max-w-[150px]" title={rule.rule}>{rule.rule.length>20?rule.rule.substring(0,20)+'…':rule.rule}</td><td className="py-1 px-2 text-right font-bold text-cyber-accent">{total.toLocaleString()}</td>{hours.map((count,hi) => (<td key={hi} className="py-0.5 px-0.5 text-center"><div className="w-3 h-3 rounded-sm mx-auto" style={{backgroundColor:count>0?`rgba(0,229,255,${Math.min(1,count/maxCount)})`:'transparent'}} title={`Hour ${hi}: ${count}`}/></td>))}</tr>);})}</tbody></table></div>
      <div className="mt-2 flex items-center gap-2 text-xs text-cyber-textMuted"><span>Less</span><div className="w-20 h-3 rounded-sm" style={{background:'linear-gradient(to right,transparent,rgba(0,229,255,0.1),rgba(0,229,255,0.3),rgba(0,229,255,0.6),rgba(0,229,255,0.9))'}}/><span>More</span></div>
    </div>
  );
}

// ── Rule Pass/Block ──
function RuleActionSection() {
  const [data, setData] = useState<{rules:any[]}>({rules:[]});
  useEffect(() => { api.ruleActionBreakdown().then(d => setData(d||{rules:[]}) ).catch(() => {}); }, []);
  if (!data.rules.length) return null;

  return (
    <div className="bg-cyber-panel/60 border border-cyber-border rounded-lg p-4 backdrop-blur-sm">
      <h3 className="text-sm font-bold text-cyber-accent mb-3 flex items-center gap-2"><span>⚖️</span> Rule Pass/Block Breakdown</h3>
      <div className="overflow-x-auto"><table className="w-full text-xs"><thead><tr className="border-b border-cyber-border"><th className="py-1 px-2 text-left text-cyber-textMuted">Rule</th><th className="py-1 px-2 text-right text-cyber-textMuted">Pass</th><th className="py-1 px-2 text-right text-red-400">Block</th><th className="py-1 px-2 text-right text-cyber-accent">Total</th></tr></thead><tbody>{data.rules.slice(0,15).map(rule => (<tr key={rule.name} className="border-b border-cyber-border/50 hover:bg-cyber-panelHover/30"><td className="py-1 px-2 font-mono text-cyber-text truncate max-w-[200px]" title={rule.name}>{rule.name.length>25?rule.name.substring(0,25)+'…':rule.name}</td><td className="py-1 px-2 text-right text-cyber-green">{rule.pass.toLocaleString()}</td><td className="py-1 px-2 text-right text-red-400">{rule.block.toLocaleString()}</td><td className="py-1 px-2 text-right font-bold text-cyber-accent">{rule.total.toLocaleString()}</td></tr>))}</tbody></table></div>
    </div>
  );
}

// ── Summary stats ──
function useSummaryStats() {
  const [data, setData] = useState({total:0,passed:0,blocked:0,topProtocol:'—'});
  useEffect(() => {
    Promise.all([api.actionDistribution(), api.protocolDistribution()]).then(([actions, protocols]) => {
      const passed = actions?.actions?.find((a:any) => a.action === 'PASS')?.count || 0;
      const blocked = actions?.actions?.find((a:any) => a.action === 'BLOCK')?.count || 0;
      setData({total: actions?.total || 0, passed, blocked, topProtocol: protocols?.protocols?.[0]?.protocol || '—'});
    }).catch(err => console.error('Stats fetch error:', err));
  }, []);
  return data;
}

// ── Main PFELK Dashboard ──
export default function PfelkDashboard() {
  const stats = useSummaryStats();
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div><h1 className="text-xl font-bold text-gradient-cyber">PFELK Network Analytics</h1><p className="text-xs text-cyber-textMuted mt-1">Firewall traffic visualization — powered by PostgreSQL</p></div>
        <div className="flex gap-3"><div className="bg-cyber-green/10 border border-cyber-green/30 rounded-lg px-3 py-1 text-xs"><span className="text-cyber-green">●</span> Live</div></div>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <CyberCard title="Total Events (24h)" value={stats.total>0?(stats.total/1000).toFixed(1)+'k':'—'} icon="📊" color="cyan"/>
        <CyberCard title="Passed" value={stats.passed>0?(stats.passed/1000).toFixed(1)+'k':'—'} icon="✅" color="green"/>
        <CyberCard title="Blocked" value={stats.blocked>0?(stats.blocked/1000).toFixed(1)+'k':'—'} icon="🚫" color="magenta"/>
        <CyberCard title="Top Protocol" value={stats.topProtocol} icon="🔀" color="yellow"/>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="lg:col-span-2"><TrafficFlowSection/></div>
        <ProtocolDistributionSection/>
        <ActionDistributionSection/>
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <BlockedIpsSection/>
        <TopPortsSection/>
        <div className="lg:col-span-2"><DirectionSection/></div>
      </div>
      <TimelineSection/>
      <RuleHeatmapSection/>
      <RuleActionSection/>
    </div>
  );
}
