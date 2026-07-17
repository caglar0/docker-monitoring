import React, { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line, Tooltip, Legend, PieChart, Pie, Cell } from "recharts";
import { ChartContainer, ChartTooltip } from "./components/ui/chart";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { Badge } from "./components/ui/badge";
import { ChevronDown, ChevronUp, Activity, ShieldAlert, Database, Clock, Box, AlertTriangle } from "lucide-react";

const API = "http://localhost:8000";

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard"); // dashboard | logs | containers | metrics_history
  const [logs, setLogs] = useState([]);
  const [liveMetrics, setLiveMetrics] = useState({ hosts: [], containers: [] });
  const [expandedRows, setExpandedRows] = useState({});
  const [historyMetrics, setHistoryMetrics] = useState({ host: [], containers: [] });
  const [filterDates, setFilterDates] = useState({ start: "", end: "" });
  const [containerSummary, setContainerSummary] = useState({ running: 0, stopped: 0, total: 0 });
  const [containers, setContainers] = useState([]);
  const [selectedContainer, setSelectedContainer] = useState(null);
  const [timeline, setTimeline] = useState([]);

  // Log filtreleri
  const [logFilters, setLogFilters] = useState({
    user: "", container_name: "", status: "", command_contains: "", unauthorized_only: false,
  });

  useEffect(() => {
    const fetchData = () => {
      fetch(`${API}/api/logs?limit=100`).then(r => r.json()).then(setLogs).catch(console.error);
      fetch(`${API}/api/metrics/live`).then(r => r.json()).then(setLiveMetrics).catch(console.error);
      fetch(`${API}/api/containers/summary`).then(r => r.json()).then(setContainerSummary).catch(console.error);
    };
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchHistoryMetrics = () => {
    let url = `${API}/api/metrics/history`;
    if (filterDates.start && filterDates.end) {
      url += `?start_date=${filterDates.start}&end_date=${filterDates.end}`;
    }
    fetch(url).then(r => r.json()).then(setHistoryMetrics).catch(console.error);
  };

  const fetchFilteredLogs = () => {
    const params = new URLSearchParams();
    if (logFilters.user) params.set("user", logFilters.user);
    if (logFilters.container_name) params.set("container_name", logFilters.container_name);
    if (logFilters.status) params.set("status", logFilters.status);
    if (logFilters.command_contains) params.set("command_contains", logFilters.command_contains);
    if (logFilters.unauthorized_only) params.set("unauthorized_only", "true");
    params.set("limit", "100");
    fetch(`${API}/api/logs?${params.toString()}`).then(r => r.json()).then(setLogs).catch(console.error);
  };

  const fetchContainers = () => {
    fetch(`${API}/api/containers`).then(r => r.json()).then(setContainers).catch(console.error);
  };

  useEffect(() => {
    if (activeTab === "metrics_history") fetchHistoryMetrics();
    if (activeTab === "containers") fetchContainers();
  }, [activeTab]);

  const openTimeline = (containerId, containerName) => {
    setSelectedContainer(containerName);
    fetch(`${API}/api/containers/${containerId}/timeline`).then(r => r.json()).then(setTimeline).catch(console.error);
  };

  const toggleRow = (id) => setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }));

  const getChartData = () => {
    const counts = {};
    logs.forEach(log => {
      let cmdName = log.command && log.command.trim() !== "" ? log.command : "";
      if (cmdName) {
        const words = cmdName.trim().split(/\s+/);
        cmdName = words.length > 1 ? `${words[0]} ${words[1]}` : words[0];
        counts[cmdName] = (counts[cmdName] || 0) + 1;
      }
    });
    return Object.keys(counts).map(key => ({ name: key, count: counts[key] })).sort((a, b) => b.count - a.count).slice(0, 5);
  };

  const groupByName = (data) => {
    const groups = {};
    data.forEach((item) => {
      if (!groups[item.name]) groups[item.name] = [];
      groups[item.name].push(item);
    });
    return groups;
  };

  const MiniProgressBar = ({ label, percentage, details }) => (
    <div className="group relative flex flex-col gap-1 w-full bg-slate-950 p-2 rounded border border-slate-800/40 cursor-help">
      <div className="flex justify-between text-xs font-mono">
        <span className="text-slate-400">{label}</span>
        <span className="text-cyan-400 font-bold">{percentage}%</span>
      </div>
      <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
        <div className="bg-cyan-500 h-full transition-all duration-500" style={{ width: `${Math.min(percentage, 100)}%` }} />
      </div>
      <div className="absolute bottom-full left-1/2 transform -translate-x-1/2 mb-2 w-48 hidden group-hover:block bg-slate-900 border border-slate-700 p-2 rounded text-[11px] font-mono shadow-xl z-50 text-slate-300">
        <p className="text-cyan-400 font-bold border-b border-slate-800 pb-1 mb-1">{label} Analizi</p>
        {details}
      </div>
    </div>
  );

  const TabButton = ({ id, label }) => (
    <button
      onClick={() => setActiveTab(id)}
      className={`px-4 py-1.5 text-xs font-mono rounded transition-colors ${activeTab === id ? "bg-cyan-500 text-slate-950 font-bold" : "text-slate-400 hover:text-slate-200"}`}
    >
      {label}
    </button>
  );

  const pieData = [
    { name: "Çalışıyor", value: containerSummary.running, color: "#10b981" },
    { name: "Durdu", value: containerSummary.stopped, color: "#f43f5e" },
  ];

  return (
    <div className="p-8 bg-slate-950 min-h-screen text-slate-100 dark">
      <div className="flex justify-between items-center border-b border-slate-800 pb-4 mb-6">
        <div className="flex items-center gap-3">
          <ShieldAlert className="text-cyan-400 w-6 h-6" />
          <h1 className="text-xl font-mono tracking-wider text-slate-200">CONTAINER MONITORING</h1>
        </div>
        <div className="flex gap-2 bg-slate-900 p-1 rounded border border-slate-800">
          <TabButton id="dashboard" label="Dashboard" />
          <TabButton id="logs" label="Loglar" />
          <TabButton id="containers" label="Container'lar" />
          <TabButton id="metrics_history" label="Geçmiş Kaynak Analizi" />
        </div>
      </div>

      {/* ---------------- DASHBOARD ---------------- */}
      {activeTab === "dashboard" && (
        <>
          <Card className="bg-slate-900 border-slate-800 mb-6">
            <CardHeader className="py-3">
              <CardTitle className="text-xs font-mono uppercase text-slate-400 flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400 animate-pulse" /> Anlık Kaynak Kullanımı
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4 pt-1">
              {liveMetrics.hosts.map((h) => (
                <MiniProgressBar
                  key={`host-${h.name}`}
                  label={`🖥️ ${h.name.toUpperCase()}`}
                  percentage={h.cpu}
                  details={<><span>CPU: %{h.cpu}</span><br/><span>RAM: %{h.ram} ({h.ram_mb?.toFixed(0)}MB / {h.ram_total_mb?.toFixed(0)}MB)</span></>}
                />
              ))}
              {liveMetrics.containers.map((c) => (
                <MiniProgressBar
                  key={`container-${c.name}`}
                  label={`📦 ${c.name.toUpperCase()}`}
                  percentage={c.ram}
                  details={<><span>Statü: {c.status}</span><br/><span>CPU: %{c.cpu}</span><br/><span>RAM: {c.ram_mb?.toFixed(1)}MB / {c.ram_total_mb?.toFixed(0)}MB</span></>}
                />
              ))}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
            <Card className="bg-slate-900 border-slate-800 md:col-span-2">
              <CardHeader>
                <CardTitle className="text-slate-200 font-mono text-sm uppercase tracking-wider">Top Aktivite Kaynakları</CardTitle>
              </CardHeader>
              <CardContent className="h-[220px] pl-0">
                <ChartContainer>
                  <BarChart data={getChartData()}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                    <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                    <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                    <Bar dataKey="count" fill="#22d3ee" radius={[4, 4, 0, 0]} maxBarSize={40} />
                    <ChartTooltip />
                  </BarChart>
                </ChartContainer>
              </CardContent>
            </Card>

            <Card className="bg-slate-900 border-slate-800">
              <CardHeader>
                <CardTitle className="text-slate-200 font-mono text-sm uppercase tracking-wider flex items-center gap-2">
                  <Box className="w-4 h-4 text-cyan-400" /> Container Durumu
                </CardTitle>
              </CardHeader>
              <CardContent className="h-[220px] flex items-center justify-center relative">
                <ChartContainer>
                  <PieChart>
                    <Pie data={pieData} dataKey="value" nameKey="name" innerRadius={45} outerRadius={70} paddingAngle={3}>
                      {pieData.map((entry, idx) => <Cell key={idx} fill={entry.color} />)}
                    </Pie>
                    <ChartTooltip />
                  </PieChart>
                </ChartContainer>
                <div className="absolute flex flex-col items-center pointer-events-none">
                  <span className="text-2xl font-bold text-cyan-400 font-mono">{containerSummary.total}</span>
                  <span className="text-[10px] text-slate-500 font-mono">TOPLAM</span>
                </div>
              </CardContent>
              <div className="flex justify-around pb-4 font-mono text-xs">
                <span className="text-emerald-400">🟢 {containerSummary.running} Çalışıyor</span>
                <span className="text-rose-400">🔴 {containerSummary.stopped} Durdu</span>
              </div>
            </Card>
          </div>
        </>
      )}

      {/* ---------------- LOGLAR ---------------- */}
      {activeTab === "logs" && (
        <div className="space-y-4">
          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="flex flex-wrap items-end gap-3 pt-6">
              <input placeholder="Kullanıcı" value={logFilters.user}
                onChange={e => setLogFilters(p => ({ ...p, user: e.target.value }))}
                className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs w-32 font-mono" />
              <input placeholder="Container adı" value={logFilters.container_name}
                onChange={e => setLogFilters(p => ({ ...p, container_name: e.target.value }))}
                className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs w-40 font-mono" />
              <select value={logFilters.status}
                onChange={e => setLogFilters(p => ({ ...p, status: e.target.value }))}
                className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs font-mono">
                <option value="">Tüm Durumlar</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="FAILED">FAILED</option>
              </select>
              <input placeholder="Komutta ara..." value={logFilters.command_contains}
                onChange={e => setLogFilters(p => ({ ...p, command_contains: e.target.value }))}
                className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs w-48 font-mono" />
              <label className="flex items-center gap-2 text-xs font-mono text-slate-400">
                <input type="checkbox" checked={logFilters.unauthorized_only}
                  onChange={e => setLogFilters(p => ({ ...p, unauthorized_only: e.target.checked }))} />
                Sadece Yetkisiz Erişimler
              </label>
              <button onClick={fetchFilteredLogs}
                className="bg-cyan-500 text-slate-950 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-cyan-400 transition-colors">
                Filtrele
              </button>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800 overflow-hidden">
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-slate-950">
                  <TableRow className="border-slate-800">
                    <TableHead className="w-[40px]"></TableHead>
                    <TableHead className="text-slate-400">ID</TableHead>
                    <TableHead className="text-slate-400">Zaman</TableHead>
                    <TableHead className="text-slate-400">User</TableHead>
                    <TableHead className="text-slate-400">Komut</TableHead>
                    <TableHead className="text-slate-400">Container</TableHead>
                    <TableHead className="text-slate-400">Durum</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {logs.map((log) => (
                    <React.Fragment key={log.id}>
                      <TableRow
                        onClick={() => toggleRow(log.id)}
                        className={`border-slate-800/60 hover:bg-slate-800/30 transition-colors cursor-pointer ${log.unauthorized ? "bg-rose-500/5" : ""}`}
                      >
                        <TableCell className="text-slate-500">
                          {expandedRows[log.id] ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </TableCell>
                        <TableCell className="text-slate-300 font-mono text-xs">{log.id}</TableCell>
                        <TableCell className="text-slate-300 font-mono text-xs">{log.timestamp}</TableCell>
                        <TableCell className="font-mono text-slate-300">👤 {log.user}</TableCell>
                        <TableCell className="font-mono text-cyan-400 text-xs max-w-[240px] truncate">{log.command}</TableCell>
                        <TableCell>
                          {log.container_name ? (
                            <Badge variant="outline" className="border-cyan-500/30 text-cyan-400 font-mono text-xs">
                              📦 {log.container_name}
                            </Badge>
                          ) : <span className="text-slate-600 text-xs">—</span>}
                        </TableCell>
                        <TableCell className="flex items-center gap-2">
                          <Badge className={log.status === "SUCCESS" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border-rose-500/20"}>
                            {log.status}
                          </Badge>
                          {log.unauthorized && (
                            <Badge className="bg-rose-500/20 text-rose-300 border-rose-500/40 flex items-center gap-1">
                              <AlertTriangle className="w-3 h-3" /> Yetkisiz
                            </Badge>
                          )}
                        </TableCell>
                      </TableRow>
                      {expandedRows[log.id] && (
                        <TableRow className="bg-slate-950/60 hover:bg-slate-950/60 border-b border-slate-800">
                          <TableCell colSpan={7} className="p-4 font-mono text-xs text-slate-300">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-900/40 p-4 rounded border border-slate-800">
                              <div>
                                <p className="text-slate-500 font-bold uppercase mb-2 text-[10px] tracking-wider">Süreç Detayları</p>
                                <p><span className="text-slate-500">Syscall:</span> <span className="text-cyan-400">{log.syscall}</span></p>
                                <p className="mt-1"><span className="text-slate-500">PID:</span> <span className="text-slate-200">{log.pid}</span></p>
                                <p className="mt-1"><span className="text-slate-500">Executable:</span> <span className="text-slate-400 break-all">{log.executable}</span></p>
                                <p className="mt-1"><span className="text-slate-500">Container ID:</span> <span className="text-slate-200">{log.container_id || "—"}</span></p>
                              </div>
                              <div>
                                <p className="text-slate-500 font-bold uppercase mb-2 text-[10px] tracking-wider">Full Command</p>
                                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-cyan-400 break-all whitespace-pre-wrap font-bold">
                                  {log.command || "[Parametre Yok]"}
                                </div>
                              </div>
                            </div>
                          </TableCell>
                        </TableRow>
                      )}
                    </React.Fragment>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      )}

      {/* ---------------- CONTAINER'LAR ---------------- */}
      {activeTab === "containers" && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="bg-slate-900 border-slate-800 lg:col-span-2 overflow-hidden">
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-slate-950">
                  <TableRow className="border-slate-800">
                    <TableHead className="text-slate-400">Container</TableHead>
                    <TableHead className="text-slate-400">Sunucu</TableHead>
                    <TableHead className="text-slate-400">Sahip</TableHead>
                    <TableHead className="text-slate-400">İmaj</TableHead>
                    <TableHead className="text-slate-400">Durum</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {containers.map((c) => (
                    <TableRow
                      key={c.container_id}
                      onClick={() => openTimeline(c.container_id, c.container_name)}
                      className="border-slate-800/60 hover:bg-slate-800/30 transition-colors cursor-pointer"
                    >
                      <TableCell className="font-mono text-cyan-400 text-xs">📦 {c.container_name}</TableCell>
                      <TableCell className="font-mono text-slate-400 text-xs">{c.server_name}</TableCell>
                      <TableCell className="font-mono text-slate-300 text-xs">👤 {c.owner || "—"}</TableCell>
                      <TableCell className="font-mono text-slate-500 text-xs">{c.image}</TableCell>
                      <TableCell>
                        <Badge className={c.status === "running" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-rose-500/10 text-rose-400 border-rose-500/20"}>
                          {c.status === "running" ? "🟢 Çalışıyor" : "🔴 Durdu"}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card className="bg-slate-900 border-slate-800">
            <CardHeader>
              <CardTitle className="text-sm font-mono text-slate-200">
                {selectedContainer ? `📦 ${selectedContainer} Yaşam Döngüsü` : "Bir container seçin"}
              </CardTitle>
            </CardHeader>
            <CardContent className="max-h-[500px] overflow-y-auto space-y-2">
              {timeline.map((t, idx) => (
                <div key={idx} className={`p-2 rounded border text-xs font-mono ${t.type === "docker_event" ? "border-purple-500/30 bg-purple-500/5" : "border-slate-800 bg-slate-950"} ${t.unauthorized ? "border-rose-500/50 bg-rose-500/10" : ""}`}>
                  <div className="flex justify-between text-slate-500">
                    <span>{t.type === "docker_event" ? "🔧 Event" : `👤 ${t.user}`}</span>
                    <span>{t.timestamp}</span>
                  </div>
                  <div className="text-slate-300 mt-1">{t.detail}</div>
                  {t.unauthorized && <div className="text-rose-400 mt-1">⚠️ Yetkisiz erişim</div>}
                </div>
              ))}
              {timeline.length === 0 && <p className="text-slate-600 text-xs">Zaman çizelgesi boş.</p>}
            </CardContent>
          </Card>
        </div>
      )}

      {/* ---------------- GEÇMİŞ KAYNAK ANALİZİ ---------------- */}
      {activeTab === "metrics_history" && (
        <div className="space-y-6">
          <Card className="bg-slate-900 border-slate-800">
            <CardContent className="flex flex-wrap items-end gap-4 pt-6">
              <div className="flex flex-col gap-1.5 text-xs font-mono">
                <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Başlangıç</span>
                <input type="text" placeholder="YYYY-MM-DD HH:MM:SS" value={filterDates.start}
                  onChange={(e) => setFilterDates(p => ({ ...p, start: e.target.value }))}
                  className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs w-52 font-mono" />
              </div>
              <div className="flex flex-col gap-1.5 text-xs font-mono">
                <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Bitiş</span>
                <input type="text" placeholder="YYYY-MM-DD HH:MM:SS" value={filterDates.end}
                  onChange={(e) => setFilterDates(p => ({ ...p, end: e.target.value }))}
                  className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 text-xs w-52 font-mono" />
              </div>
              <button onClick={fetchHistoryMetrics}
                className="bg-cyan-500 text-slate-950 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-cyan-400 transition-colors">
                Metrikleri Filtrele
              </button>
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {Object.entries(groupByName(historyMetrics.host)).map(([serverName, data]) => (
              <Card key={`host-chart-${serverName}`} className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-sm font-mono text-slate-200 flex items-center gap-2">
                    <Database className="w-4 h-4 text-cyan-400" /> {serverName.toUpperCase()}
                  </CardTitle>
                </CardHeader>
                <CardContent className="h-[260px] pl-0">
                  <ChartContainer>
                    <LineChart data={data.slice().reverse()}>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" hide />
                      <YAxis stroke="#64748b" fontSize={10} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                        formatter={(value, name) => name.includes("MB") ? [`${value} MB`, name] : [`${value}%`, name]} />
                      <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
                      <Line type="monotone" dataKey="cpu_usage" name="CPU (%)" stroke="#22d3ee" strokeWidth={2} dot={false} />
                      <Line type="monotone" dataKey="ram_usage_mb" name="RAM (MB)" stroke="#a78bfa" strokeWidth={2} dot={false} />
                    </LineChart>
                  </ChartContainer>
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {Object.entries(groupByName(historyMetrics.containers)).map(([containerName, data]) => (
              <Card key={`container-chart-${containerName}`} className="bg-slate-900 border-slate-800">
                <CardHeader>
                  <CardTitle className="text-sm font-mono text-slate-200 flex items-center gap-2">
                    📦 {containerName.toUpperCase()}
                  </CardTitle>
                </CardHeader>
                <CardContent className="h-[260px] pl-0">
                  <ChartContainer>
                    <LineChart data={data.slice().reverse()}>
                      <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                      <XAxis dataKey="timestamp" hide />
                      <YAxis stroke="#64748b" fontSize={10} />
                      <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
                        formatter={(value, name) => name.includes("MB") ? [`${value} MB`, name] : [`${value}%`, name]} />
                      <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
                      <Line type="monotone" dataKey="cpu_usage" name="CPU (%)" stroke="#f59e0b" strokeWidth={1.5} dot={false} />
                      <Line type="monotone" dataKey="ram_usage_mb" name="RAM (MB)" stroke="#ec4899" strokeWidth={1.5} dot={false} />
                    </LineChart>
                  </ChartContainer>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
