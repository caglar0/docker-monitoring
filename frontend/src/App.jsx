import React, { useEffect, useState, useRef } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, LineChart, Line, Tooltip, Legend, PieChart, Pie, Cell } from "recharts";
import { ChartContainer, ChartTooltip } from "./components/ui/chart";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "./components/ui/card";
import { Badge } from "./components/ui/badge";
import { ChevronDown, ChevronUp, Activity, ShieldAlert, Database, Clock, Box, AlertTriangle, List, BarChart2 } from "lucide-react";
import Login from "./Login";

const API = "http://localhost:8000";

export default function App() {
    const [authToken, setAuthToken] = useState(localStorage.getItem("auth_token"));
    const [authUser, setAuthUser] = useState(localStorage.getItem("auth_user"));
    const [activeTab, setActiveTab] = useState("dashboard");
    const [logs, setLogs] = useState([]);
    const [liveMetrics, setLiveMetrics] = useState({ hosts: [], containers: [] });
    const [expandedRows, setExpandedRows] = useState({});
    const [historyMetrics, setHistoryMetrics] = useState({ host: [], containers: [] });
    const [filterDates, setFilterDates] = useState({ start: "", end: "" });
    const [containerSummary, setContainerSummary] = useState({ running: 0, stopped: 0, total: 0 });
    const [containers, setContainers] = useState([]);
    const [selectedContainer, setSelectedContainer] = useState(null);
    const [timeline, setTimeline] = useState([]);
    const [logFilters, setLogFilters] = useState({
	user: "", container_name: "", status: "", command_contains: "", unauthorized_only: false,
    });
    const [userResources, setUserResources] = useState([]);
    const [userResourceView, setUserResourceView] = useState("list"); // list | chart | pie
    const [expandedOwners, setExpandedOwners] = useState({});
    const toggleOwner = (owner) => setExpandedOwners(prev => ({ ...prev, [owner]: !prev[owner] }));
    const [userResourceSubTab, setUserResourceSubTab] = useState("live"); // live | history
    const [userResourceHistory, setUserResourceHistory] = useState([]);
    const [userHistoryFilterDates, setUserHistoryFilterDates] = useState({ start: "", end: "" });
    const [userHistoryView, setUserHistoryView] = useState("list"); // list | chart | pie
    
    const safeSetLogs = (data) => {
	if (Array.isArray(data)) {
	    setLogs(data);
	} else {
	    console.error("Beklenmeyen /api/logs yanıtı:", data);
	    setLogs([]);
	}
    };
    
    const logFiltersRef = useRef(logFilters);
    useEffect(() => {
	logFiltersRef.current = logFilters;
    }, [logFilters]);

    const buildLogQueryParams = (filters) => {
	const params = new URLSearchParams();
	if (filters.user) params.set("user", filters.user);
	if (filters.container_name) params.set("container_name", filters.container_name);
	if (filters.status) params.set("status", filters.status);
	if (filters.command_contains) params.set("command_contains", filters.command_contains);
	if (filters.unauthorized_only) params.set("unauthorized_only", "true");
	params.set("limit", "100");
	return params.toString();
    };
    
    const handleLoginSuccess = (token, username) => {
	setAuthToken(token);
	setAuthUser(username);
    };

    const handleLogout = () => {
	localStorage.removeItem("auth_token");
	localStorage.removeItem("auth_user");
	setAuthToken(null);
	setAuthUser(null);
    };
    
    

    const authFetch = async (url, options = {}) => {
	const res = await fetch(url, {
            ...options,
            headers: {
		...options.headers,
		"Authorization": `Bearer ${authToken}`,
            },
	});
	if (res.status === 401) {
            handleLogout();
            throw new Error("Oturum süresi doldu, lütfen tekrar giriş yapın");
	}
	return res;
    };

    useEffect(() => {
	if (!authToken) return;
	const fetchData = () => {
	    authFetch(`${API}/api/logs?${buildLogQueryParams(logFiltersRef.current)}`)
		.then(r => r.json()).then(safeSetLogs).catch(console.error);
	    authFetch(`${API}/api/metrics/live`).then(r => r.json()).then(setLiveMetrics).catch(console.error);
	    authFetch(`${API}/api/containers/summary`).then(r => r.json()).then(setContainerSummary).catch(console.error);
	};
	fetchData();
	const interval = setInterval(fetchData, 3000);
	return () => clearInterval(interval);
    }, [authToken]);

    
    const fetchHistoryMetrics = () => fetchHistoryMetricsWithDates(filterDates);
    
    const fetchHistoryMetricsWithDates = (dates) => {
	let url = `${API}/api/metrics/history`;
	if (dates.start && dates.end) {
	    url += `?start_date=${encodeURIComponent(dates.start)}&end_date=${encodeURIComponent(dates.end)}`;
	}
	authFetch(url).then(r => r.json()).then(setHistoryMetrics).catch(console.error);
    };

    const fetchFilteredLogs = () => {
	authFetch(`${API}/api/logs?${buildLogQueryParams(logFilters)}`)
	    .then(r => r.json()).then(safeSetLogs).catch(console.error);
    };
    
    const fetchContainers = () => {
	authFetch(`${API}/api/containers`).then(r => r.json()).then(setContainers).catch(console.error);
    };

    useEffect(() => {
	if (activeTab === "metrics_history") fetchHistoryMetrics();
	if (activeTab === "containers") fetchContainers();
    }, [activeTab]);

    const openTimeline = (containerId, containerName) => {
	setSelectedContainer(containerName);
	authFetch(`${API}/api/containers/${containerId}/timeline`).then(r => r.json()).then(setTimeline).catch(console.error);
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

    const MiniProgressBar = ({ label, cpu, ram, percentage, details }) => (
	<div className="group relative flex flex-col gap-1 w-full bg-slate-950 p-2 rounded border border-slate-800/40 cursor-help">
	    <div className="flex justify-between text-xs font-mono">
		<span className="text-slate-400">{label}</span>
		<span className="text-cyan-400 font-bold text-[11px]">CPU: {cpu}% · RAM: {ram}%</span>
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

    const fetchUserResources = () => {
	authFetch(`${API}/api/users/resource-usage`).then(r => r.json()).then(setUserResources).catch(console.error);
    };

    const activeTabRef = useRef(activeTab);
    useEffect(() => {
	activeTabRef.current = activeTab;
    }, [activeTab]);
    
    useEffect(() => {
	if (!authToken) return;
	const fetchData = () => {
	    authFetch(`${API}/api/logs?${buildLogQueryParams(logFiltersRef.current)}`)
		.then(r => r.json()).then(safeSetLogs).catch(console.error);
	    authFetch(`${API}/api/metrics/live`).then(r => r.json()).then(setLiveMetrics).catch(console.error);
	    authFetch(`${API}/api/containers/summary`).then(r => r.json()).then(setContainerSummary).catch(console.error);
	    if (activeTabRef.current === "user_resources") {
		fetchUserResources();
	    }
	};
	fetchData();
	const interval = setInterval(fetchData, 3000);
	return () => clearInterval(interval);
    }, [authToken]);

    const UserCpuPieTooltip = ({ active, payload }) => {
	if (!active || !payload || !payload.length) return null;
	const data = payload[0].payload;

	return (
	    <div className="bg-slate-900 border border-slate-700 p-3 rounded text-xs font-mono shadow-xl max-w-xs">
		<p className="text-cyan-400 font-bold border-b border-slate-800 pb-1 mb-2">
		    👤 {data.owner}
		</p>
		<p className="text-slate-300">
		    Toplam CPU: <span className="text-cyan-400">{data.cpu_total}%</span>
		</p>
		<p className="text-slate-500 mt-2 mb-1">Container'lar:</p>
		{data.containers?.map((c) => (
		    <p key={c.name} className="text-slate-400 pl-2">
			📦 {c.name} — CPU: {c.cpu}%
		    </p>
		))}
	    </div>
	);
    };

    const UserRamPieTooltip = ({ active, payload }) => {
        if (!active || !payload || !payload.length) return null;
        const data = payload[0].payload;

        return (
            <div className="bg-slate-900 border border-slate-700 p-3 rounded text-xs font-mono shadow-xl max-w-xs">
                <p className="text-cyan-400 font-bold border-b border-slate-800 pb-1 mb-2">
                    👤 {data.owner}
                </p>
                <p className="text-slate-300">
                    Toplam RAM:{" "}
                    <span className="text-purple-400">
                        {data.ram_percent}% ({data.ram_total_mb} MB)
                    </span>
                </p>
                <p className="text-slate-500 mt-2 mb-1">Container'lar:</p>
                    {data.containers?.map((c) => (
                        <p key={c.name} className="text-slate-400 pl-2">
                            📦 {c.name} — RAM: {c.ram_percent}% ({c.ram_mb}MB)
                        </p>
                    ))}
                    </div>
		    );
		    };

    
    const fetchUserResourceHistory = (dates) => {
	const d = dates || userHistoryFilterDates;
	let url = `${API}/api/users/resource-usage/history`;
	if (d.start && d.end) {
	    url += `?start_date=${encodeURIComponent(d.start)}&end_date=${encodeURIComponent(d.end)}`;
	}
	authFetch(url).then(r => r.json()).then(data => setUserResourceHistory(Array.isArray(data) ? data : [])).catch(console.error);
    };

    const groupByOwner = (data) => {
	const groups = {};
	data.forEach((item) => {
	    if (!groups[item.owner]) groups[item.owner] = [];
	    groups[item.owner].push(item);
	});
	return groups;
    };

    // Liste/Pie görünümü için dönem özeti (ortalama) hesapla
    const getUserHistorySummary = () => {
	const groups = groupByOwner(userResourceHistory);
	return Object.entries(groups).map(([owner, points]) => {
	    const avgCpu = points.reduce((s, p) => s + p.cpu_total, 0) / points.length;
	    const avgRamPercent = points.reduce((s, p) => s + p.ram_percent, 0) / points.length;
	    const avgRamMb = points.reduce((s, p) => s + p.ram_total_mb, 0) / points.length;
	    return {
		owner,
		cpu_total: Math.round(avgCpu * 100) / 100,
		ram_percent: Math.round(avgRamPercent * 10) / 10,
		ram_total_mb: Math.round(avgRamMb * 100) / 100,
		point_count: points.length,
	    };
	}).sort((a, b) => b.cpu_total - a.cpu_total);
    };
    
    if (!authToken) {
	return <Login onLoginSuccess={handleLoginSuccess} />;
    }

    
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
		    <TabButton id="containers" label="Containerlar" />
		    <TabButton id="metrics_history" label="Sunucu/Container Kaynak Kullanımı" />
		    <TabButton id="user_resources" label="Kullanıcı Kaynak Kullanımı" />
		</div>
		<div className="flex items-center gap-3">
		    <span className="text-xs font-mono text-slate-500">👤 {authUser}</span>
		    <button
			onClick={handleLogout}
			className="text-xs font-mono text-slate-400 hover:text-rose-400 transition-colors"
		    >
			Çıkış
		    </button>
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
				    cpu={h.cpu}
				    ram={h.ram}
				    details={<><span>CPU: %{h.cpu}</span><br/><span>RAM: %{h.ram} ({h.ram_mb?.toFixed(0)}MB / {h.ram_total_mb?.toFixed(0)}MB)</span></>}
				/>
			    ))}
			    {liveMetrics.containers.map((c) => (
				<MiniProgressBar
				    key={`container-${c.name}`}
				    label={`📦 ${c.name.toUpperCase()}`}
				    cpu={c.cpu}
				    ram={c.ram}
				    details={<><span>Status: {c.status}</span><br/><span>CPU: %{c.cpu}</span><br/><span>RAM: {c.ram_mb?.toFixed(1)}MB / {c.ram_total_mb?.toFixed(0)}MB</span></>}
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
								<p className="mt-1"><span className="text-slate-500">Container Sahibi:</span> <span className="text-slate-200">{log.container_owner && log.container_owner !== "unknown" ? `👤 ${log.container_owner}` : "—"}</span></p>
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
				{selectedContainer ? `📦 ${selectedContainer}` : "Bir container seçin."}
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
			<CardContent className="flex flex-col gap-4 pt-6">
			    <div className="flex flex-wrap gap-2">
				{[
				    { label: "Son 1 Gün", days: 1 },
				    { label: "Son 1 Hafta", days: 7 },
				    { label: "Son 1 Ay", days: 30 },
				    { label: "Son 3 Ay", days: 90 },
				    { label: "Son 6 Ay", days: 180 },
				    { label: "Son 1 Yıl", days: 365 },
				].map((preset) => (
				    <button
					key={preset.label}
					onClick={() => {
					    const end = new Date();
					    const start = new Date();
					    start.setDate(start.getDate() - preset.days);
					    const fmt = (d) => d.toISOString().slice(0, 19).replace("T", " ");
					    const newDates = { start: fmt(start), end: fmt(end) };
					    setFilterDates(newDates);
					    fetchHistoryMetricsWithDates(newDates);
					}}
					className="px-3 py-1.5 text-xs font-mono rounded bg-slate-950 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/50 border border-slate-800 transition-colors"
				    >
					{preset.label}
				    </button>
				))}
			    </div>

			    <div className="flex flex-wrap items-end gap-4">
				<div className="flex flex-col gap-1.5 text-xs font-mono">
				    <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Başlangıç Tarihi</span>
				    <input
					type="date"
					onChange={(e) => setFilterDates(p => ({ ...p, start: e.target.value ? `${e.target.value} 00:00:00` : "" }))}
					className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 focus:outline-none focus:border-cyan-500 text-xs font-mono"
				    />
				</div>
				<div className="flex flex-col gap-1.5 text-xs font-mono">
				    <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Bitiş Tarihi</span>
				    <input
					type="date"
					onChange={(e) => setFilterDates(p => ({ ...p, end: e.target.value ? `${e.target.value} 23:59:59` : "" }))}
					className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 focus:outline-none focus:border-cyan-500 text-xs font-mono"
				    />
				</div>
				<button onClick={fetchHistoryMetrics}
					className="bg-cyan-500 text-slate-950 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-cyan-400 transition-colors">
				    Metrikleri Filtrele
				</button>
				<button
				    onClick={() => {
					const cleared = { start: "", end: "" };
					setFilterDates(cleared);
					fetchHistoryMetricsWithDates(cleared);
				    }}
				    className="bg-slate-800 text-slate-300 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-slate-700 transition-colors"
				>
				    Filtreyi Sıfırla
				</button>
				{filterDates.start && (
				    <span className="text-[10px] font-mono text-slate-500">
					Seçili: {filterDates.start} → {filterDates.end}
				    </span>
				)}
			    </div>
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
					    <YAxis stroke="#64748b" fontSize={10} domain={[0,100]} />
					    <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
						     formatter={(value, name, props) => {
							 if (name === "RAM (%)") {
							     const mb = props.payload.ram_usage_mb;
							     return [`${value}%${mb != null ? ` (${mb.toFixed(1)} MB)` : ""}`, name];
							 }
							 return [`${value}%`, name];
						     }}
					    />
					    <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
					    <Line type="monotone" dataKey="cpu_usage" name="CPU (%)" stroke="#22d3ee" strokeWidth={2} dot={false} />
					    <Line type="monotone" dataKey="ram_usage" name="RAM (%)" stroke="#a78bfa" strokeWidth={2} dot={false} />
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
					    <YAxis stroke="#64748b" fontSize={10} domain={[0, 100]} />
					    <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
						     formatter={(value, name, props) => {
                                                         if (name === "RAM (%)") {
                                                             const mb = props.payload.ram_usage_mb;
                                                             return [`${value}%${mb != null ? ` (${mb.toFixed(1)} MB)` : ""}`, name];
                                                         }
                                                         return [`${value}%`, name];
                                                     }}
                                            />
					    <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
					    <Line type="monotone" dataKey="cpu_usage" name="CPU (%)" stroke="#f59e0b" strokeWidth={1.5} dot={false} />
					    <Line type="monotone" dataKey="ram_usage" name="RAM (%)" stroke="#ec4899" strokeWidth={1.5} dot={false} />
					</LineChart>
				    </ChartContainer>
				</CardContent>
			    </Card>
			))}
		    </div>
		</div>
	    )}
	{/*-----------KULLANICI BAZLI KAYNAK KULLANIMI--------------------*/}   
	    {activeTab === "user_resources" && (
		<div className="space-y-4">
		    <div className="flex gap-2 bg-slate-900 p-1 rounded border border-slate-800 w-fit">
			<button
			    onClick={() => setUserResourceSubTab("live")}
			    className={`px-4 py-1.5 text-xs font-mono rounded transition-colors ${userResourceSubTab === "live" ? "bg-cyan-500 text-slate-950 font-bold" : "text-slate-400 hover:text-slate-200"}`}
			>
			    Anlık
			</button>
			<button
			    onClick={() => {
				setUserResourceSubTab("history");
				fetchUserResourceHistory();
			    }}
			    className={`px-4 py-1.5 text-xs font-mono rounded transition-colors ${userResourceSubTab === "history" ? "bg-cyan-500 text-slate-950 font-bold" : "text-slate-400 hover:text-slate-200"}`}
			>
			    Geçmiş
			</button>
		    </div>

		    {userResourceSubTab === "live" && (
			<>
			    <Card className="bg-slate-900 border-slate-800">
				<CardContent className="flex items-center gap-2 pt-6">
				    <span className="text-xs font-mono text-slate-400 mr-2">Görünüm:</span>
				    {[
					{ id: "list", label: "Liste" },
					{ id: "chart", label: "Grafik" },
					{ id: "pie", label: "Pie Chart" },
				    ].map((v) => (
					<button
					    key={v.id}
					    onClick={() => setUserResourceView(v.id)}
					    className={`px-3 py-1.5 text-xs font-mono rounded transition-colors ${userResourceView === v.id ? "bg-cyan-500 text-slate-950 font-bold" : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"}`}
					>
					    {v.label}
					</button>
				    ))}
				</CardContent>
			    </Card>

			    {userResourceView === "list" && (
				<Card className="bg-slate-900 border-slate-800 overflow-hidden">
				    <CardContent className="p-0">
					<Table>
					    <TableHeader className="bg-slate-950">
						<TableRow className="border-slate-800">
						    <TableHead className="w-[30px]"></TableHead>
						    <TableHead className="text-slate-400">Kullanıcı</TableHead>
						    <TableHead className="text-slate-400">Container Sayısı</TableHead>
						    <TableHead className="text-slate-400">Toplam CPU Kullanımı (%)</TableHead>
						    <TableHead className="text-slate-400">Toplam RAM Kullanımı (%)</TableHead>
						</TableRow>
					    </TableHeader>
					    <TableBody>
						{userResources.map((u) => (
						    <React.Fragment key={u.owner}>
							<TableRow
							    onClick={() => toggleOwner(u.owner)}
							    className="border-slate-800/60 hover:bg-slate-800/30 transition-colors cursor-pointer"
							>
							    <TableCell className="text-slate-500">
								{expandedOwners[u.owner] ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
							    </TableCell>
							    <TableCell className="font-mono text-slate-300">👤 {u.owner}</TableCell>
							    <TableCell className="font-mono text-slate-400 text-xs">{u.container_count}</TableCell>
							    <TableCell className="font-mono text-cyan-400 text-xs">{u.cpu_total}%</TableCell>
							    <TableCell className="font-mono text-purple-400 text-xs">
								{u.ram_percent}% <span className="text-slate-500">({u.ram_total_mb} MB)</span>
							    </TableCell>
							</TableRow>
							{expandedOwners[u.owner] && (
							    <TableRow className="bg-slate-950/60 border-b border-slate-800">
								<TableCell colSpan={5} className="p-4">
								    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
									{u.containers.map((c) => (
									    <div key={c.name} className="bg-slate-900/60 border border-slate-800 rounded p-2 text-xs font-mono">
										<p className="text-cyan-400">📦 {c.name}</p>
										<p className="text-slate-400 mt-1">
										    CPU: {c.cpu}% · RAM: {c.ram_percent}% <span className="text-slate-600">({c.ram_mb} MB)</span>
										</p>
									    </div>
									))}
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
			    )}

			    {userResourceView === "chart" && (
				<Card className="bg-slate-900 border-slate-800">
				    <CardContent className="h-[400px] pt-6">
					<ChartContainer>
					    <BarChart data={userResources}>
						<CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
						<XAxis dataKey="owner" stroke="#64748b" fontSize={11} />
						<YAxis stroke="#64748b" fontSize={11} domain={[0,100]}/>
						<Tooltip
						    cursor={false}
						    contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }}
						    formatter={(value, name, props) => {
							if (name === "RAM (%)") {
							    return [`${value}% (${props.payload.ram_total_mb} MB)`, name];
							}
							return [`${value}%`, name];
						    }}
						/>
						<Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
						<Bar dataKey="cpu_total" name="CPU (%)" fill="#22d3ee" radius={[4, 4, 0, 0]} />
						<Bar dataKey="ram_percent" name="RAM (%)" fill="#a78bfa" radius={[4, 4, 0, 0]} />
					    </BarChart>
					</ChartContainer>
				    </CardContent>
				</Card>
			    )}

			    {userResourceView === "pie" && (
				<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
				    <Card className="bg-slate-900 border-slate-800">
					<CardHeader><CardTitle className="text-sm font-mono text-slate-200">CPU Dağılımı</CardTitle></CardHeader>
					<CardContent className="h-[340px]">
					    <ChartContainer>
						<PieChart>
						    <Pie data={userResources} dataKey="cpu_total" nameKey="owner" outerRadius={90} label>
							{userResources.map((_, idx) => (
							    <Cell key={idx} fill={["#22d3ee", "#a78bfa", "#f59e0b", "#ec4899", "#10b981"][idx % 5]} />
							))}
						    </Pie>
						    <Tooltip content={<UserCpuPieTooltip />} cursor={false} />
						    <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
						</PieChart>
					    </ChartContainer>
					</CardContent>
				    </Card>
				    <Card className="bg-slate-900 border-slate-800">
					<CardHeader><CardTitle className="text-sm font-mono text-slate-200">RAM Dağılımı</CardTitle></CardHeader>
					<CardContent className="h-[340px]">
					    <ChartContainer>
						<PieChart>
						    <Pie data={userResources} dataKey="ram_percent" nameKey="owner" outerRadius={90} label>
							{userResources.map((_, idx) => (
							    <Cell key={idx} fill={["#a78bfa", "#22d3ee", "#f59e0b", "#ec4899", "#10b981"][idx % 5]} />
							))}
						    </Pie>
						    <Tooltip content={<UserRamPieTooltip />} cursor={false} />
						    <Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
						</PieChart>
					    </ChartContainer>
					</CardContent>
				    </Card>
				</div>
			    )}
			</>
		    )}

		    {userResourceSubTab === "history" && (
			<>
			    {/* Tarih filtresi + presetler (container history sayfasındakiyle aynı yapı) */}
			    <Card className="bg-slate-900 border-slate-800">
				<CardContent className="flex flex-col gap-4 pt-6">
				    <div className="flex flex-wrap gap-2">
					{[
					    { label: "Son 1 Gün", days: 1 },
					    { label: "Son 1 Hafta", days: 7 },
					    { label: "Son 1 Ay", days: 30 },
					    { label: "Son 3 Ay", days: 90 },
					    { label: "Son 6 Ay", days: 180 },
					    { label: "Son 1 Yıl", days: 365 },
					].map((preset) => (
					    <button
						key={preset.label}
						onClick={() => {
						    const end = new Date();
						    const start = new Date();
						    start.setDate(start.getDate() - preset.days);
						    const fmt = (d) => d.toISOString().slice(0, 19).replace("T", " ");
						    const newDates = { start: fmt(start), end: fmt(end) };
						    setUserHistoryFilterDates(newDates);
						    fetchUserResourceHistory(newDates);
						}}
						className="px-3 py-1.5 text-xs font-mono rounded bg-slate-950 text-slate-400 hover:text-cyan-400 hover:border-cyan-500/50 border border-slate-800 transition-colors"
					    >
						{preset.label}
					    </button>
					))}
				    </div>
				    <div className="flex flex-wrap items-end gap-4">
					<div className="flex flex-col gap-1.5 text-xs font-mono">
					    <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Başlangıç Tarihi</span>
					    <input
						type="date"
						onChange={(e) => setUserHistoryFilterDates(p => ({ ...p, start: e.target.value ? `${e.target.value} 00:00:00` : "" }))}
						className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 focus:outline-none focus:border-cyan-500 text-xs font-mono"
					    />
					</div>
					<div className="flex flex-col gap-1.5 text-xs font-mono">
					    <span className="text-slate-400 flex items-center gap-1"><Clock className="w-3.5 h-3.5" /> Bitiş Tarihi</span>
					    <input
						type="date"
						onChange={(e) => setUserHistoryFilterDates(p => ({ ...p, end: e.target.value ? `${e.target.value} 23:59:59` : "" }))}
						className="bg-slate-950 border border-slate-800 px-3 py-1.5 rounded text-slate-200 focus:outline-none focus:border-cyan-500 text-xs font-mono"
					    />
					</div>
					<button onClick={() => fetchUserResourceHistory()}
						className="bg-cyan-500 text-slate-950 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-cyan-400 transition-colors">
					    Filtrele
					</button>
					<button
					    onClick={() => {
						const cleared = { start: "", end: "" };
						setUserHistoryFilterDates(cleared);
						fetchUserResourceHistory(cleared);
					    }}
					    className="bg-slate-800 text-slate-300 text-xs font-mono font-bold px-5 py-2 rounded hover:bg-slate-700 transition-colors"
					>
					    Filtreyi Sıfırla
					</button>
				    </div>
				</CardContent>
			    </Card>

			    {/* Görünüm seçici */}
			    <Card className="bg-slate-900 border-slate-800">
				<CardContent className="flex items-center gap-2 pt-6">
				    <span className="text-xs font-mono text-slate-400 mr-2">Görünüm:</span>
				    {[
					{ id: "chart", label: "Grafik" },
					
				    ].map((v) => (
					<button
					    key={v.id}
					    onClick={() => setUserHistoryView(v.id)}
					    className={`px-3 py-1.5 text-xs font-mono rounded transition-colors ${userHistoryView === v.id ? "bg-cyan-500 text-slate-950 font-bold" : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"}`}
					>
					    {v.label}
					</button>
				    ))}
				</CardContent>
			    </Card>

			    {userHistoryView === "chart" && (
				<div className="grid grid-cols-1 md:grid-cols-2 gap-6">
				    {Object.entries(groupByOwner(userResourceHistory)).map(([owner, points]) => (
					<Card key={`user-history-${owner}`} className="bg-slate-900 border-slate-800">
					    <CardHeader>
						<CardTitle className="text-sm font-mono text-slate-200">👤 {owner}</CardTitle>
					    </CardHeader>
					    <CardContent className="h-[260px] pl-0">
						<ChartContainer>
						    <LineChart data={points}>
							<CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
							<XAxis dataKey="timestamp" hide />
							<YAxis stroke="#64748b" fontSize={10} domain={[0, 100]} />
							<Tooltip cursor={false} contentStyle={{ backgroundColor: "#0f172a", borderColor: "#1e293b" }} />
							<Legend wrapperStyle={{ fontSize: 11, fontFamily: "monospace" }} />
							<Line type="monotone" dataKey="cpu_total" name="CPU (%)" stroke="#22d3ee" strokeWidth={2} dot={false} />
							<Line type="monotone" dataKey="ram_percent" name="RAM (%)" stroke="#a78bfa" strokeWidth={2} dot={false} />
						    </LineChart>
						</ChartContainer>
					    </CardContent>
					</Card>
				    ))}
				</div>
			    )}

			</>
		    )}
		</div>
	    )}
	</div>
    );
}

