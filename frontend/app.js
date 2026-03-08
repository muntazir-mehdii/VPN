const { useState, useEffect, useRef } = React;

// --- Components ---

function StatCard({ title, value, unit, icon, color }) {
    return (
        <div className={`p-4 bg-gray-900/50 border border-gray-800 rounded-xl flex items-center gap-4`}>
            <div className={`p-3 rounded-lg bg-${color}-500/10 text-${color}-400`}>
                <i className={`ph ${icon} text-xl`}></i>
            </div>
            <div>
                <div className="text-xs text-gray-500 uppercase tracking-wider">{title}</div>
                <div className="text-2xl font-bold font-mono text-white">
                    {value} <span className="text-sm text-gray-600">{unit}</span>
                </div>
            </div>
        </div>
    );
}

function WorldMap({ isRunning }) {
    const mapRef = useRef(null);
    const mapInstance = useRef(null);

    useEffect(() => {
        if (!mapInstance.current) {
            mapInstance.current = L.map(mapRef.current, {
                zoomControl: false,
                attributionControl: false
            }).setView([20, 0], 2);

            L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                subdomains: 'abcd',
                maxZoom: 19
            }).addTo(mapInstance.current);
        }

        // Fix rendering issues on re-render/resize
        setTimeout(() => mapInstance.current?.invalidateSize(), 100);

        // Clear layers
        mapInstance.current.eachLayer((layer) => {
            if (layer instanceof L.Polyline || layer instanceof L.Marker) {
                mapInstance.current.removeLayer(layer);
            }
        });

        if (isRunning) {
            // 1. Main Tunnel (NY -> Frankfurt -> Tokyo)
            const tunnelRoute = [
                [40.7128, -74.0060], // NY
                [50.1109, 8.6821],   // Frankfurt
                [35.6762, 139.6503]  // Tokyo
            ];

            const polyline = L.polyline(tunnelRoute, {
                color: '#00ffcc',
                weight: 3,
                opacity: 0.8,
                dashArray: '5, 10',
                lineCap: 'round'
            }).addTo(mapInstance.current);

            // 2. Simulated Global Clients (Random dots)
            const randomClients = [
                [51.5074, -0.1278], // London
                [48.8566, 2.3522],  // Paris
                [-33.8688, 151.2093], // Sydney
                [1.3521, 103.8198], // Singapore
                [55.7558, 37.6173], // Moscow
                [-23.5505, -46.6333] // Sao Paulo
            ];

            // Add randomized active clients
            randomClients.forEach(coord => {
                if (Math.random() > 0.3) {
                    L.circleMarker(coord, {
                        radius: 3,
                        fillColor: '#0ea5e9', // Sky Blue
                        color: '#fff',
                        weight: 1,
                        opacity: 0.6,
                        fillOpacity: 0.6
                    }).addTo(mapInstance.current);
                }
            });

            // Tunnel Nodes
            tunnelRoute.forEach(coord => {
                L.circleMarker(coord, {
                    radius: 5,
                    fillColor: '#00ffcc',
                    color: '#fff',
                    weight: 2,
                    opacity: 1,
                    fillOpacity: 1
                }).addTo(mapInstance.current);
            });

            mapInstance.current.fitBounds(polyline.getBounds(), { padding: [50, 50] });
        }
    }, [isRunning]);

    return <div ref={mapRef} className="w-full h-64 bg-gray-900 rounded-xl overflow-hidden border border-gray-800" />;
}

function Terminal({ logs, latestPacket }) {
    const endRef = useRef(null);
    useEffect(() => endRef.current?.scrollIntoView({ behavior: "smooth" }), [logs, latestPacket]);

    return (
        <div className="bg-black border border-gray-800 rounded-xl p-4 font-mono text-xs h-64 flex flex-col relative overflow-hidden">
            <div className="absolute top-0 right-0 p-2 text-gray-600">LIVE PACKET CAPTURE</div>
            <div className="flex-1 overflow-y-auto space-y-1 z-10 scrollbar-hide">
                {logs.map((log, i) => (
                    <div key={i} className={`${log.type === 'THREAT' ? 'text-red-500 bg-red-900/10' : 'text-gray-400'}`}>
                        <span className="opacity-50">[{log.time}]</span> {log.msg}
                    </div>
                ))}

                {latestPacket && (
                    <div className="text-green-500 animate-pulse">
                        &gt; {latestPacket}
                    </div>
                )}
                <div ref={endRef} />
            </div>

            {/* Scanline Effect */}
            <div className="scan-line pointer-events-none"></div>
        </div>
    );
}

function ThreatRadar({ count, threats }) {
    return (
        <div className="bg-gray-900/50 border border-gray-800 rounded-xl p-6 relative overflow-hidden">
            <div className="flex justify-between items-start mb-4">
                <h3 className="text-gray-400 font-bold uppercase tracking-widest text-xs">Active Threats</h3>
                <div className={`px-2 py-1 rounded text-xs font-bold ${count > 0 ? 'bg-red-500/20 text-red-500 animate-pulse' : 'bg-green-500/20 text-green-500'}`}>
                    {count > 0 ? 'CRITICAL' : 'SECURE'}
                </div>
            </div>

            {threats.length === 0 ? (
                <div className="flex items-center justify-center h-32 text-gray-600 italic">
                    No active threats detected in perimeter.
                </div>
            ) : (
                <div className="space-y-2">
                    {threats.map((t, i) => (
                        <div key={i} className="flex items-center gap-3 p-2 bg-red-500/5 border border-red-500/10 rounded">
                            <i className="ph ph-warning text-red-500"></i>
                            <div>
                                <div className="text-red-400 font-bold text-xs">{t.threat}</div>
                                <div className="text-gray-500 text-[10px]">{t.source_ip}</div>
                            </div>
                        </div>
                    ))}
                </div>
            )}
        </div>
    );
}

// --- Views ---

function LoginView({ onLogin }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });
            if (res.ok) {
                const data = await res.json();
                onLogin(data.role, data.token);
            } else {
                setError("Invalid credentials");
            }
        } catch (err) {
            setError("Connection failed");
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-[#050505]">
            <form onSubmit={handleSubmit} className="bg-gray-900/50 p-8 rounded-2xl border border-gray-800 w-96 space-y-6">
                <div className="text-center">
                    <i className="ph ph-shield-check text-4xl text-cyan-400 mb-2"></i>
                    <h1 className="text-2xl font-bold text-white">SECURE LOGIN</h1>
                    <p className="text-xs text-gray-500">CYBER COMMAND ACCESS CONTROL</p>
                </div>

                {error && <div className="p-3 bg-red-500/10 text-red-500 text-xs rounded border border-red-500/20">{error}</div>}

                <div className="space-y-2">
                    <label className="text-xs text-gray-500">IDENTITY</label>
                    <input type="text" value={username} onChange={e => setUsername(e.target.value)} className="w-full bg-black border border-gray-700 p-3 rounded text-cyan-400 outline-none focus:border-cyan-400 transition-colors" />
                </div>
                <div className="space-y-2">
                    <label className="text-xs text-gray-500">PASSPHRASE</label>
                    <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full bg-black border border-gray-700 p-3 rounded text-cyan-400 outline-none focus:border-cyan-400 transition-colors" />
                </div>

                <button type="submit" className="w-full bg-cyan-500 text-black font-bold py-3 rounded hover:bg-cyan-400 transition-colors">AUTHENTICATE</button>
                <div className="text-center text-[10px] text-gray-600">DEFAULT: admin / admin</div>
            </form>
        </div>
    );
}

function AdminView({ onBack }) {
    const [logs, setLogs] = useState([]);

    useEffect(() => {
        fetch('/api/admin/threats').then(r => r.json()).then(setLogs);
    }, []);

    return (
        <div className="p-8 max-w-6xl mx-auto">
            <header className="flex justify-between items-center mb-8 border-b border-gray-800 pb-6">
                <div>
                    <h1 className="text-2xl font-bold text-white">ADMIN CONSOLE</h1>
                    <p className="text-xs text-gray-500 font-mono">GLOBAL THREAT INTELLIGENCE</p>
                </div>
                <button onClick={onBack} className="px-4 py-2 border border-gray-700 rounded hover:bg-gray-800 text-sm">EXIT CONSOLE</button>
            </header>

            <div className="bg-gray-900/50 rounded-xl overflow-hidden border border-gray-800">
                <table className="w-full text-left text-sm">
                    <thead className="bg-gray-900 text-gray-500 uppercase text-xs">
                        <tr>
                            <th className="p-4">Timestamp</th>
                            <th className="p-4">Threat Type</th>
                            <th className="p-4">Source IP</th>
                            <th className="p-4">Severity</th>
                            <th className="p-4">Action</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                        {logs.map(log => (
                            <tr key={log.id} className="hover:bg-gray-800/50">
                                <td className="p-4 font-mono text-gray-400">{log.timestamp}</td>
                                <td className="p-4 text-white font-bold">{log.threat_type}</td>
                                <td className="p-4 font-mono text-cyan-400">{log.source_ip}</td>
                                <td className="p-4">
                                    <span className={`px-2 py-1 rounded text-xs font-bold ${log.severity === 'CRITICAL' ? 'bg-red-500/20 text-red-500' : 'bg-yellow-500/20 text-yellow-500'}`}>
                                        {log.severity}
                                    </span>
                                </td>
                                <td className="p-4 text-gray-400">{log.action}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function DashboardView({ onLogout, onAdmin }) {
    const [status, setStatus] = useState({
        is_running: false,
        traffic: { in: 0, out: 0 },
        handshake: { status: 'IDLE', message: '' },
        latency: 0,
        algo: 'AES',
        threat_count: 0,
        local_ip: '...',
        proxy_port: 1080,
        public_url: 'Initializing...',
        auth: { user: '...', pass: '...' }
    });

    const [configAlgo, setConfigAlgo] = useState('AES');
    const [logs, setLogs] = useState([]);
    const [threats, setThreats] = useState([]);
    const [latestPkt, setLatestPkt] = useState('');
    const socket = useRef(null);

    const log = (msg, type = 'INFO') => {
        const time = new Date().toLocaleTimeString();
        setLogs(prev => [...prev.slice(-49), { time, msg, type }]);
    };

    useEffect(() => {
        const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
        socket.current = new WebSocket(`${protocol}://${window.location.host}/ws/traffic`);

        socket.current.onopen = () => log("Link Established", "SYS");

        socket.current.onmessage = (e) => {
            const data = JSON.parse(e.data);
            setStatus(prev => ({
                ...prev,
                is_running: data.is_running,
                traffic: { in: data.bytes_in, out: data.bytes_out },
                handshake: { status: data.handshake_status, message: data.handshake_msg },
                latency: data.latency || 0,
                threat_count: data.threats_detected || 0,
                algo: data.algorithm || 'AES',
                local_ip: data.local_ip,
                proxy_port: data.proxy_port,
                public_url: data.public_url || 'Unavailable (Check Ngrok)',
                auth: { user: data.proxy_user, pass: data.proxy_pass }
            }));

            if (data.latest_packet) {
                setLatestPkt(data.latest_packet);
            }

            // Removed auto-sync to allow user selection
            /*
            if (data.is_running && data.algorithm) {
                setConfigAlgo(data.algorithm);
            }
            */
        };

        return () => socket.current.close();
    }, []);

    useEffect(() => {
        if (status.threat_count > 0) {
            fetch('/threats').then(r => r.json()).then(data => {
                setThreats(data);
            });
        }
    }, [status.threat_count]);

    const toggleVPN = async () => {
        if (status.is_running) {
            await fetch('/stop', { method: 'POST' });
            log("VPN Tunnel Deactivated", "WARN");
        } else {
            await fetch('/config', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ algorithm: configAlgo })
            });
            await fetch('/start', { method: 'POST' });
            log(`Initializing ${configAlgo} Tunnel...`, "SYS");
        }
    };

    const triggerAttack = async () => {
        try {
            await fetch('/api/ids/simulate', { method: 'POST' });
            log("SIMULATE ATTACK COMMAND SENT", "CRITICAL");
        } catch (e) {
            log("Attack Simulation Trigger Failed", "ERR");
        }
    };

    return (
        <div className="min-h-screen bg-[#050505] text-[#00ffcc] p-6 cyber-border m-4 rounded-3xl">
            <header className="flex justify-between items-center mb-8 border-b border-gray-800 pb-6">
                <div className="flex items-center gap-4">
                    <div className="w-12 h-12 bg-gray-900 rounded-full flex items-center justify-center border border-gray-700">
                        <i className="ph ph-shield-check text-2xl text-cyan-400"></i>
                    </div>
                    <div>
                        <h1 className="text-2xl font-bold tracking-tighter text-white">CYBER<span className="text-cyan-400">COMMAND</span></h1>
                        <p className="text-xs text-gray-500 font-mono tracking-widest">SECURE OPERATIONS CENTER</p>
                    </div>
                </div>

                <div className="flex gap-2 items-center">
                    <button onClick={onAdmin} className="text-gray-500 hover:text-white text-xs mr-4 uppercase font-bold tracking-widest">Admin Console</button>
                    <button onClick={onLogout} className="text-gray-500 hover:text-red-400 text-xs mr-4 uppercase font-bold tracking-widest">Logout</button>

                    <div className={`px-3 py-1 rounded bg-gray-900 border ${status.is_running ? 'border-green-500 text-green-500' : 'border-red-500 text-red-500'} text-xs font-mono flex items-center gap-2`}>
                        <div className={`w-2 h-2 rounded-full ${status.is_running ? 'bg-green-500 animate-pulse' : 'bg-red-500'}`}></div>
                        {status.is_running ? 'SYSTEM ONLINE' : 'SYSTEM OFFLINE'}
                    </div>
                </div>
            </header>

            <div className="grid grid-cols-12 gap-6">
                <div className="col-span-12 lg:col-span-4 space-y-6">
                    <div className="space-y-4 bg-gray-900/30 p-6 rounded-2xl border border-gray-800">
                        <label className="text-xs text-gray-500 uppercase font-bold">Encryption Protocol</label>
                        <select
                            value={configAlgo}
                            onChange={(e) => setConfigAlgo(e.target.value)}
                            className="w-full bg-black border border-gray-700 text-cyan-400 p-3 rounded font-mono focus:border-cyan-400 outline-none"
                        >
                            <option value="AES">AES-256-GCM (Standard)</option>
                            <option value="ChaCha20">ChaCha20-Poly1305 (WireGuard)</option>
                            <option value="3DES">Triple DES (Legacy)</option>
                            <option value="DES">DES (Insecure / Educational)</option>
                        </select>

                        <button
                            onClick={toggleVPN}
                            className={`w-full py-4 rounded font-bold tracking-widest transition-all ${status.is_running ? 'bg-red-500/10 text-red-500 border border-red-500 hover:bg-red-500/20' : 'bg-cyan-500 text-black hover:bg-cyan-400 shadow-[0_0_20px_rgba(6,182,212,0.5)]'}`}
                        >
                            {status.is_running ? 'TERMINATE UPLINK' : 'INITIATE SEQUENCE'}
                        </button>

                        {/* ATTACK BUTTON */}
                        <button
                            onClick={triggerAttack}
                            disabled={!status.is_running}
                            className={`w-full py-2 rounded font-bold tracking-widest transition-all text-xs border ${status.is_running ? 'border-red-600 text-red-500 hover:bg-red-900/50' : 'border-gray-800 text-gray-600 cursor-not-allowed'}`}
                        >
                            <i className="ph ph-skull mr-2"></i>
                            SIMULATE CYBER ATTACK
                        </button>
                    </div>

                    <WorldMap isRunning={status.is_running} />
                    <ThreatRadar count={status.threat_count} threats={threats} />
                </div>

                <div className="col-span-12 lg:col-span-5 space-y-6">
                    <div>
                        <div className="text-xs text-gray-500 mb-2">OPERATIONAL STATUS</div>
                        <div className="grid grid-cols-2 gap-4">
                            <StatCard
                                title="Throughput"
                                value={(status.traffic.in / 1024 / 1024).toFixed(2)}
                                unit="MB"
                                icon="ph-arrows-left-right"
                                color="cyan"
                            />
                            <StatCard
                                title="Latency"
                                value={status.latency}
                                unit="ms"
                                icon="ph-activity"
                                color={status.latency > 100 ? 'yellow' : 'green'}
                            />
                        </div>
                    </div>

                    <div className="bg-gray-900/30 border border-gray-800 p-6 rounded-xl h-64 flex flex-col justify-center items-center text-center relative overflow-hidden">
                        {status.handshake.status === 'CONNECTED' ? (
                            <div className="space-y-4 z-10">
                                <i className="ph ph-lock-key text-6xl text-green-500 animate-pulse"></i>
                                <div>
                                    <div className="text-xl font-bold text-white">TUNNEL SECURE</div>
                                    <div className="text-sm text-gray-500 font-mono mt-1 text-green-400">
                                        {status.algo} // 2048-BIT RSA // SIGNED
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="space-y-4 z-10 opacity-50">
                                <i className="ph ph-globe text-6xl text-gray-700"></i>
                                <div className="text-sm font-mono text-gray-500">
                                    {status.handshake.status !== 'IDLE' ? status.handshake.message : 'WAITING FOR CONNECTION...'}
                                </div>
                            </div>
                        )}
                        <div className="absolute inset-0 bg-[linear-gradient(rgba(0,255,204,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(0,255,204,0.03)_1px,transparent_1px)] bg-[size:20px_20px]"></div>
                    </div>

                    {/* Connection Info Panel */}
                    <div className="bg-gray-900/30 border border-gray-800 p-4 rounded-xl space-y-4">
                        <div className="text-xs text-gray-500 uppercase font-bold border-b border-gray-800 pb-2">Connection Profiles</div>

                        {/* Local */}
                        <div>
                            <div className="text-[10px] text-cyan-500 font-bold mb-1">LOCAL (WI-FI)</div>
                            <div className="flex gap-2">
                                <div className="bg-black/50 px-2 py-1 rounded border border-gray-700 font-mono text-gray-300 text-xs">
                                    Host: <span className="text-cyan-400">{status.local_ip}</span>
                                </div>
                                <div className="bg-black/50 px-2 py-1 rounded border border-gray-700 font-mono text-gray-300 text-xs">
                                    Port: <span className="text-cyan-400">{status.proxy_port}</span>
                                </div>
                            </div>
                        </div>

                        {/* Remote */}
                        <div>
                            <div className="text-[10px] text-pink-500 font-bold mb-1 flex justify-between">
                                <span>REMOTE (WORLD WIDE)</span>
                                <span className="text-gray-600">REQ: Ngrok Auth</span>
                            </div>
                            <div className="bg-pink-500/5 border border-pink-500/20 p-2 rounded">
                                <div className="font-mono text-gray-300 text-xs mb-2">
                                    Host: <span className="text-pink-400">{status.public_url ? status.public_url.replace('tcp://', '') : '...'}</span>
                                </div>
                                <div className="flex gap-2">
                                    <div className="bg-black/50 px-2 py-1 rounded border border-pink-900/50 font-mono text-gray-400 text-[10px]">
                                        User: <span className="text-white">{status.auth && status.auth.user}</span>
                                    </div>
                                    <div className="bg-black/50 px-2 py-1 rounded border border-pink-900/50 font-mono text-gray-400 text-[10px]">
                                        Pass: <span className="text-white">{status.auth && status.auth.pass}</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div className="col-span-12 lg:col-span-3">
                    <Terminal logs={logs} latestPacket={latestPkt} />
                </div>
            </div>
        </div>
    );
}

// --- Main App ---

function App() {
    const [view, setView] = useState('login'); // login | dashboard | admin
    const [token, setToken] = useState(null);
    const [role, setRole] = useState(null);

    const handleLogin = (userRole, userToken) => {
        setToken(userToken);
        setRole(userRole);
        setView('dashboard');
    };

    const handleLogout = () => {
        setToken(null);
        setRole(null);
        setView('login');
    };

    if (view === 'login') {
        return <LoginView onLogin={handleLogin} />;
    }

    if (view === 'admin') {
        return <AdminView onBack={() => setView('dashboard')} />;
    }

    // Dashboard View
    return <DashboardView onLogout={handleLogout} onAdmin={() => setView('admin')} />;
}

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
