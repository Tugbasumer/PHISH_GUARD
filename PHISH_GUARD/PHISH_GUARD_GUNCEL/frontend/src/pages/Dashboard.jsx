import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

export default function Dashboard() {
    const [activeTab, setActiveTab] = useState('email');
    const [text, setText] = useState('');
    const [url, setUrl] = useState('');
    const [result, setResult] = useState(null);
    const [stats, setStats] = useState(null);
    const [history, setHistory] = useState([]);
    const navigate = useNavigate();
    const username = localStorage.getItem('username');

    const handleLogout = () => {
        localStorage.removeItem('token');
        localStorage.removeItem('username');
        navigate('/login');
    };

    const fetchStats = async () => {
        try {
            const res = await axios.get('http://127.0.0.1:8000/get-stats');
            setStats(res.data.summary);
            setHistory(res.data.recent_scans);
        } catch (err) {
            console.error("Failed to fetch stats");
        }
    };

    // Fetch stats on mount
    React.useEffect(() => {
        fetchStats();
    }, []);

    const analyzeContent = async () => {
        try {
            let res;
            if (activeTab === 'email') {
                res = await axios.post('http://127.0.0.1:8000/analyze', { text });
            } else {
                res = await axios.post('http://127.0.0.1:8000/analyze-url', { url });
            }
            setResult(res.data);
            fetchStats(); // Update history immediately
        } catch (err) {
            alert("Analysis failed. Ensure backend is running.");
        }
    };

    const getScoreColor = (score) => {
        if (score > 70) return 'text-red-500 border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.6)]';
        if (score > 30) return 'text-yellow-400 border-yellow-400 shadow-[0_0_15px_rgba(250,204,21,0.6)]';
        return 'text-cyber-primary border-cyber-primary shadow-[0_0_15px_rgba(0,255,157,0.6)]';
    };

    return (
        <div className="min-h-screen flex flex-col relative overflow-hidden">
            {/* Background Decor */}
            <div className="absolute inset-0 bg-cyber-900 z-0" />
            <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-cyber-primary/10 blur-[100px] rounded-full pointer-events-none" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyber-secondary/10 blur-[100px] rounded-full pointer-events-none" />

            {/* Navbar */}
            <nav className="border-b border-gray-800 bg-cyber-900/50 backdrop-blur-md sticky top-0 z-50">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center gap-2">
                            <div className="w-3 h-3 bg-cyber-primary rounded-full animate-pulse" />
                            <h1 className="text-xl font-bold tracking-tighter text-white">
                                PHISH<span className="text-cyber-primary">GUARD</span>
                            </h1>
                        </div>
                        <div className="flex items-center gap-6">
                            <a href="/about" className="text-gray-400 hover:text-white transition text-sm font-medium">Hakkımızda</a>
                            <span className="text-gray-400 text-sm hidden sm:block">
                                User: <span className="text-white font-mono">{username}</span>
                            </span>
                            <button
                                onClick={handleLogout}
                                className="text-xs border border-gray-700 text-gray-400 hover:text-white hover:border-white px-3 py-1.5 rounded transition uppercase tracking-wide"
                            >
                                Disconnect
                            </button>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="flex-1 flex flex-col items-center p-6 relative z-10 w-full max-w-5xl mx-auto pb-20">
                <header className="mb-10 text-center space-y-2 mt-10">
                    <h2 className="text-3xl md:text-5xl font-bold text-white tracking-tight">Threat Analysis Console</h2>
                    <p className="text-gray-400">Securely analyze email headers and content for malicious signatures.</p>
                </header>

                <div className="w-full grid lg:grid-cols-3 gap-8 mb-12">

                    {/* Input Section */}
                    <div className="lg:col-span-2 space-y-6">

                        {/* Tabs */}
                        <div className="flex gap-4 border-b border-gray-800 pb-1">
                            <button
                                onClick={() => { setActiveTab('email'); setResult(null); }}
                                className={`pb-2 px-4 text-sm font-bold uppercase tracking-wider transition-all ${activeTab === 'email' ? 'text-cyber-primary border-b-2 border-cyber-primary' : 'text-gray-500 hover:text-white'}`}
                            >
                                Email Content
                            </button>
                            <button
                                onClick={() => { setActiveTab('url'); setResult(null); }}
                                className={`pb-2 px-4 text-sm font-bold uppercase tracking-wider transition-all ${activeTab === 'url' ? 'text-cyber-secondary border-b-2 border-cyber-secondary' : 'text-gray-500 hover:text-white'}`}
                            >
                                URL Scanner
                            </button>
                        </div>

                        <div className="cyber-card p-1 relative group">
                            {/* Decorative borders */}
                            <div className="absolute top-0 left-0 w-4 h-4 border-t-2 border-l-2 border-cyber-secondary/50 rounded-tl-lg" />
                            <div className="absolute top-0 right-0 w-4 h-4 border-t-2 border-r-2 border-cyber-secondary/50 rounded-tr-lg" />
                            <div className="absolute bottom-0 left-0 w-4 h-4 border-b-2 border-l-2 border-cyber-secondary/50 rounded-bl-lg" />
                            <div className="absolute bottom-0 right-0 w-4 h-4 border-b-2 border-r-2 border-cyber-secondary/50 rounded-br-lg" />

                            <div className="bg-cyber-900 p-6 rounded-lg min-h-[300px] flex flex-col">
                                <div className="flex justify-between items-center mb-4">
                                    <label className={`text-xs font-bold uppercase tracking-widest flex items-center gap-2 ${activeTab === 'email' ? 'text-cyber-primary' : 'text-cyber-secondary'}`}>
                                        <span className={`w-1.5 h-1.5 rounded-full ${activeTab === 'email' ? 'bg-cyber-primary' : 'bg-cyber-secondary'}`} />
                                        {activeTab === 'email' ? 'Input Stream' : 'Target URL'}
                                    </label>
                                    <span className="text-[10px] text-gray-600 font-mono">READY</span>
                                </div>

                                {activeTab === 'email' ? (
                                    <textarea
                                        className="w-full h-64 p-4 terminal-input rounded-md resize-none text-sm leading-relaxed focus:outline-none flex-1"
                                        placeholder="// Paste email content here for analysis..."
                                        value={text}
                                        onChange={(e) => setText(e.target.value)}
                                    ></textarea>
                                ) : (
                                    <div className="flex-1 flex flex-col justify-center">
                                        <input
                                            type="text"
                                            className="w-full p-4 terminal-input rounded-md text-sm leading-relaxed focus:outline-none font-mono"
                                            placeholder="https://example.com/suspicious-link"
                                            value={url}
                                            onChange={(e) => setUrl(e.target.value)}
                                        />
                                        <p className="mt-4 text-xs text-gray-500 font-mono">
                                            &gt; Preparing deep scan module...<br />
                                            &gt; Waiting for target input...
                                        </p>
                                    </div>
                                )}

                                <div className="mt-6 flex justify-end">
                                    <button
                                        onClick={analyzeContent}
                                        className={`cyber-button px-8 py-3 rounded text-sm w-full sm:w-auto ${activeTab === 'url' ? 'bg-cyber-secondary hover:bg-cyan-400 hover:shadow-neon-blue' : ''}`}
                                    >
                                        {activeTab === 'email' ? 'Run Analysis' : 'Scan URL'}
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>

                    {/* Results Section */}
                    <div className="lg:col-span-1">
                        {result ? (
                            <div className="cyber-card p-6 h-full flex flex-col items-center justify-center animate-fade-in text-center relative overflow-hidden">
                                <div className="absolute inset-0 bg-cyber-primary/5 pointer-events-none" />

                                <span className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-6">Threat Factor</span>

                                <div className={`
                            ${getScoreColor(result.score)}
                            relative
                        `}>
                                    {result.score}
                                    <span className="absolute -bottom-2 text-[10px] bg-cyber-900 px-2 text-gray-400 font-sans tracking-widest">SCORE</span>
                                </div>

                                <div className="mt-8 space-y-2">
                                    <p className="text-gray-400 text-xs uppercase tracking-widest">Classification</p>
                                    <div className={`text-2xl font-bold tracking-tight ${result.risk_level === 'High' ? 'text-red-500' :
                                        result.risk_level === 'Medium' ? 'text-yellow-400' : 'text-cyber-primary'
                                        }`}>
                                        {result.risk_level} Risk
                                    </div>
                                </div>
                            </div>
                        ) : (
                            <div className="cyber-card p-6 h-full flex flex-col items-center justify-center text-center opacity-50 border-dashed">
                                <div className="w-16 h-16 rounded-full border-2 border-gray-700 mb-4 flex items-center justify-center">
                                    <span className="w-2 h-2 bg-gray-700 rounded-full animate-ping" />
                                </div>
                                <p className="text-gray-500 text-sm font-mono">Waiting for data...</p>
                            </div>
                        )}
                    </div>

                </div>
            </main>
        </div>
    );
}
