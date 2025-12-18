import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import axios from 'axios';

export default function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setError(''); // Reset error
        try {
            console.log("Attempting login with:", username);
            const res = await axios.post('http://127.0.0.1:8000/auth/login', {
                username,
                password
            });
            console.log("Login success:", res.data);
            localStorage.setItem('token', res.data.token);
            localStorage.setItem('username', res.data.username);

            // Redirect immediately
            navigate('/dashboard');
        } catch (err) {
            console.error("Login failed:", err); // Log full error for debugging

            let msg = "Connection to server failed. Ensure Backend is running.";

            if (err.response && err.response.data && err.response.data.detail) {
                // If detail is an object/array (e.g., validation errors), stringify it
                if (typeof err.response.data.detail === 'object') {
                    msg = JSON.stringify(err.response.data.detail);
                } else {
                    msg = err.response.data.detail;
                }
            } else if (err.message) {
                msg = err.message;
            }

            setError(msg);
            alert(`Login Failed: ${msg}`);
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen relative overflow-hidden">
            {/* Background Gradients */}
            <div className="absolute inset-0 bg-cyber-900 z-0" />
            <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-cyber-primary/10 blur-[100px] rounded-full" />
            <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-cyber-secondary/10 blur-[100px] rounded-full" />

            <div className="w-full max-w-md z-10 p-6">
                <div className="cyber-card p-8 backdrop-blur-sm bg-cyber-800/90">
                    <div className="text-center mb-8">
                        <h1 className="text-3xl font-bold tracking-tighter text-white">
                            PHISH<span className="text-cyber-primary">GUARD</span>
                        </h1>
                        <p className="text-gray-400 text-sm mt-2">Secure Access Portal</p>
                    </div>

                    {error && <div className="bg-red-500/10 border border-red-500/50 text-red-500 p-3 rounded text-sm mb-6 text-center">{error}</div>}

                    <form onSubmit={handleLogin} className="space-y-6">
                        <div>
                            <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2">Username</label>
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="w-full bg-cyber-900 border border-gray-700 text-white rounded p-3 focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary outline-none transition-all"
                                placeholder="Enter username"
                                required
                            />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-400 uppercase tracking-widest mb-2">Password</label>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full bg-cyber-900 border border-gray-700 text-white rounded p-3 focus:border-cyber-primary focus:ring-1 focus:ring-cyber-primary outline-none transition-all"
                                placeholder="••••••••"
                                required
                            />
                        </div>
                        <button type="submit" className="w-full cyber-button py-3 rounded shadow-lg shadow-cyber-primary/20">
                            Authenticate
                        </button>
                    </form>
                    <p className="mt-8 text-center text-sm text-gray-500">
                        No credentials? <Link to="/register" className="text-cyber-secondary hover:text-white transition-colors">Initialize Identity</Link>
                    </p>
                </div>
            </div>
        </div>
    );
}
