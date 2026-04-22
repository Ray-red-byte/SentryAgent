import { useState } from 'react';
import { login } from '../api';
import { ShieldCheck, LogIn, Eye, EyeOff, Loader2, AlertCircle } from 'lucide-react';

export default function LoginPage({ onLogin }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [showPass, setShowPass] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!username.trim() || !password.trim()) {
            setError('Username and password are required.');
            return;
        }

        setError('');
        setLoading(true);
        try {
            await login(username.trim(), password);
            onLogin();
        } catch (err) {
            const detail = err.response?.data?.detail;
            setError(detail || 'Login failed. Check your credentials and try again.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-sentry-dark flex items-center justify-center p-4 relative overflow-hidden">

            {/* ── Ambient glow blobs ── */}
            <div className="absolute top-[-10%] left-[-5%] w-[500px] h-[500px] rounded-full bg-sentry-accent/5 blur-3xl pointer-events-none" />
            <div className="absolute bottom-[-10%] right-[-5%] w-[400px] h-[400px] rounded-full bg-blue-600/5 blur-3xl pointer-events-none" />

            <div className="w-full max-w-sm relative z-10">

                {/* ── Logo / Brand ── */}
                <div className="text-center mb-10">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-sentry-accent/20 to-blue-600/20 border border-sentry-accent/30 mb-5 shadow-xl shadow-sentry-accent/10">
                        <ShieldCheck className="w-8 h-8 text-sentry-accent" />
                    </div>
                    <h1 className="text-3xl font-bold tracking-tight text-white">Sentry Agent</h1>
                    <p className="text-gray-500 text-sm mt-2">AI-Powered Security Auditor</p>
                </div>

                {/* ── Login Card ── */}
                <div className="bg-sentry-card border border-gray-700/60 rounded-2xl p-8 shadow-2xl backdrop-blur-sm">
                    <h2 className="text-lg font-semibold text-white mb-6">Sign in to continue</h2>

                    <form onSubmit={handleSubmit} className="space-y-5" noValidate>

                        {/* Username */}
                        <div>
                            <label htmlFor="username" className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">
                                Username
                            </label>
                            <input
                                id="username"
                                type="text"
                                autoComplete="username"
                                autoFocus
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                disabled={loading}
                                placeholder="admin"
                                className="w-full bg-gray-800/60 border border-gray-600 text-white rounded-lg px-4 py-2.5 text-sm
                           placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sentry-accent/60
                           focus:border-sentry-accent transition-all disabled:opacity-50"
                            />
                        </div>

                        {/* Password */}
                        <div>
                            <label htmlFor="password" className="block text-xs font-medium text-gray-400 mb-1.5 uppercase tracking-wider">
                                Password
                            </label>
                            <div className="relative">
                                <input
                                    id="password"
                                    type={showPass ? 'text' : 'password'}
                                    autoComplete="current-password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    disabled={loading}
                                    placeholder="••••••••"
                                    className="w-full bg-gray-800/60 border border-gray-600 text-white rounded-lg px-4 py-2.5 text-sm
                             placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-sentry-accent/60
                             focus:border-sentry-accent transition-all pr-11 disabled:opacity-50"
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPass(s => !s)}
                                    aria-label={showPass ? 'Hide password' : 'Show password'}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors"
                                >
                                    {showPass ? <EyeOff size={16} /> : <Eye size={16} />}
                                </button>
                            </div>
                        </div>

                        {/* Error message */}
                        {error && (
                            <div className="flex items-start gap-2 bg-red-900/20 border border-red-500/30 rounded-lg p-3 text-red-400 text-sm">
                                <AlertCircle size={15} className="mt-0.5 flex-none" />
                                <span>{error}</span>
                            </div>
                        )}

                        {/* Submit */}
                        <button
                            id="login-submit"
                            type="submit"
                            disabled={loading}
                            className="w-full flex items-center justify-center gap-2.5 bg-sentry-accent hover:bg-sky-300
                         text-sentry-dark font-bold py-2.5 rounded-lg text-sm transition-all duration-200
                         shadow-lg shadow-sentry-accent/20 hover:shadow-sentry-accent/40
                         disabled:opacity-60 disabled:cursor-not-allowed"
                        >
                            {loading
                                ? <><Loader2 size={16} className="animate-spin" /> Signing in…</>
                                : <><LogIn size={16} /> Sign In</>
                            }
                        </button>
                    </form>
                </div>

                {/* ── Footer note ── */}
                <p className="text-center text-xs text-gray-600 mt-6">
                    Credentials are set via environment variables.
                </p>
            </div>
        </div>
    );
}
