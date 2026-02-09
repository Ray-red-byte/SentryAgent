import React, { useState, useEffect, useRef } from 'react';
import api from '../api';
import { ShieldAlert, Wrench, MessageSquare, Send, User, Bot, Play, Loader2, Save, CheckCircle } from 'lucide-react';

const AuditWorkspace = ({ sessionId, file }) => {
    const [report, setReport] = useState([]);
    const [fixedCode, setFixedCode] = useState(null);
    const [chatHistory, setChatHistory] = useState([]);
    const [chatInput, setChatInput] = useState("");
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('audit');
    const [hasAudited, setHasAudited] = useState(false);
    const chatEndRef = useRef(null);

    // Reset state when file changes (New Upload / Selection)
    useEffect(() => {
        setReport([]);
        setFixedCode(null);
        setChatHistory([]);
        setActiveTab('audit');
        setHasAudited(false);
    }, [file]);

    // Auto-scroll chat
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [chatHistory, activeTab]);

    const runAudit = async () => {
        if (loading) return;
        setLoading(true);
        try {
            const res = await api.post("/audit", { session_id: sessionId, file_path: file.file });
            setReport(Array.isArray(res.data.report) ? res.data.report : []);
            setHasAudited(true);
        } catch (err) {
            console.error(err);
            setReport([]);
        } finally {
            setLoading(false);
        }
    };

    const runFix = async () => {
        if (fixedCode) { setActiveTab('fix'); return; }
        setLoading(true);
        try {
            const res = await api.post("/fix", { session_id: sessionId, file_path: file.file });
            setFixedCode(res.data.fixed_code);
            setActiveTab('fix');
        } catch (err) { console.error(err); } finally { setLoading(false); }
    };

    const applyFix = async () => {
        if (!fixedCode) return;
        setLoading(true);
        try {
            await api.post("/apply", { session_id: sessionId, file_path: file.file, fixed_code: fixedCode });
            setReport([]); setFixedCode(null); setHasAudited(false); setActiveTab('audit');
            setTimeout(() => runAudit(), 500); // Auto Re-Verify
        } catch (err) { alert("Failed to apply fix."); } finally { setLoading(false); }
    };

    const sendChat = async () => {
        if (!chatInput.trim()) return;
        const userMsg = { role: 'user', text: chatInput };
        setChatHistory(prev => [...prev, userMsg]);
        setChatInput("");
        setLoading(true);

        try {
            const res = await api.post("/chat", {
                session_id: sessionId,
                file_path: file.file,
                query: userMsg.text
            });
            setChatHistory(prev => [...prev, { role: 'ai', text: res.data.response }]);
        } catch (err) {
            setChatHistory(prev => [...prev, { role: 'ai', text: "Error connecting to AI." }]);
        } finally {
            setLoading(false);
        }
    };

    // Logic to Disable Fix Button
    // Disabled if: Not Audited OR No Vulnerabilities Found (Clean)
    const isFixDisabled = !hasAudited || report.length === 0;

    return (
        <div className="h-full flex flex-col min-h-0">

            {/* Header */}
            <div className="flex-none flex items-center justify-between mb-4 border-b border-gray-700 pb-4">
                <h2 className="text-xl font-bold font-mono truncate max-w-md" title={file.file}>{file.file}</h2>
                <div className="flex gap-2">

                    <button onClick={() => setActiveTab('audit')}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-2 transition-colors ${activeTab === 'audit' ? 'bg-sentry-accent text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}>
                        <ShieldAlert size={16} /> Audit
                    </button>

                    <button onClick={runFix} disabled={isFixDisabled}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-2 transition-colors ${activeTab === 'fix' ? 'bg-green-500 text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300'} 
            ${isFixDisabled ? 'opacity-50 cursor-not-allowed' : 'hover:bg-gray-700'}`}>
                        <Wrench size={16} /> Fix
                    </button>

                    <button onClick={() => setActiveTab('chat')}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-2 transition-colors ${activeTab === 'chat' ? 'bg-blue-500 text-white font-bold' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}>
                        <MessageSquare size={16} /> Chat
                    </button>

                </div>
            </div>

            {/* --- TAB 1: AUDIT --- */}
            {activeTab === 'audit' && (
                <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar flex flex-col">
                    {!hasAudited && !loading && (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-400">
                            <ShieldAlert className="w-16 h-16 mb-4 opacity-30" />
                            <p className="mb-6 text-lg">Ready to analyze <span className="font-mono text-white">{file.file}</span></p>
                            <button onClick={runAudit} className="flex items-center gap-2 bg-sentry-accent text-sentry-dark px-6 py-3 rounded-lg font-bold hover:bg-white transition-all shadow-lg shadow-sentry-accent/20">
                                <Play size={20} fill="currentColor" /> Run Audit
                            </button>
                        </div>
                    )}
                    {loading && <div className="flex-1 flex flex-col items-center justify-center text-sentry-accent animate-pulse"><Loader2 className="w-10 h-10 animate-spin mb-4" /><p>Analyzing...</p></div>}

                    {hasAudited && !loading && (
                        <div className="space-y-4">
                            {report.map((vuln, idx) => (
                                <div key={idx} className="bg-gray-800/50 border border-red-500/30 p-4 rounded-lg">
                                    <div className="flex justify-between items-start mb-2">
                                        <span className="text-red-400 font-bold flex items-center gap-2"><ShieldAlert size={16} /> {vuln.type}</span>
                                        <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded">{vuln.severity}</span>
                                    </div>
                                    <p className="text-gray-300 text-sm mb-3">{vuln.description}</p>
                                </div>
                            ))}
                            {report.length === 0 && (
                                <div className="text-center text-green-400 py-10">
                                    <CheckCircle className="w-20 h-20 mx-auto mb-4" />
                                    <h3 className="text-xl font-bold">Secure & Clean</h3>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* --- TAB 2: FIX --- */}
            {activeTab === 'fix' && (
                <div className="flex-1 flex flex-col min-h-0">
                    {loading ? <div className="flex-1 flex items-center justify-center text-green-400 animate-pulse"><Wrench className="w-8 h-8 animate-spin mr-2" /> Generating Patch...</div> :
                        fixedCode && (
                            <div className="flex-1 bg-black rounded-lg border border-gray-700 overflow-hidden flex flex-col">
                                <div className="bg-gray-800 px-4 py-2 text-xs flex justify-between items-center">
                                    <span className="text-gray-400">Proposed Fix</span>
                                    <button onClick={applyFix} className="flex items-center gap-2 bg-green-600 hover:bg-green-500 text-white px-3 py-1 rounded text-xs font-bold"><Save size={12} /> Apply & Verify</button>
                                </div>
                                <pre className="flex-1 p-4 overflow-auto text-sm font-mono text-green-100 custom-scrollbar">{fixedCode}</pre>
                            </div>
                        )}
                </div>
            )}

            {/* --- TAB 3: CHAT (New!) --- */}
            {activeTab === 'chat' && (
                <div className="flex-1 flex flex-col min-h-0 bg-gray-900/50 rounded-lg border border-gray-700">
                    <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                        {chatHistory.length === 0 && (
                            <div className="text-center text-gray-500 mt-10">
                                <Bot className="w-12 h-12 mx-auto mb-3 opacity-50" />
                                <p>Ask anything about <span className="font-mono text-gray-400">{file.file}</span></p>
                            </div>
                        )}
                        {chatHistory.map((msg, i) => (
                            <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                                <div className={`w-8 h-8 rounded-full flex items-center justify-center flex-none ${msg.role === 'user' ? 'bg-sentry-accent text-sentry-dark' : 'bg-blue-600 text-white'}`}>
                                    {msg.role === 'user' ? <User size={16} /> : <Bot size={16} />}
                                </div>
                                <div className={`p-3 rounded-lg text-sm max-w-[80%] ${msg.role === 'user' ? 'bg-gray-800 text-white' : 'bg-blue-900/30 text-blue-100'}`}>
                                    {msg.text}
                                </div>
                            </div>
                        ))}
                        {loading && <div className="flex gap-3"><div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center"><Bot size={16} /></div><div className="text-gray-400 text-sm flex items-center">Thinking...</div></div>}
                        <div ref={chatEndRef} />
                    </div>
                    <div className="p-3 border-t border-gray-700 flex gap-2">
                        <input
                            type="text"
                            value={chatInput}
                            onChange={(e) => setChatInput(e.target.value)}
                            onKeyDown={(e) => e.key === 'Enter' && sendChat()}
                            placeholder="Ask a security question..."
                            className="flex-1 bg-gray-800 border-none rounded px-4 py-2 text-sm text-white focus:ring-1 focus:ring-sentry-accent outline-none"
                        />
                        <button onClick={sendChat} disabled={loading} className="bg-sentry-accent text-sentry-dark p-2 rounded hover:bg-white transition-colors disabled:opacity-50">
                            <Send size={18} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AuditWorkspace;