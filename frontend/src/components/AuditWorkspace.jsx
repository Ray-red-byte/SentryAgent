import React, { useState, useEffect } from 'react';
import api from '../api';
import { ShieldAlert, Wrench, Baby, CheckCircle, ArrowRight } from 'lucide-react';

const AuditWorkspace = ({ sessionId, file }) => {
    const [report, setReport] = useState([]); // Default to empty array
    const [fixedCode, setFixedCode] = useState(null);
    const [explanation, setExplanation] = useState(null);
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('audit');

    useEffect(() => {
        setReport([]); // Reset to array
        setFixedCode(null);
        setExplanation(null);
        setActiveTab('audit');
        runAudit();
    }, [file]);

    const runAudit = async () => {
        setLoading(true);
        try {
            const res = await api.post("/audit", {
                session_id: sessionId,
                file_path: file.file
            });
            // Safety Check: Ensure we received an Array
            if (Array.isArray(res.data.report)) {
                setReport(res.data.report);
            } else {
                console.error("Invalid report format:", res.data.report);
                setReport([]);
            }
        } catch (err) {
            console.error(err);
            setReport([]);
        } finally {
            setLoading(false);
        }
    };

    const runFix = async () => {
        setLoading(true);
        try {
            const res = await api.post("/fix", {
                session_id: sessionId,
                file_path: file.file
            });
            setFixedCode(res.data.fixed_code);
            setActiveTab('fix');
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    const runExplain = async () => {
        if (!report || report.length === 0) return;
        setLoading(true);
        try {
            const res = await api.post("/explain", { report: report });
            setExplanation(res.data.explanation);
        } catch (err) {
            console.error(err);
        } finally {
            setLoading(false);
        }
    };

    if (loading && report.length === 0) {
        return (
            <div className="h-full flex items-center justify-center text-sentry-accent animate-pulse">
                Running Deep Security Audit...
            </div>
        );
    }

    return (
        <div className="h-full flex flex-col min-h-0"> {/* min-h-0 is KEY for nested scrolling */}

            {/* Header */}
            <div className="flex-none flex items-center justify-between mb-4 border-b border-gray-700 pb-4">
                <h2 className="text-xl font-bold font-mono truncate max-w-md" title={file.file}>
                    {file.file}
                </h2>
                <div className="flex gap-2">
                    <button
                        onClick={() => setActiveTab('audit')}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-2 ${activeTab === 'audit' ? 'bg-sentry-accent text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300'}`}
                    >
                        <ShieldAlert size={16} /> Audit
                    </button>
                    <button
                        onClick={() => { runFix(); setActiveTab('fix'); }}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-2 ${activeTab === 'fix' ? 'bg-green-500 text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300'}`}
                    >
                        <Wrench size={16} /> Fix
                    </button>
                </div>
            </div>

            {/* VIEW 1: AUDIT REPORT (Scrollable) */}
            {activeTab === 'audit' && (
                <div className="flex-1 overflow-y-auto pr-2 custom-scrollbar space-y-6">
                    {!explanation && report.length > 0 && (
                        <button onClick={runExplain} className="w-full py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm text-gray-300 flex items-center justify-center gap-2 transition-colors">
                            <Baby size={16} /> Explain like I'm 5
                        </button>
                    )}

                    {explanation && (
                        <div className="bg-blue-900/20 border border-blue-500/30 p-4 rounded-lg text-sm text-blue-200">
                            <h4 className="font-bold flex items-center gap-2 mb-2">
                                <Baby size={16} /> Vibe Check
                            </h4>
                            <div className="whitespace-pre-wrap">{explanation}</div>
                        </div>
                    )}

                    {Array.isArray(report) && report.map((vuln, idx) => (
                        <div key={idx} className="bg-gray-800/50 border border-red-500/30 p-4 rounded-lg">
                            <div className="flex justify-between items-start mb-2">
                                <span className="text-red-400 font-bold flex items-center gap-2">
                                    <ShieldAlert size={16} /> {vuln.type}
                                </span>
                                <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded">
                                    {vuln.severity}
                                </span>
                            </div>
                            <p className="text-gray-300 text-sm mb-3">{vuln.description}</p>
                            <div className="bg-black/50 p-3 rounded text-xs font-mono text-gray-400 border-l-2 border-red-500">
                                Line {vuln.line}: {vuln.fix}
                            </div>
                        </div>
                    ))}

                    {report.length === 0 && !loading && (
                        <div className="text-center text-green-400 py-10">
                            <CheckCircle className="w-16 h-16 mx-auto mb-4" />
                            <p>No vulnerabilities found (or parser failed).</p>
                        </div>
                    )}
                </div>
            )}

            {/* VIEW 2: FIX (Scrollable Code Block) */}
            {activeTab === 'fix' && (
                <div className="flex-1 flex flex-col min-h-0"> {/* min-h-0 allows child to scroll */}
                    {loading ? (
                        <div className="flex-1 flex items-center justify-center text-green-400 animate-pulse">
                            <Wrench className="w-8 h-8 animate-spin mr-2" /> Generating Secure Code...
                        </div>
                    ) : fixedCode ? (
                        <div className="flex-1 bg-black rounded-lg border border-gray-700 overflow-hidden flex flex-col">
                            <div className="bg-gray-800 px-4 py-2 text-xs text-gray-400 flex justify-between flex-none">
                                <span>Fixed Version</span>
                                <span className="text-green-400">Ready to Apply</span>
                            </div>
                            {/* Overflow-auto here enables scrolling within the code block */}
                            <pre className="flex-1 p-4 overflow-auto text-sm font-mono text-green-100 custom-scrollbar">
                                {fixedCode}
                            </pre>
                        </div>
                    ) : null}
                </div>
            )}
        </div>
    );
};

export default AuditWorkspace;