import React, { useState, useEffect, useRef } from 'react';
import api, { tokenStore } from '../api';
import { useTaskContext } from '../context/TaskContext';
import {
    ShieldAlert, Wrench, MessageSquare, Send, User, Bot,
    Play, Loader2, Save, CheckCircle, Download, RefreshCw,
    AlertCircle, Info, ChevronRight, ChevronDown, FileText, Layers,
} from 'lucide-react';

// ── Severity helpers ────────────────────────────────────────────────────────
const SEVERITY_STYLES = {
    CRITICAL: 'bg-red-900/40 text-red-300 border-red-500/40',
    HIGH: 'bg-orange-900/40 text-orange-300 border-orange-500/40',
    MEDIUM: 'bg-yellow-900/30 text-yellow-300 border-yellow-500/30',
    LOW: 'bg-blue-900/30 text-blue-300 border-blue-500/30',
    INFO: 'bg-gray-800/50 text-gray-300 border-gray-600/40',
    ERROR: 'bg-red-900/20 text-red-400 border-red-600/30',
};

const SEVERITY_DOT = {
    CRITICAL: 'bg-red-400',
    HIGH: 'bg-orange-400',
    MEDIUM: 'bg-yellow-400',
    LOW: 'bg-blue-400',
    INFO: 'bg-gray-400',
    ERROR: 'bg-red-500',
};

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'ERROR'];

function SeverityBadge({ severity }) {
    const s = (severity || 'INFO').toUpperCase();
    return (
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${SEVERITY_STYLES[s] || SEVERITY_STYLES.INFO}`}>
            {s}
        </span>
    );
}

// ── Progress bar ─────────────────────────────────────────────────────────────
function ProgressBar({ value, label }) {
    return (
        <div className="space-y-1.5">
            <div className="flex justify-between text-xs text-gray-400">
                <span>{label}</span>
                <span>{value}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-1.5">
                <div
                    className="h-1.5 rounded-full bg-gradient-to-r from-sentry-accent to-blue-500 transition-all duration-700"
                    style={{ width: `${value}%` }}
                />
            </div>
        </div>
    );
}

// ── Single vulnerability card ──────────────────────────────────────────────
function VulnCard({ vuln, showFile = false }) {
    return (
        <div className={`rounded-xl border p-4 space-y-2 ${SEVERITY_STYLES[vuln.severity?.toUpperCase()] || SEVERITY_STYLES.INFO}`}>
            <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                    <span className={`w-2 h-2 rounded-full flex-none mt-0.5 ${SEVERITY_DOT[vuln.severity?.toUpperCase()] || 'bg-gray-400'}`} />
                    <span className="font-bold text-sm truncate">{vuln.type}</span>
                </div>
                <SeverityBadge severity={vuln.severity} />
            </div>

            {(vuln.line > 0 || showFile) && (
                <div className="flex items-center gap-1.5 text-xs opacity-70 flex-wrap">
                    <ChevronRight size={12} />
                    {vuln.line > 0 && <span className="font-mono">Line {vuln.line}</span>}
                    {showFile && vuln.file && <span>· {vuln.file}</span>}
                    {!showFile && vuln.file && vuln.line > 0 && <span>· {vuln.file}</span>}
                    {vuln.cvss_score > 0 && <span>· CVSS {vuln.cvss_score.toFixed(1)}</span>}
                </div>
            )}

            <p className="text-sm opacity-90 leading-relaxed">{vuln.description}</p>

            {vuln.fix && (
                <details className="group">
                    <summary className="text-xs cursor-pointer opacity-60 hover:opacity-100 transition-opacity flex items-center gap-1">
                        <Info size={11} /> Suggested fix
                    </summary>
                    <pre className="mt-2 text-xs font-mono bg-black/20 rounded p-2 whitespace-pre-wrap opacity-80">
                        {vuln.fix}
                    </pre>
                </details>
            )}
        </div>
    );
}

// ── Bundle results: findings grouped by file ──────────────────────────────
function BundleResults({ report }) {
    const [expandedFiles, setExpandedFiles] = useState({});

    // Group by file, preserving severity order within each group
    const grouped = report
        .filter(v => v.severity !== 'ERROR')
        .reduce((acc, vuln) => {
            const key = vuln.file || 'Unknown File';
            if (!acc[key]) acc[key] = [];
            acc[key].push(vuln);
            return acc;
        }, {});

    // Sort files by their worst severity
    const sortedFiles = Object.entries(grouped).sort(([, aVulns], [, bVulns]) => {
        const worstIdx = (vulns) =>
            Math.min(...vulns.map(v => SEVERITY_ORDER.indexOf(v.severity?.toUpperCase() || 'INFO')));
        return worstIdx(aVulns) - worstIdx(bVulns);
    });

    const toggleFile = (fp) =>
        setExpandedFiles(prev => ({ ...prev, [fp]: !prev[fp] }));

    // Start all expanded
    useEffect(() => {
        const init = {};
        sortedFiles.forEach(([fp]) => { init[fp] = true; });
        setExpandedFiles(init);
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [report]);

    if (sortedFiles.length === 0) return null;

    return (
        <div className="space-y-3">
            {sortedFiles.map(([filePath, vulns]) => {
                const worstSeverity = SEVERITY_ORDER.find(s => vulns.some(v => v.severity?.toUpperCase() === s)) || 'INFO';
                const isOpen = expandedFiles[filePath] !== false;

                return (
                    <div key={filePath} className="rounded-xl border border-gray-700 overflow-hidden">
                        {/* File sub-header */}
                        <button
                            onClick={() => toggleFile(filePath)}
                            className="w-full flex items-center gap-2.5 px-4 py-2.5 bg-gray-800/60 hover:bg-gray-800 transition-colors text-left"
                        >
                            {isOpen
                                ? <ChevronDown size={13} className="flex-none text-gray-400" />
                                : <ChevronRight size={13} className="flex-none text-gray-400" />
                            }
                            <FileText size={13} className="flex-none text-gray-400" />
                            <span className="font-mono text-xs text-gray-200 truncate flex-1">{filePath}</span>
                            <div className="flex items-center gap-2 flex-none">
                                <span className="text-[10px] text-gray-500">{vulns.length} finding{vulns.length !== 1 ? 's' : ''}</span>
                                <SeverityBadge severity={worstSeverity} />
                            </div>
                        </button>

                        {/* Findings for this file */}
                        {isOpen && (
                            <div className="p-3 space-y-2.5 bg-gray-900/30">
                                {vulns.map((vuln, idx) => (
                                    <VulnCard key={idx} vuln={vuln} showFile={false} />
                                ))}
                            </div>
                        )}
                    </div>
                );
            })}
        </div>
    );
}

// ── Main component ────────────────────────────────────────────────────────────
const AuditWorkspace = ({ sessionId, file }) => {
    const [report, setReport] = useState([]);
    const [fixedCode, setFixedCode] = useState(null);
    const [chatHistory, setChatHistory] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('audit');
    const [hasAudited, setHasAudited] = useState(false);
    const [applyState, setApplyState] = useState('idle'); // idle | applying | applied | error
    const [downloadUrl, setDownloadUrl] = useState(null);
    const [progress, setProgress] = useState(0);
    const [progressLabel, setProgressLabel] = useState('');
    // null while idle; { total, current, currentFile, errors[], done } during sequential bundle fix
    const [bundleFixProgress, setBundleFixProgress] = useState(null);
    const chatEndRef = useRef(null);
    const runAuditRef = useRef(null);

    // Per-file/bundle result cache
    const fileCache = useRef({});
    const currentFileRef = useRef(null);

    const { activeTasks, startTask, endTask } = useTaskContext();

    // ── Derived values ──────────────────────────────────────────────────────
    const isBundleMode = (file?.involved_files?.length ?? 0) > 1;
    const bundleName = file?.bundleName;
    // Cache key: bundle name for bundles, file path for single-file
    const cacheKey = bundleName || file?.file || file?.file_path;
    // Primary file (used in /chat and /fix as the single-file target)
    const primaryFile = file?.file || file?.file_path;

    // Progressive audit animation
    const progressTimerRef = useRef(null);
    const startProgressAnimation = (startPct, endPct, label, durationMs) => {
        clearInterval(progressTimerRef.current);
        setProgressLabel(label);
        setProgress(startPct);
        const step = (endPct - startPct) / (durationMs / 200);
        progressTimerRef.current = setInterval(() => {
            setProgress(p => {
                if (p >= endPct) { clearInterval(progressTimerRef.current); return endPct; }
                return Math.min(p + step, endPct);
            });
        }, 200);
    };

    // Restore from cache or reset when the selected file/bundle changes
    useEffect(() => {
        if (!cacheKey) return;

        currentFileRef.current = cacheKey;
        clearInterval(progressTimerRef.current);

        const cached = fileCache.current[cacheKey];
        if (cached) {
            setReport(cached.report ?? []);
            setFixedCode(cached.fixedCode ?? null);
            setChatHistory(cached.chatHistory ?? []);
            setHasAudited(cached.hasAudited ?? false);
            setApplyState(cached.applyState ?? 'idle');
            setDownloadUrl(cached.downloadUrl ?? null);
        } else {
            setReport([]);
            setFixedCode(null);
            setChatHistory([]);
            setHasAudited(false);
            setApplyState('idle');
            setDownloadUrl(null);
        }
        setLoading(false);
        setActiveTab('audit');
        setProgress(0);
        setProgressLabel('');
        setBundleFixProgress(null);
    }, [cacheKey]);

    // Persist state to cache
    useEffect(() => {
        if (!cacheKey) return;
        fileCache.current[cacheKey] = { report, fixedCode, chatHistory, hasAudited, applyState, downloadUrl };
    }, [cacheKey, report, fixedCode, chatHistory, hasAudited, applyState, downloadUrl]);

    // Auto-scroll chat
    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatHistory, activeTab]);

    // Clean up timer
    useEffect(() => () => clearInterval(progressTimerRef.current), []);

    // ── Actions ────────────────────────────────────────────────────────────────

    const runAudit = async () => {
        if (loading || activeTasks[cacheKey]) return;
        const thisKey = cacheKey;
        setLoading(true);
        setHasAudited(false);
        setReport([]);

        const label = isBundleMode
            ? `AI analyzing ${file.involved_files.length} files in bundle…`
            : 'AI analyzing file…';
        startTask(thisKey, 'auditing', label);
        startProgressAnimation(0, 85, label, isBundleMode ? 60000 : 40000);

        try {
            const payload = { session_id: sessionId, file_path: primaryFile };
            if (isBundleMode) {
                payload.bundle_name = bundleName;
                payload.involved_files = file.involved_files;
            }
            const res = await api.post('/audit', payload);
            if (currentFileRef.current !== thisKey) return;

            const raw = Array.isArray(res.data.report) ? res.data.report : [];
            const findings = raw.filter(v => v.severity !== 'ERROR');
            setReport(findings.length > 0 ? findings : raw);
            setHasAudited(true);
            setProgress(100);
            setProgressLabel('Audit complete');
        } catch (err) {
            if (currentFileRef.current !== thisKey) return;
            console.error('Audit failed:', err);
            setReport([{ severity: 'ERROR', type: 'Connection Error', description: err.response?.data?.detail || err.message, fix: '' }]);
            setHasAudited(true);
        } finally {
            clearInterval(progressTimerRef.current);
            endTask(thisKey);
            if (currentFileRef.current === thisKey) setLoading(false);
        }
    };

    // Single-file fix — always targets primaryFile only, with bundle context for data-flow awareness
    const runFix = async () => {
        if (fixedCode) { setActiveTab('fix'); return; }
        const thisKey = cacheKey;
        startTask(thisKey, 'fixing', 'Generating security patch…');
        setLoading(true);
        startProgressAnimation(0, 90, 'Generating security patch…', 60000);

        try {
            const payload = { session_id: sessionId, file_path: primaryFile };
            if (isBundleMode) {
                payload.bundle_name = bundleName;
                payload.involved_files = file.involved_files;
                // Only vulns attributed to the primary file
                const primaryVulns = report.filter(v => v.severity !== 'ERROR' && (v.file === primaryFile || !v.file));
                if (primaryVulns.length > 0) payload.vulnerabilities = primaryVulns;
            }
            const res = await api.post('/fix', payload);
            if (currentFileRef.current !== thisKey) return;
            setFixedCode(res.data.fixed_code);
            setActiveTab('fix');
            setProgress(100);
            setProgressLabel('Patch ready');
        } catch (err) {
            if (currentFileRef.current !== thisKey) return;
            console.error('Fix failed:', err);
        } finally {
            clearInterval(progressTimerRef.current);
            endTask(thisKey);
            if (currentFileRef.current === thisKey) setLoading(false);
        }
    };

    // Sequential bundle fix — one ReAct agent call per file, auto-applied after each
    const runBundleFix = async () => {
        if (loading || activeTasks[cacheKey]) return;
        const thisKey = cacheKey;

        // Group findings by the file they were reported against
        const validVulns = report.filter(v => v.severity !== 'ERROR');
        const byFile = {};
        validVulns.forEach(v => {
            const fp = v.file || primaryFile;
            if (!byFile[fp]) byFile[fp] = [];
            byFile[fp].push(v);
        });
        const fileGroups = Object.entries(byFile);
        if (fileGroups.length === 0) return;

        setLoading(true);
        setBundleFixProgress({ total: fileGroups.length, current: 0, currentFile: null, errors: [], done: false });
        startTask(thisKey, 'fixing', `Fixing ${bundleName} domain…`);

        const errors = [];
        try {
            for (let i = 0; i < fileGroups.length; i++) {
                const [filePath, fileVulns] = fileGroups[i];
                if (currentFileRef.current !== thisKey) break; // user navigated away

                setBundleFixProgress({ total: fileGroups.length, current: i + 1, currentFile: filePath, errors, done: false });
                startTask(filePath, 'fixing', `Fixing ${filePath}…`);

                try {
                    // Step A+B: fix this specific file (peer files provided as read-only context)
                    const fixRes = await api.post('/fix', {
                        session_id: sessionId,
                        file_path: filePath,
                        bundle_name: bundleName,
                        involved_files: file.involved_files,
                        vulnerabilities: fileVulns,
                    });

                    // Step C: apply immediately so the next iteration sees the updated workspace
                    startTask(filePath, 'applying', `Applying fix for ${filePath}…`);
                    const vulnTypes = [...new Set(fileVulns.map(v => v.type).filter(Boolean))].join(', ');
                    const topSeverity = fileVulns.find(v => ['CRITICAL', 'HIGH'].includes(v.severity))?.severity || 'MEDIUM';
                    await api.post('/apply', {
                        session_id: sessionId,
                        file_path: filePath,
                        fixed_code: fixRes.data.fixed_code,
                        vuln_type: vulnTypes || 'Security Fix',
                        severity: topSeverity,
                        cwe: '',
                    });
                } catch (err) {
                    console.error(`Bundle fix failed for ${filePath}:`, err);
                    errors.push(filePath);
                } finally {
                    endTask(filePath);
                }
            }

            if (currentFileRef.current !== thisKey) return;

            setBundleFixProgress({ total: fileGroups.length, current: fileGroups.length, currentFile: null, errors, done: true });
            setDownloadUrl(`/v2/download/${sessionId}`);
            setLoading(false);

            // Re-audit to verify all fixes landed
            setTimeout(() => {
                if (currentFileRef.current === thisKey) {
                    setHasAudited(false);
                    runAuditRef.current?.();
                }
            }, 1000);
        } finally {
            endTask(thisKey);
        }
    };

    const applyFix = async () => {
        if (!fixedCode) return;
        const thisKey = cacheKey;
        startTask(thisKey, 'applying', `Applying fix for ${primaryFile}…`);
        setApplyState('applying');
        setLoading(true);

        const vulnTypes = [...new Set(report.map(v => v.type).filter(Boolean))].join(', ');
        const topSeverity = report.find(v => ['CRITICAL', 'HIGH'].includes(v.severity))?.severity || 'MEDIUM';
        const cwes = [...new Set(report.map(v => v.cwe).filter(Boolean))].join(', ');

        try {
            await api.post('/apply', {
                session_id: sessionId,
                file_path: primaryFile,
                fixed_code: fixedCode,
                vuln_type: vulnTypes || 'Security Fix',
                severity: topSeverity,
                cwe: cwes,
            });

            setApplyState('applied');
            setDownloadUrl(`/v2/download/${sessionId}`);

            setTimeout(() => {
                if (currentFileRef.current !== thisKey) return;
                setFixedCode(null);
                setActiveTab('audit');
                setHasAudited(false);
                runAuditRef.current?.();
            }, 800);
        } catch (err) {
            if (currentFileRef.current === thisKey) {
                console.error('Apply failed:', err);
                setApplyState('error');
                alert('Failed to apply fix: ' + (err.response?.data?.detail || err.message));
            }
        } finally {
            endTask(thisKey);
            if (currentFileRef.current === thisKey) setLoading(false);
        }
    };

    const handleDownload = () => {
        const token = tokenStore.get();
        const url = `http://localhost:8000/v2/download/${sessionId}/${primaryFile}`;
        fetch(url, { headers: { Authorization: `Bearer ${token}` } })
            .then(r => r.blob())
            .then(blob => {
                const blobUrl = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = blobUrl;
                a.download = primaryFile.split('/').pop();
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(blobUrl);
            })
            .catch(err => alert('Download failed: ' + err.message));
    };

    const handleDownloadZip = () => {
        const token = tokenStore.get();
        const url = `http://localhost:8000/v2/download/${sessionId}`;
        fetch(url, { headers: { Authorization: `Bearer ${token}` } })
            .then(r => r.blob())
            .then(blob => {
                const blobUrl = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = blobUrl;
                a.download = `sentry_fixed_${sessionId.slice(0, 8)}.zip`;
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(blobUrl);
            })
            .catch(err => alert('Download failed: ' + err.message));
    };

    const sendChat = async () => {
        if (!chatInput.trim()) return;
        const userMsg = { role: 'user', text: chatInput };
        setChatHistory(prev => [...prev, userMsg]);
        setChatInput('');
        setLoading(true);

        try {
            const res = await api.post('/chat', {
                session_id: sessionId,
                file_path: primaryFile,
                query: userMsg.text,
            });
            setChatHistory(prev => [...prev, { role: 'ai', text: res.data.response }]);
        } catch (err) {
            setChatHistory(prev => [...prev, { role: 'ai', text: 'Error: ' + (err.response?.data?.detail || err.message) }]);
        } finally {
            setLoading(false);
        }
    };

    const isFixDisabled = !hasAudited || report.length === 0 || report.every(v => v.severity === 'ERROR');

    // Keep the ref current so stale setTimeout callbacks always call the latest version
    runAuditRef.current = runAudit;

    // ── Render ─────────────────────────────────────────────────────────────────
    return (
        <div className="relative h-full flex flex-col min-h-0">

            {/* Background task overlay — shown when user navigated away and came back mid-task */}
            {!loading && activeTasks[cacheKey] && (
                <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-gray-950/80 backdrop-blur-sm rounded-xl">
                    <Loader2 className="w-10 h-10 text-sentry-accent animate-spin mb-3" />
                    <p className="text-sm font-semibold text-white capitalize">
                        {activeTasks[cacheKey].label || `${activeTasks[cacheKey].type}…`}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">Running in background…</p>
                </div>
            )}

            {/* Header */}
            <div className="flex-none flex items-center justify-between mb-4 border-b border-gray-700 pb-4">
                <div className="min-w-0">
                    {isBundleMode ? (
                        <div className="flex items-center gap-2">
                            <Layers size={15} className="flex-none text-sentry-accent" />
                            <h2 className="text-base font-bold truncate max-w-sm text-white capitalize" title={bundleName}>
                                {bundleName?.replace(/_/g, ' ')}
                            </h2>
                            <span className="text-[10px] bg-gray-700 text-gray-300 px-2 py-0.5 rounded-full flex-none">
                                {file.involved_files.length} files
                            </span>
                        </div>
                    ) : (
                        <h2 className="text-base font-bold font-mono truncate max-w-sm text-white" title={primaryFile}>
                            {primaryFile}
                        </h2>
                    )}
                    {hasAudited && (
                        <p className="text-xs text-gray-500 mt-0.5">
                            {report.filter(v => v.severity !== 'ERROR').length} finding(s) · {report.filter(v => ['CRITICAL', 'HIGH'].includes(v.severity)).length} critical/high
                        </p>
                    )}
                </div>

                <div className="flex gap-2 flex-none">
                    <button
                        id="tab-audit"
                        onClick={() => setActiveTab('audit')}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-1.5 transition-colors
              ${activeTab === 'audit' ? 'bg-sentry-accent text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
                    >
                        <ShieldAlert size={15} /> Audit
                    </button>

                    <button
                        id="tab-fix"
                        onClick={runFix}
                        disabled={isFixDisabled}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-1.5 transition-colors
              ${activeTab === 'fix' ? 'bg-green-500 text-sentry-dark font-bold' : 'bg-gray-800 text-gray-300'}
              ${isFixDisabled ? 'opacity-40 cursor-not-allowed' : 'hover:bg-gray-700'}`}
                    >
                        <Wrench size={15} /> Fix
                    </button>

                    <button
                        id="tab-chat"
                        onClick={() => setActiveTab('chat')}
                        className={`px-3 py-1.5 rounded text-sm flex items-center gap-1.5 transition-colors
              ${activeTab === 'chat' ? 'bg-blue-500 text-white font-bold' : 'bg-gray-800 text-gray-300 hover:bg-gray-700'}`}
                    >
                        <MessageSquare size={15} /> Chat
                    </button>
                </div>
            </div>

            {/* ── TAB 1: AUDIT ── */}
            {activeTab === 'audit' && (
                <div className="flex-1 overflow-y-auto pr-1 custom-scrollbar flex flex-col">

                    {/* Pre-audit call-to-action */}
                    {!hasAudited && !loading && (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-400 gap-4">
                            <div className="p-5 rounded-2xl bg-gray-800/40 border border-gray-700">
                                <ShieldAlert className="w-12 h-12 opacity-30 mx-auto" />
                            </div>

                            {isBundleMode ? (
                                <div className="text-center space-y-1">
                                    <p className="text-sm text-gray-400">
                                        Ready to audit the <span className="font-semibold text-white capitalize">{bundleName?.replace(/_/g, ' ')}</span> security domain
                                    </p>
                                    <p className="text-xs text-gray-600">
                                        {file.involved_files.join(' · ')}
                                    </p>
                                </div>
                            ) : (
                                <p className="text-sm text-gray-500">
                                    Ready to analyze <span className="font-mono text-white">{primaryFile}</span>
                                </p>
                            )}

                            <button
                                id="run-audit-btn"
                                onClick={runAudit}
                                disabled={Boolean(activeTasks[cacheKey])}
                                className="flex items-center gap-2 bg-sentry-accent text-sentry-dark px-6 py-3 rounded-xl
                           font-bold hover:bg-white transition-all shadow-lg shadow-sentry-accent/20 text-sm
                           disabled:opacity-40 disabled:cursor-not-allowed"
                            >
                                <Play size={16} fill="currentColor" />
                                {isBundleMode ? 'Run Bundle Audit' : 'Run Security Audit'}
                            </button>
                        </div>
                    )}

                    {/* Loading / progress */}
                    {loading && (
                        <div className="flex-1 flex flex-col items-center justify-center gap-6 px-8">
                            {bundleFixProgress && !bundleFixProgress.done ? (
                                /* Sequential bundle-fix progress */
                                <div className="w-full max-w-sm space-y-4">
                                    <div className="flex items-center gap-3">
                                        <Wrench className="w-8 h-8 text-sentry-accent animate-bounce flex-none" />
                                        <div>
                                            <p className="text-sm font-semibold text-white">Fixing security domain…</p>
                                            <p className="text-xs text-gray-400">
                                                File {bundleFixProgress.current} of {bundleFixProgress.total}
                                            </p>
                                        </div>
                                    </div>
                                    <ProgressBar
                                        value={Math.round((bundleFixProgress.current / bundleFixProgress.total) * 100)}
                                        label={bundleFixProgress.currentFile
                                            ? bundleFixProgress.currentFile.split('/').pop()
                                            : 'Starting…'}
                                    />
                                    {bundleFixProgress.currentFile && (
                                        <p className="text-xs font-mono text-gray-500 truncate">
                                            {bundleFixProgress.currentFile}
                                        </p>
                                    )}
                                </div>
                            ) : (
                                /* Regular audit / single-file fix spinner */
                                <>
                                    <Loader2 className="w-10 h-10 text-sentry-accent animate-spin" />
                                    <div className="w-full max-w-xs">
                                        <ProgressBar value={Math.round(progress)} label={progressLabel} />
                                    </div>
                                    <p className="text-xs text-gray-500">
                                        {isBundleMode
                                            ? 'AI is tracing cross-file data flows…'
                                            : 'AI is reading every line of your code…'}
                                    </p>
                                </>
                            )}
                        </div>
                    )}

                    {/* Results */}
                    {hasAudited && !loading && (
                        <div className="space-y-3">
                            {/* Clean state */}
                            {report.filter(v => v.severity !== 'ERROR').length === 0 && applyState !== 'error' && (
                                <div className="flex flex-col items-center text-green-400 py-10 gap-3">
                                    <CheckCircle className="w-16 h-16" />
                                    <h3 className="text-xl font-bold">No Vulnerabilities Found</h3>
                                    <p className="text-gray-500 text-sm">
                                        {isBundleMode ? 'This security domain looks clean.' : 'This file looks secure.'}
                                    </p>
                                </div>
                            )}

                            {/* Apply success banner */}
                            {applyState === 'applied' && downloadUrl && (
                                <div className="flex items-center justify-between bg-green-900/20 border border-green-500/30 rounded-xl p-4">
                                    <div className="flex items-center gap-2 text-green-400">
                                        <CheckCircle size={18} />
                                        <span className="text-sm font-medium">Fix applied! Re-verifying…</span>
                                    </div>
                                    <button
                                        id="download-zip-btn"
                                        onClick={handleDownloadZip}
                                        className="flex items-center gap-1.5 bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded-lg text-xs font-bold transition-colors"
                                    >
                                        <Download size={13} /> Download Fixed ZIP
                                    </button>
                                </div>
                            )}

                            {/* Bundle fix complete banner */}
                            {bundleFixProgress?.done && downloadUrl && (
                                <div className="flex items-center justify-between bg-green-900/20 border border-green-500/30 rounded-xl p-4">
                                    <div className="flex items-center gap-2 text-green-400">
                                        <CheckCircle size={18} />
                                        <div>
                                            <span className="text-sm font-medium">
                                                Domain fixed ({bundleFixProgress.total - bundleFixProgress.errors.length}/{bundleFixProgress.total} files)
                                            </span>
                                            {bundleFixProgress.errors.length > 0 && (
                                                <p className="text-xs text-yellow-400 mt-0.5">
                                                    {bundleFixProgress.errors.length} file(s) had errors — check console
                                                </p>
                                            )}
                                        </div>
                                    </div>
                                    <button
                                        onClick={handleDownloadZip}
                                        className="flex items-center gap-1.5 bg-green-600 hover:bg-green-500 text-white px-3 py-1.5 rounded-lg text-xs font-bold transition-colors"
                                    >
                                        <Download size={13} /> Download Fixed ZIP
                                    </button>
                                </div>
                            )}

                            {/* Bundle mode: Fix Entire Security Domain CTA */}
                            {isBundleMode && report.filter(v => v.severity !== 'ERROR').length > 0 && (
                                <div className="rounded-xl border border-sentry-accent/30 bg-sentry-accent/5 p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                                    <div className="min-w-0">
                                        <p className="text-sm font-semibold text-white flex items-center gap-2">
                                            <Layers size={14} className="text-sentry-accent flex-none" />
                                            Fix Entire Security Domain
                                        </p>
                                        <p className="text-xs text-gray-400 mt-0.5">
                                            Fixes each affected file sequentially — one focused agent call per file, auto-applied. Download the ZIP when complete.
                                        </p>
                                    </div>
                                    <button
                                        id="fix-bundle-btn"
                                        onClick={runBundleFix}
                                        disabled={loading || Boolean(activeTasks[cacheKey])}
                                        className="flex-none flex items-center gap-2 bg-sentry-accent text-sentry-dark px-4 py-2 rounded-lg
                                                   font-bold text-sm hover:bg-white transition-all shadow-lg shadow-sentry-accent/20
                                                   disabled:opacity-40 disabled:cursor-not-allowed"
                                    >
                                        <Wrench size={14} />
                                        Fix Entire Domain
                                    </button>
                                </div>
                            )}

                            {/* Bundle mode: vulnerabilities grouped by file */}
                            {isBundleMode && report.filter(v => v.severity !== 'ERROR').length > 0 && (
                                <BundleResults report={report} />
                            )}

                            {/* Single-file mode: flat vulnerability cards */}
                            {!isBundleMode && report.map((vuln, idx) => (
                                <VulnCard key={idx} vuln={vuln} showFile={true} />
                            ))}
                        </div>
                    )}
                </div>
            )}

            {/* ── TAB 2: FIX ── */}
            {activeTab === 'fix' && (
                <div className="flex-1 flex flex-col min-h-0">
                    {loading ? (
                        <div className="flex-1 flex flex-col items-center justify-center gap-6 px-8">
                            <Wrench className="w-8 h-8 text-green-400 animate-bounce" />
                            <div className="w-full max-w-xs">
                                <ProgressBar value={Math.round(progress)} label={progressLabel} />
                            </div>
                            <p className="text-xs text-gray-500">
                                {isBundleMode
                                    ? 'Generating cross-file security patch…'
                                    : 'Generating minimal surgical patch…'}
                            </p>
                        </div>
                    ) : fixedCode && (
                        <div className="flex-1 bg-[#0d1117] rounded-xl border border-gray-700 overflow-hidden flex flex-col">
                            {/* Toolbar */}
                            <div className="bg-gray-800 px-4 py-2.5 text-xs flex justify-between items-center border-b border-gray-700">
                                <div className="flex items-center gap-2 text-gray-400">
                                    <Wrench size={12} />
                                    <span>
                                        Proposed Patch{isBundleMode ? ` for ${primaryFile}` : ''} — review before applying
                                    </span>
                                    {isBundleMode && (
                                        <span className="text-[10px] bg-yellow-900/40 text-yellow-300 border border-yellow-700/40 px-1.5 py-0.5 rounded">
                                            peer files may also be modified
                                        </span>
                                    )}
                                </div>
                                <div className="flex items-center gap-2">
                                    <button
                                        id="download-file-btn"
                                        onClick={handleDownload}
                                        className="flex items-center gap-1.5 bg-gray-700 hover:bg-gray-600 text-gray-200 px-2.5 py-1 rounded text-xs transition-colors"
                                    >
                                        <Download size={11} /> Download
                                    </button>
                                    <button
                                        id="apply-fix-btn"
                                        onClick={applyFix}
                                        disabled={applyState === 'applying'}
                                        className="flex items-center gap-1.5 bg-green-600 hover:bg-green-500 text-white px-3 py-1 rounded text-xs font-bold transition-colors disabled:opacity-50"
                                    >
                                        {applyState === 'applying'
                                            ? <><Loader2 size={11} className="animate-spin" /> Applying…</>
                                            : <><Save size={11} /> Apply & Re-verify</>
                                        }
                                    </button>
                                </div>
                            </div>

                            {/* Diff viewer */}
                            <div className="flex-1 overflow-auto text-xs font-mono custom-scrollbar py-2">
                                {fixedCode.split('\n').map((line, idx) => {
                                    if (line.startsWith('-') && !line.startsWith('---'))
                                        return <div key={idx} className="bg-red-900/30 text-red-400 px-4 py-0.5 whitespace-pre-wrap border-l-2 border-red-500">{line}</div>;
                                    if (line.startsWith('+') && !line.startsWith('+++'))
                                        return <div key={idx} className="bg-green-900/30 text-green-400 px-4 py-0.5 whitespace-pre-wrap border-l-2 border-green-500">{line}</div>;
                                    if (line.startsWith('@@'))
                                        return <div key={idx} className="bg-blue-900/20 text-blue-400 px-4 py-2 whitespace-pre-wrap font-bold mt-1">{line}</div>;
                                    if (line.startsWith('---') || line.startsWith('+++'))
                                        return <div key={idx} className="text-gray-300 font-bold px-4 py-1 whitespace-pre-wrap">{line}</div>;
                                    return <div key={idx} className="text-gray-500 px-4 py-0.5 whitespace-pre-wrap border-l-2 border-transparent">{line}</div>;
                                })}
                            </div>
                        </div>
                    )}
                </div>
            )}

            {/* ── TAB 3: CHAT ── */}
            {activeTab === 'chat' && (
                <div className="flex-1 flex flex-col min-h-0 bg-gray-900/50 rounded-xl border border-gray-700">
                    <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
                        {chatHistory.length === 0 && (
                            <div className="text-center text-gray-500 mt-10">
                                <Bot className="w-10 h-10 mx-auto mb-3 opacity-40" />
                                <p className="text-sm">Ask anything about <span className="font-mono text-gray-400">{primaryFile}</span></p>
                                <p className="text-xs mt-1 text-gray-600">e.g. "What are the most dangerous lines?" or "How do I fix the SQL injection?"</p>
                            </div>
                        )}
                        {chatHistory.map((msg, i) => (
                            <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                                <div className={`w-7 h-7 rounded-full flex items-center justify-center flex-none text-xs ${msg.role === 'user' ? 'bg-sentry-accent text-sentry-dark' : 'bg-blue-600 text-white'}`}>
                                    {msg.role === 'user' ? <User size={14} /> : <Bot size={14} />}
                                </div>
                                <div className={`p-3 rounded-xl text-sm max-w-[80%] leading-relaxed ${msg.role === 'user' ? 'bg-gray-800 text-white' : 'bg-blue-900/30 text-blue-100 border border-blue-800/30'}`}>
                                    {msg.text}
                                </div>
                            </div>
                        ))}
                        {loading && (
                            <div className="flex gap-3">
                                <div className="w-7 h-7 bg-blue-600 rounded-full flex items-center justify-center"><Bot size={14} /></div>
                                <div className="text-gray-400 text-sm flex items-center gap-2">
                                    <Loader2 size={14} className="animate-spin" /> Thinking…
                                </div>
                            </div>
                        )}
                        <div ref={chatEndRef} />
                    </div>

                    <div className="p-3 border-t border-gray-700 flex gap-2">
                        <input
                            id="chat-input"
                            type="text"
                            value={chatInput}
                            onChange={e => setChatInput(e.target.value)}
                            onKeyDown={e => e.key === 'Enter' && !loading && sendChat()}
                            placeholder="Ask a security question…"
                            disabled={loading}
                            className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-sm text-white
                         placeholder-gray-500 focus:ring-1 focus:ring-sentry-accent focus:border-sentry-accent
                         outline-none transition-all disabled:opacity-50"
                        />
                        <button
                            id="chat-send-btn"
                            onClick={sendChat}
                            disabled={loading || !chatInput.trim()}
                            className="bg-sentry-accent text-sentry-dark p-2 rounded-lg hover:bg-white transition-colors disabled:opacity-40"
                        >
                            <Send size={16} />
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AuditWorkspace;
