import React, { useState, useEffect, useRef } from 'react';
import api, { tokenStore } from '../api';
import { useTaskContext } from '../context/TaskContext';
import {
    ShieldAlert, Wrench, MessageSquare, Send, User, Bot,
    Play, Loader2, CheckCircle, Download, RefreshCw,
    Info, ChevronRight, ChevronDown, FileText, Layers,
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

// ── Bundle results: findings grouped by file, with per-file resolved state ──
function BundleResults({ report, resolvedFiles = {} }) {
    const [expandedFiles, setExpandedFiles] = useState({});

    const grouped = report
        .filter(v => v.severity !== 'ERROR')
        .reduce((acc, vuln) => {
            const key = vuln.file || 'Unknown File';
            if (!acc[key]) acc[key] = [];
            acc[key].push(vuln);
            return acc;
        }, {});

    const sortedFiles = Object.entries(grouped).sort(([aFp, aVulns], [bFp, bVulns]) => {
        // Resolved files sink to the bottom
        const aResolved = Boolean(resolvedFiles[aFp]);
        const bResolved = Boolean(resolvedFiles[bFp]);
        if (aResolved !== bResolved) return aResolved ? 1 : -1;
        const worstIdx = (vulns) =>
            Math.min(...vulns.map(v => SEVERITY_ORDER.indexOf(v.severity?.toUpperCase() || 'INFO')));
        return worstIdx(aVulns) - worstIdx(bVulns);
    });

    const toggleFile = (fp) =>
        setExpandedFiles(prev => ({ ...prev, [fp]: !prev[fp] }));

    useEffect(() => {
        const init = {};
        sortedFiles.forEach(([fp]) => { init[fp] = true; });
        setExpandedFiles(init);
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [report]);

    if (sortedFiles.length === 0) return null;

    return (
        <div className="space-y-2.5">
            {sortedFiles.map(([filePath, vulns]) => {
                const isResolved = Boolean(resolvedFiles[filePath]);
                const patchedCode = resolvedFiles[filePath]?.patchedCode;
                const worstSeverity = isResolved
                    ? null
                    : SEVERITY_ORDER.find(s => vulns.some(v => v.severity?.toUpperCase() === s)) || 'INFO';
                const isOpen = expandedFiles[filePath] !== false;

                return (
                    <div
                        key={filePath}
                        className={`rounded-xl border overflow-hidden transition-colors ${isResolved ? 'border-green-500/30' : 'border-gray-700'
                            }`}
                    >
                        {/* File header row */}
                        <button
                            onClick={() => toggleFile(filePath)}
                            className={`w-full flex items-center gap-2.5 px-4 py-2.5 transition-colors text-left ${isResolved
                                ? 'bg-green-900/20 hover:bg-green-900/30'
                                : 'bg-gray-800/60 hover:bg-gray-800'
                                }`}
                        >
                            {isOpen
                                ? <ChevronDown size={13} className="flex-none text-gray-400" />
                                : <ChevronRight size={13} className="flex-none text-gray-400" />
                            }
                            <FileText size={13} className={`flex-none ${isResolved ? 'text-green-400' : 'text-gray-400'}`} />
                            <span className={`font-mono text-xs truncate flex-1 ${isResolved ? 'text-green-200' : 'text-gray-200'}`}>
                                {filePath}
                            </span>
                            <div className="flex items-center gap-2 flex-none">
                                {isResolved ? (
                                    <span className="text-[10px] text-green-400 font-bold flex items-center gap-1">
                                        <CheckCircle size={10} /> Secured
                                    </span>
                                ) : (
                                    <>
                                        <span className="text-[10px] text-gray-500">
                                            {vulns.length} finding{vulns.length !== 1 ? 's' : ''}
                                        </span>
                                        <SeverityBadge severity={worstSeverity} />
                                    </>
                                )}
                            </div>
                        </button>

                        {/* Expanded body */}
                        {isOpen && (
                            isResolved ? (
                                <div className="p-4 bg-green-900/10 space-y-3">
                                    <div className="flex items-center gap-2 text-green-400 text-sm font-medium">
                                        <CheckCircle size={15} />
                                        <span>
                                            Patch applied — {vulns.length} {vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} resolved
                                        </span>
                                    </div>
                                    {patchedCode && (
                                        <>
                                            <p className="text-xs text-gray-500">Patched source:</p>
                                            <pre className="text-xs font-mono bg-gray-950/70 border border-green-900/30 rounded-lg p-3 overflow-x-auto text-green-100/70 max-h-72 overflow-y-auto custom-scrollbar">
                                                {patchedCode}
                                            </pre>
                                        </>
                                    )}
                                </div>
                            ) : (
                                <div className="p-3 space-y-2.5 bg-gray-900/30">
                                    {vulns.map((vuln, idx) => (
                                        <VulnCard key={idx} vuln={vuln} showFile={false} />
                                    ))}
                                </div>
                            )
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
    const [resolvedFiles, setResolvedFiles] = useState({});
    const [chatHistory, setChatHistory] = useState([]);
    const [chatInput, setChatInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [activeTab, setActiveTab] = useState('audit');
    const [hasAudited, setHasAudited] = useState(false);
    const [downloadUrl, setDownloadUrl] = useState(null);
    const [progress, setProgress] = useState(0);
    const [progressLabel, setProgressLabel] = useState('');
    const [bundleFixProgress, setBundleFixProgress] = useState(null);

    const fileCache = useRef({});
    const currentFileRef = useRef(null);
    const chatEndRef = useRef(null);
    const progressTimerRef = useRef(null);

    const { activeTasks, startTask, endTask } = useTaskContext();

    // ── Derived values ──────────────────────────────────────────────────────
    const isBundleMode = Boolean(file?.bundleName);
    const bundleName = file?.bundleName;
    const parentBundleName = file?.parentBundleName;
    const cacheKey = bundleName || file?.file || file?.file_path;
    const primaryFile = file?.file || file?.file_path;

    const hasFindings = report.filter(v => v.severity !== 'ERROR').length > 0;

    // All unique files that have findings
    const filesWithFindings = isBundleMode
        ? [...new Set(report.filter(v => v.severity !== 'ERROR').map(v => v.file || primaryFile))]
        : [];

    // True when every file that had a finding has been resolved
    const allResolved =
        hasFindings &&
        filesWithFindings.length > 0 &&
        filesWithFindings.every(fp => Boolean(resolvedFiles[fp]));

    // ── Progress animation ──────────────────────────────────────────────────
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

    // ── Cache restore/persist ───────────────────────────────────────────────
    useEffect(() => {
        if (!cacheKey) return;
        currentFileRef.current = cacheKey;
        clearInterval(progressTimerRef.current);

        const cached = fileCache.current[cacheKey];
        if (cached) {
            setReport(cached.report ?? []);
            setResolvedFiles(cached.resolvedFiles ?? {});
            setChatHistory(cached.chatHistory ?? []);
            setHasAudited(cached.hasAudited ?? false);
            setDownloadUrl(cached.downloadUrl ?? null);
        } else {
            setReport([]);
            setResolvedFiles({});
            setChatHistory([]);
            setHasAudited(false);
            setDownloadUrl(null);
        }
        setLoading(false);
        setActiveTab('audit');
        setProgress(0);
        setProgressLabel('');
        setBundleFixProgress(null);
    }, [cacheKey]);

    useEffect(() => {
        if (!cacheKey) return;
        fileCache.current[cacheKey] = { report, resolvedFiles, chatHistory, hasAudited, downloadUrl };
    }, [cacheKey, report, resolvedFiles, chatHistory, hasAudited, downloadUrl]);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatHistory, activeTab]);

    useEffect(() => () => clearInterval(progressTimerRef.current), []);

    // ── Actions ────────────────────────────────────────────────────────────────

    const runAudit = async () => {
        if (!isBundleMode || loading || activeTasks[cacheKey]) return;
        const thisKey = cacheKey;
        setLoading(true);
        setHasAudited(false);
        setReport([]);
        setResolvedFiles({});

        const label = `AI analyzing ${file.involved_files.length} files in bundle…`;
        startTask(thisKey, 'auditing', label);
        startProgressAnimation(0, 85, label, 60000);

        try {
            const res = await api.post('/audit', {
                session_id: sessionId,
                file_path: primaryFile,
                bundle_name: bundleName,
                involved_files: file.involved_files,
            });
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

    // Sequential bundle fix — skips already-resolved files on retry
    const runBundleFix = async () => {
        if (loading || activeTasks[cacheKey]) return;
        const thisKey = cacheKey;

        const validVulns = report.filter(v => v.severity !== 'ERROR');
        const byFile = {};
        validVulns.forEach(v => {
            const fp = v.file || primaryFile;
            if (!byFile[fp]) byFile[fp] = [];
            byFile[fp].push(v);
        });

        // Skip files that were already successfully patched
        const fileGroups = Object.entries(byFile).filter(([fp]) => !resolvedFiles[fp]);
        if (fileGroups.length === 0) return;

        setLoading(true);
        setBundleFixProgress({ total: fileGroups.length, current: 0, currentFile: null, errors: [], done: false });
        startTask(thisKey, 'fixing', `Fixing ${bundleName} domain…`);

        const errors = [];
        try {
            for (let i = 0; i < fileGroups.length; i++) {
                const [filePath, fileVulns] = fileGroups[i];
                if (currentFileRef.current !== thisKey) break;

                setBundleFixProgress({ total: fileGroups.length, current: i + 1, currentFile: filePath, errors, done: false });
                startTask(filePath, 'fixing', `Fixing ${filePath}…`);

                try {
                    const fixRes = await api.post('/fix', {
                        session_id: sessionId,
                        file_path: filePath,
                        bundle_name: bundleName,
                        involved_files: file.involved_files,
                        vulnerabilities: fileVulns,
                    });

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

                    // Mark file as resolved and store the patched source for display
                    setResolvedFiles(prev => ({
                        ...prev,
                        [filePath]: { patchedCode: fixRes.data.fixed_code },
                    }));
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
        } finally {
            setLoading(false);
            endTask(thisKey);
        }
    };

    const handleDownloadZip = () => {
        const token = tokenStore.get();
        fetch(`http://localhost:8000/v2/download/${sessionId}`, {
            headers: { Authorization: `Bearer ${token}` },
        })
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

    // ── Single-file state badge ────────
    const singleFileStateBadge = !isBundleMode && parentBundleName
        ? (() => {
            const parentCache = fileCache.current[parentBundleName];
            if (parentCache?.resolvedFiles?.[primaryFile]) {
                return (
                    <span className="text-[11px] text-green-400 bg-green-900/20 border border-green-500/30 px-2.5 py-1 rounded-full flex items-center gap-1 flex-none">
                        <CheckCircle size={11} /> File Secured ✓
                    </span>
                );
            }
            if (parentCache?.hasAudited) {
                const ff = (parentCache.report || []).filter(v => v.severity !== 'ERROR' && v.file === primaryFile);
                if (ff.length > 0) {
                    return (
                        <span className="text-[11px] text-orange-300 bg-orange-900/20 border border-orange-500/30 px-2.5 py-1 rounded-full flex-none">
                            {ff.length} finding{ff.length !== 1 ? 's' : ''}
                        </span>
                    );
                }
            }
            return null;
        })()
        : null;

    // ── Render ─────────────────────────────────────────────────────────────────
    return (
        <div className="relative h-full flex flex-col min-h-0">

            {/* Background task overlay */}
            {!loading && activeTasks[cacheKey] && (
                <div className="absolute inset-0 z-10 flex flex-col items-center justify-center bg-gray-950/80 backdrop-blur-sm rounded-xl">
                    <Loader2 className="w-10 h-10 text-sentry-accent animate-spin mb-3" />
                    <p className="text-sm font-semibold text-white capitalize">
                        {activeTasks[cacheKey].label || `${activeTasks[cacheKey].type}…`}
                    </p>
                    <p className="text-xs text-gray-400 mt-1">Running in background…</p>
                </div>
            )}

            {/* =========================================
                LEVEL 1: The State Header (Top)
            ========================================= */}
            <div className="flex-none p-6 border-b border-gray-700 bg-gray-900/40 text-center">
                <div className="flex items-center justify-center gap-3 mb-2">
                    {isBundleMode ? (
                        <>
                            <Layers className="text-sentry-accent" size={24} />
                            <h2 className="text-2xl font-bold text-white capitalize">
                                {bundleName?.replace(/_/g, ' ')} Domain
                            </h2>
                        </>
                    ) : (
                        <>
                            <FileText className="text-gray-400" size={24} />
                            <h2 className="text-2xl font-bold font-mono text-white">
                                {primaryFile}
                            </h2>
                        </>
                    )}
                </div>

                {/* Dynamic Status Badge (Centered) */}
                <div className="text-sm mt-2">
                    {loading && (
                        <span className="text-gray-400 flex items-center justify-center gap-2">
                            <Loader2 size={14} className="animate-spin" />
                            Status: {bundleFixProgress ? `Fixing ${bundleFixProgress.current}/${bundleFixProgress.total}…` : 'Auditing…'}
                        </span>
                    )}
                    {!loading && !hasAudited && (
                        <span className="text-gray-500">Status: Pending Audit 🔍</span>
                    )}
                    {!loading && hasAudited && !hasFindings && (
                        <span className="text-green-400 font-bold">Status: Domain Clean ✅</span>
                    )}
                    {!loading && hasAudited && hasFindings && !allResolved && (
                        <span className="text-orange-400 font-bold">
                            Status: Vulnerabilities Found ⚠️
                            <span className="text-gray-400 text-xs ml-2 font-normal">
                                ({report.filter(v => v.severity !== 'ERROR').length} findings)
                            </span>
                        </span>
                    )}
                    {!loading && allResolved && (
                        <span className="text-green-500 font-bold">Status: Domain Secured ✅</span>
                    )}

                    {/* Single File Status Override */}
                    {!isBundleMode && singleFileStateBadge && !loading && (
                        <div className="mt-2 flex justify-center">{singleFileStateBadge}</div>
                    )}
                </div>
            </div>

            {/* =========================================
                LEVEL 2: Action Buttons (Middle)
            ========================================= */}
            <div className="flex-none flex justify-center items-center gap-3 p-4 bg-gray-800/30 border-b border-gray-700">
                {isBundleMode ? (
                    <>
                        {/* STATE 1: Not yet audited */}
                        {!hasAudited && !loading && (
                            <button
                                onClick={() => { setActiveTab('audit'); runAudit(); }}
                                disabled={Boolean(activeTasks[cacheKey])}
                                className="px-6 py-2.5 rounded-lg text-sm flex items-center gap-2 transition-colors bg-blue-600 text-white font-bold hover:bg-blue-500 shadow-lg"
                            >
                                <ShieldAlert size={16} /> Run Domain Audit
                            </button>
                        )}

                        {/* STATE 2: Audited with unfixed findings */}
                        {hasAudited && hasFindings && !allResolved && !loading && (
                            <button
                                onClick={runBundleFix}
                                disabled={Boolean(activeTasks[cacheKey])}
                                className="px-6 py-2.5 rounded-lg text-sm flex items-center gap-2 transition-colors bg-orange-500 text-white font-bold hover:bg-orange-400 shadow-lg"
                            >
                                <Wrench size={16} /> Fix Entire Domain
                            </button>
                        )}

                        {/* STATE 3: Clean domain — offer re-audit */}
                        {hasAudited && !hasFindings && !loading && (
                            <button
                                onClick={() => { setActiveTab('audit'); runAudit(); }}
                                className="px-6 py-2.5 rounded-lg text-sm flex items-center gap-2 bg-gray-700 text-gray-300 hover:bg-gray-600"
                            >
                                <RefreshCw size={16} /> Re-audit Domain
                            </button>
                        )}

                        {/* STATE 4: All resolved — download */}
                        {allResolved && !loading && downloadUrl && (
                            <button
                                onClick={handleDownloadZip}
                                className="px-6 py-2.5 rounded-lg text-sm flex items-center gap-2 bg-green-600 text-white font-bold hover:bg-green-500 shadow-lg"
                            >
                                <Download size={16} /> Download Secured Codebase
                            </button>
                        )}
                    </>
                ) : (
                    /* Single File Read-Only Tab Toggles */
                    <div className="flex gap-2">
                        <button
                            onClick={() => setActiveTab('audit')}
                            className={`px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition-colors ${activeTab === 'audit' ? 'bg-gray-700 text-white font-bold' : 'bg-transparent text-gray-400 hover:bg-gray-800'}`}
                        >
                            <ShieldAlert size={16} /> Vulnerability Report
                        </button>
                        <button
                            onClick={() => setActiveTab('chat')}
                            className={`px-4 py-2 rounded-lg text-sm flex items-center gap-2 transition-colors ${activeTab === 'chat' ? 'bg-blue-600 text-white font-bold' : 'bg-transparent text-gray-400 hover:bg-gray-800'}`}
                        >
                            <MessageSquare size={16} /> Chat with AI
                        </button>
                    </div>
                )}
            </div>

            {/* =========================================
                LEVEL 3: Content (Bottom)
            ========================================= */}
            {activeTab === 'audit' && (
                <div className="flex-1 overflow-y-auto pr-1 custom-scrollbar flex flex-col">

                    {/* ── Single-file view ── */}
                    {!isBundleMode && (() => {
                        const parentCache = parentBundleName ? fileCache.current[parentBundleName] : null;
                        const parentAudited = Boolean(parentCache?.hasAudited);
                        const parentResolvedFiles = parentCache?.resolvedFiles || {};
                        const isFileResolved = Boolean(parentResolvedFiles[primaryFile]);
                        const filePatchedCode = parentResolvedFiles[primaryFile]?.patchedCode;
                        const fileFindings = parentAudited && !isFileResolved
                            ? (parentCache.report || []).filter(v => v.severity !== 'ERROR' && v.file === primaryFile)
                            : [];

                        // Resolved state: show secured banner + patched source
                        if (isFileResolved) {
                            return (
                                <div className="space-y-4">
                                    <div className="flex flex-col items-center text-green-400 py-8 gap-3">
                                        <CheckCircle className="w-14 h-14" />
                                        <h3 className="text-lg font-bold">File Secured</h3>
                                        <p className="text-gray-500 text-sm text-center max-w-xs">
                                            Patch was applied successfully as part of the{' '}
                                            <span className="text-white capitalize">{parentBundleName?.replace(/_/g, ' ')}</span> domain fix.
                                        </p>
                                    </div>
                                    {filePatchedCode && (
                                        <div>
                                            <p className="text-xs text-gray-500 mb-1.5">Patched source:</p>
                                            <pre className="text-xs font-mono bg-gray-950/70 border border-green-900/30 rounded-lg p-3 overflow-x-auto text-green-100/70 max-h-96 overflow-y-auto custom-scrollbar">
                                                {filePatchedCode}
                                            </pre>
                                        </div>
                                    )}
                                </div>
                            );
                        }

                        // Audited state: show filtered findings
                        if (parentAudited) {
                            return fileFindings.length > 0 ? (
                                <div className="space-y-2.5 p-4">
                                    {fileFindings.map((vuln, idx) => (
                                        <VulnCard key={idx} vuln={vuln} showFile={false} />
                                    ))}
                                </div>
                            ) : (
                                <div className="flex flex-col items-center text-green-400 py-10 gap-3">
                                    <CheckCircle className="w-16 h-16" />
                                    <h3 className="text-xl font-bold">No Vulnerabilities Found</h3>
                                    <p className="text-gray-500 text-sm">This file looks clean.</p>
                                </div>
                            );
                        }

                        // Not yet audited: guidance panel
                        return (
                            <div className="flex-1 flex flex-col items-center justify-center text-gray-400 gap-4">
                                <div className="p-5 rounded-2xl bg-gray-800/40 border border-gray-700">
                                    <ShieldAlert className="w-12 h-12 opacity-30 mx-auto" />
                                </div>
                                <div className="text-center space-y-2 max-w-xs">
                                    <p className="text-sm font-mono text-white">{primaryFile}</p>
                                    {file?.risk_score > 0 && (
                                        <p className="text-xs text-gray-500">
                                            Risk score: <span className="text-red-300 font-bold">{file.risk_score}</span>
                                        </p>
                                    )}
                                    <p className="text-xs text-gray-500 mt-3 leading-relaxed">
                                        Click the <span className="text-white font-semibold">Run Domain Audit</span> button for the parent domain to analyze this file.
                                    </p>
                                </div>
                            </div>
                        );
                    })()}

                    {/* ── Bundle mode: pre-audit CTA ── */}
                    {isBundleMode && !hasAudited && !loading && (
                        <div className="flex-1 flex flex-col items-center justify-center text-gray-400 gap-4">
                            <div className="p-5 rounded-2xl bg-gray-800/40 border border-gray-700">
                                <ShieldAlert className="w-12 h-12 opacity-30 mx-auto" />
                            </div>
                            <div className="text-center space-y-1">
                                <p className="text-sm text-gray-400">
                                    Ready to audit the{' '}
                                    <span className="font-semibold text-white capitalize">{bundleName?.replace(/_/g, ' ')}</span>{' '}
                                    security domain
                                </p>
                                <p className="text-xs text-gray-600">{file.involved_files.join(' · ')}</p>
                            </div>
                        </div>
                    )}

                    {/* ── Bundle mode: loading/progress ── */}
                    {isBundleMode && loading && (
                        <div className="flex-1 flex flex-col items-center justify-center gap-6 px-8 py-10">
                            {bundleFixProgress && !bundleFixProgress.done ? (
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
                                <>
                                    <Loader2 className="w-10 h-10 text-sentry-accent animate-spin" />
                                    <div className="w-full max-w-xs">
                                        <ProgressBar value={Math.round(progress)} label={progressLabel} />
                                    </div>
                                    <p className="text-xs text-gray-500">AI is tracing cross-file data flows…</p>
                                </>
                            )}
                        </div>
                    )}

                    {/* ── Bundle mode: results ── */}
                    {isBundleMode && hasAudited && !loading && (
                        <div className="space-y-3 p-4">
                            {/* No vulnerabilities found */}
                            {!hasFindings && (
                                <div className="flex flex-col items-center text-green-400 py-10 gap-3">
                                    <CheckCircle className="w-16 h-16" />
                                    <h3 className="text-xl font-bold">No Vulnerabilities Found</h3>
                                    <p className="text-gray-500 text-sm">This security domain looks clean.</p>
                                </div>
                            )}

                            {/* Partial errors banner — only shown when some files failed during fix */}
                            {bundleFixProgress?.done && bundleFixProgress.errors.length > 0 && (
                                <div className="flex items-center gap-3 bg-yellow-900/20 border border-yellow-500/30 rounded-xl p-3 text-sm">
                                    <span className="text-yellow-400">⚠</span>
                                    <p className="text-yellow-300">
                                        {bundleFixProgress.errors.length} file{bundleFixProgress.errors.length !== 1 ? 's' : ''} failed — click <strong>Fix Entire Domain</strong> to retry.
                                    </p>
                                </div>
                            )}

                            {/* Per-file findings with resolved state */}
                            {hasFindings && (
                                <BundleResults report={report} resolvedFiles={resolvedFiles} />
                            )}
                        </div>
                    )}
                </div>
            )}

            {/* ── TAB: CHAT ── */}
            {activeTab === 'chat' && (
                <div className="flex-1 flex flex-col min-h-0 bg-gray-900/50 rounded-xl border border-gray-700 m-4">
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