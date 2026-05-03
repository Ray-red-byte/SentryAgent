import React, { useState, useEffect, useRef } from 'react';
import api, { tokenStore } from '../api';
import { useTaskContext } from '../context/TaskContext';
import {
    ShieldAlert, Wrench, MessageSquare, Send, User, Bot,
    Play, Loader2, CheckCircle, Download, RefreshCw,
    Info, ChevronRight, ChevronDown, FileText, Layers,
} from 'lucide-react';

import ProgressBar from './audit/ProgressBar';
import VulnCard from './audit/VulnCard';
import BundleResults from './audit/BundleResults';

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
    const [rejectingFile, setRejectingFile] = useState(null);  // filePath being re-generated

    const getInitialCache = () => {
        try {
            const saved = localStorage.getItem(`sentry_session_${sessionId}`);
            return saved ? JSON.parse(saved) : {};
        } catch (e) {
            return {};
        }
    };

    const fileCache = useRef(getInitialCache());
    const currentFileRef = useRef(null);
    const chatEndRef = useRef(null);
    const progressTimerRef = useRef(null);
    // Tracks which domains have in-flight operations to prevent double-launch
    // even when the user switches away (loading state is reset on nav).
    const inFlightRef = useRef({});

    const { activeTasks, startTask, endTask } = useTaskContext();

    // Keep a ref so async loops always read the latest activeTasks (not a stale closure snapshot)
    const activeTasksRef = useRef(activeTasks);
    useEffect(() => { activeTasksRef.current = activeTasks; }, [activeTasks]);

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

    // ── Unified Status Logic ────────────────────────────────────────────────
    const getDerivedStatus = () => {
        if (loading) return 'LOADING';

        if (isBundleMode) {
            if (!hasAudited) return 'UNAUDITED';
            if (!hasFindings) return 'CLEAN';
            if (allResolved) return 'SECURED';
            return 'VULNERABILITIES_FOUND';
        } else {
            if (!parentBundleName) return 'UNAUDITED';
            const pCache = fileCache.current[parentBundleName];
            if (!pCache || !pCache.hasAudited) return 'UNAUDITED';

            if (pCache.resolvedFiles?.[primaryFile]) return 'SECURED';

            const fileFindings = (pCache.report || []).filter(v => v.severity !== 'ERROR' && v.file === primaryFile);
            if (fileFindings.length > 0) return 'VULNERABILITIES_FOUND';

            return 'CLEAN';
        }
    };
    const currentStatus = getDerivedStatus();

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

        // 1. Update the in-memory React cache
        fileCache.current[cacheKey] = {
            report,
            resolvedFiles,
            chatHistory,
            hasAudited,
            downloadUrl
        };

        // 2. Sync to the browser's hard drive so it survives a refresh
        try {
            localStorage.setItem(`sentry_session_${sessionId}`, JSON.stringify(fileCache.current));
        } catch (e) {
            console.error("Failed to save session cache:", e);
        }
    }, [cacheKey, report, resolvedFiles, chatHistory, hasAudited, downloadUrl, sessionId]);

    useEffect(() => {
        chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [chatHistory, activeTab]);

    useEffect(() => () => clearInterval(progressTimerRef.current), []);

    // ── Actions ────────────────────────────────────────────────────────────────

    const runAudit = async () => {
        if (!isBundleMode) return;
        const thisKey = cacheKey;

        // Prevent double-launch per domain even if user has navigated away
        // (loading state gets reset on domain switch, so we need our own guard)
        if (inFlightRef.current[thisKey]) return;
        inFlightRef.current[thisKey] = 'auditing';

        // Update UI only if we are still viewing this domain
        const isActive = () => currentFileRef.current === thisKey;

        if (isActive()) {
            setLoading(true);
            setHasAudited(false);
            setReport([]);
            setResolvedFiles({});
        }

        const label = `AI analyzing ${file.involved_files.length} files in bundle…`;
        startTask(thisKey, 'auditing', label);
        if (isActive()) startProgressAnimation(0, 85, label, 60000);

        try {
            const res = await api.post('/audit', {
                session_id: sessionId,
                file_path: primaryFile,
                bundle_name: bundleName,
                involved_files: file.involved_files,
            });

            const raw = Array.isArray(res.data.report) ? res.data.report : [];
            const findings = raw.filter(v => v.severity !== 'ERROR');
            const finalReport = findings.length > 0 ? findings : raw;

            // Always persist into cache — even if the user has switched domains
            fileCache.current[thisKey] = {
                ...fileCache.current[thisKey],
                report: finalReport,
                hasAudited: true,
            };
            try {
                localStorage.setItem(`sentry_session_${sessionId}`, JSON.stringify(fileCache.current));
            } catch (e) { /* ignore */ }

            // Only touch React state when still viewing this domain
            if (isActive()) {
                setReport(finalReport);
                setHasAudited(true);
                setProgress(100);
                setProgressLabel('Audit complete');
            }
        } catch (err) {
            console.error('Audit failed:', err);
            const errReport = [{ severity: 'ERROR', type: 'Connection Error', description: err.response?.data?.detail || err.message, fix: '' }];

            fileCache.current[thisKey] = {
                ...fileCache.current[thisKey],
                report: errReport,
                hasAudited: true,
            };
            try {
                localStorage.setItem(`sentry_session_${sessionId}`, JSON.stringify(fileCache.current));
            } catch (e) { /* ignore */ }

            if (isActive()) {
                setReport(errReport);
                setHasAudited(true);
            }
        } finally {
            clearInterval(progressTimerRef.current);
            endTask(thisKey);
            delete inFlightRef.current[thisKey];
            if (isActive()) setLoading(false);
        }
    };

    // Sequential bundle fix — runs to completion even if user switches domains
    const runBundleFix = async () => {
        const thisKey = cacheKey;

        // Prevent double-launch per domain
        if (inFlightRef.current[thisKey]) return;
        inFlightRef.current[thisKey] = 'fixing';

        const isActive = () => currentFileRef.current === thisKey;

        const validVulns = report.filter(v => v.severity !== 'ERROR');
        const byFile = {};
        validVulns.forEach(v => {
            const fp = v.file || primaryFile;
            if (!byFile[fp]) byFile[fp] = [];
            byFile[fp].push(v);
        });

        // Skip files already successfully patched (check fileCache, not just state)
        const cachedResolved = fileCache.current[thisKey]?.resolvedFiles || {};
        const fileGroups = Object.entries(byFile).filter(([fp]) => !cachedResolved[fp] && !resolvedFiles[fp]);
        if (fileGroups.length === 0) {
            delete inFlightRef.current[thisKey];
            return;
        }

        if (isActive()) {
            setLoading(true);
            setBundleFixProgress({ total: fileGroups.length, current: 0, currentFile: null, errors: [], skipped: [], done: false });
        }
        startTask(thisKey, 'fixing', `Fixing ${bundleName} domain…`);

        const errors = [];
        const skipped = [];
        // Accumulates patched files so we can write to cache incrementally
        const newlyResolved = {};

        try {
            for (let i = 0; i < fileGroups.length; i++) {
                const [filePath, fileVulns] = fileGroups[i];
                // NOTE: no currentFileRef check here — the loop always runs to completion

                // Another domain's runBundleFix already claimed this file — skip to prevent overwrites.
                // The user can re-run "Fix Entire Domain" after the other domain finishes.
                if (activeTasksRef.current[filePath]) {
                    skipped.push(filePath);
                    if (isActive()) {
                        setBundleFixProgress(prev => ({ ...prev, current: i + 1, skipped: [...skipped] }));
                    }
                    continue;
                }

                if (isActive()) {
                    setBundleFixProgress({ total: fileGroups.length, current: i + 1, currentFile: filePath, errors, skipped, done: false });
                }
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

                    const patchEntry = { patchedCode: fixRes.data.fixed_code };
                    newlyResolved[filePath] = patchEntry;

                    // Always persist into cache — user may have navigated away
                    fileCache.current[thisKey] = {
                        ...fileCache.current[thisKey],
                        resolvedFiles: {
                            ...(fileCache.current[thisKey]?.resolvedFiles || {}),
                            [filePath]: patchEntry,
                        },
                    };
                    try {
                        localStorage.setItem(`sentry_session_${sessionId}`, JSON.stringify(fileCache.current));
                    } catch (e) { /* ignore */ }

                    // Update React state only when still on this domain
                    if (isActive()) {
                        setResolvedFiles(prev => ({ ...prev, [filePath]: patchEntry }));
                    }
                } catch (err) {
                    console.error(`Bundle fix failed for ${filePath}:`, err);
                    errors.push(filePath);
                } finally {
                    endTask(filePath);
                }
            }

            // Persist final download URL into cache
            const downloadUrl = `/v2/download/${sessionId}`;
            fileCache.current[thisKey] = {
                ...fileCache.current[thisKey],
                downloadUrl,
            };
            try {
                localStorage.setItem(`sentry_session_${sessionId}`, JSON.stringify(fileCache.current));
            } catch (e) { /* ignore */ }

            if (isActive()) {
                setBundleFixProgress({ total: fileGroups.length, current: fileGroups.length, currentFile: null, errors, skipped, done: true });
                setDownloadUrl(downloadUrl);
            }
        } finally {
            delete inFlightRef.current[thisKey];
            endTask(thisKey);
            if (isActive()) setLoading(false);
        }
    };

    // ── Reject & Retry a single file ─────────────────────────────────────
    const handleRejectFile = async (filePath, feedback) => {
        if (rejectingFile) return; // prevent concurrent rejections
        setRejectingFile(filePath);

        try {
            // Collect the vulnerabilities for this file from the report
            const fileVulns = report.filter(
                v => v.severity !== 'ERROR' && (v.file || primaryFile) === filePath
            );

            const res = await api.post('/fix/reject', {
                session_id: sessionId,
                file_path: filePath,
                feedback,
                bundle_name: bundleName,
                involved_files: file.involved_files,
                vulnerabilities: fileVulns,
            });

            // Apply the new fix
            const vulnTypes = [...new Set(fileVulns.map(v => v.type).filter(Boolean))].join(', ');
            const topSeverity = fileVulns.find(v => ['CRITICAL', 'HIGH'].includes(v.severity))?.severity || 'MEDIUM';
            await api.post('/apply', {
                session_id: sessionId,
                file_path: filePath,
                fixed_code: res.data.fixed_code,
                vuln_type: vulnTypes || 'Security Fix',
                severity: topSeverity,
                cwe: '',
            });

            // Update resolved state with new patched code
            setResolvedFiles(prev => ({
                ...prev,
                [filePath]: { patchedCode: res.data.fixed_code },
            }));
        } catch (err) {
            console.error(`Reject & retry failed for ${filePath}:`, err);
            alert(`Failed to regenerate fix for ${filePath}: ${err.response?.data?.detail || err.message}`);
        } finally {
            setRejectingFile(null);
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
                    {currentStatus === 'LOADING' && (
                        <span className="text-gray-400 flex items-center justify-center gap-2">
                            <Loader2 size={14} className="animate-spin" />
                            Status: {bundleFixProgress ? `Fixing ${bundleFixProgress.current}/${bundleFixProgress.total}…` : 'Auditing…'}
                        </span>
                    )}
                    {currentStatus === 'UNAUDITED' && (
                        <span className="text-gray-500">Status: Pending Audit 🔍</span>
                    )}
                    {currentStatus === 'CLEAN' && (
                        <span className="text-green-400 font-bold">Status: {isBundleMode ? 'Domain' : 'File'} Clean ✅</span>
                    )}
                    {currentStatus === 'VULNERABILITIES_FOUND' && (
                        <span className="text-orange-400 font-bold">
                            Status: Vulnerabilities Found ⚠️
                            {isBundleMode && (
                                <span className="text-gray-400 text-xs ml-2 font-normal">
                                    ({report.filter(v => v.severity !== 'ERROR').length} findings)
                                </span>
                            )}
                        </span>
                    )}
                    {currentStatus === 'SECURED' && (
                        <span className="text-green-500 font-bold">Status: {isBundleMode ? 'Domain' : 'File'} Secured ✅</span>
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

                        // Resolved state: show ONLY patched source (Header already says Secured)
                        if (currentStatus === 'SECURED') {
                            const filePatchedCode = parentCache?.resolvedFiles?.[primaryFile]?.patchedCode;
                            return (
                                <div className="space-y-4 p-4">
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
                        if (currentStatus === 'VULNERABILITIES_FOUND') {
                            const fileFindings = (parentCache.report || []).filter(v => v.severity !== 'ERROR' && v.file === primaryFile);
                            return (
                                <div className="space-y-2.5 p-4">
                                    {fileFindings.map((vuln, idx) => (
                                        <VulnCard key={idx} vuln={vuln} showFile={false} />
                                    ))}
                                </div>
                            );
                        }

                        // Clean State
                        if (currentStatus === 'CLEAN') {
                            return (
                                <div className="flex flex-col items-center text-green-400 py-10 gap-3">
                                    <CheckCircle className="w-16 h-16" />
                                    <p className="text-gray-500 text-sm">This file looks clean.</p>
                                </div>
                            )
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
                    {isBundleMode && currentStatus === 'UNAUDITED' && (
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
                    {isBundleMode && currentStatus === 'LOADING' && (
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
                    {isBundleMode && (currentStatus === 'VULNERABILITIES_FOUND' || currentStatus === 'SECURED' || currentStatus === 'CLEAN') && (
                        <div className="space-y-3 p-4">
                            {/* No vulnerabilities found */}
                            {currentStatus === 'CLEAN' && (
                                <div className="flex flex-col items-center text-green-400 py-10 gap-3">
                                    <CheckCircle className="w-16 h-16" />
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

                            {/* Skipped files banner — shown when another domain was patching the same file */}
                            {bundleFixProgress?.done && bundleFixProgress.skipped?.length > 0 && (
                                <div className="flex items-start gap-3 bg-blue-900/20 border border-blue-500/30 rounded-xl p-3 text-sm">
                                    <span className="text-blue-400 mt-0.5">ℹ</span>
                                    <p className="text-blue-300">
                                        {bundleFixProgress.skipped.length} file{bundleFixProgress.skipped.length !== 1 ? 's were' : ' was'} skipped — already being patched by another domain. Run <strong>Fix Entire Domain</strong> again once the other domain finishes.
                                    </p>
                                </div>
                            )}

                            {/* Per-file findings with resolved state */}
                            {(currentStatus === 'VULNERABILITIES_FOUND' || currentStatus === 'SECURED') && (
                                <BundleResults
                                    report={report}
                                    resolvedFiles={resolvedFiles}
                                    onRejectFile={handleRejectFile}
                                    rejectingFile={rejectingFile}
                                />
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