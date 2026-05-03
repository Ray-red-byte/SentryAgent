import React, { useState, useEffect } from 'react';
import { ChevronRight, ChevronDown, FileText, CheckCircle, RotateCcw, Send, Loader2 } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import VulnCard from './VulnCard';
import { SEVERITY_ORDER } from './severity';

export default function BundleResults({ report, resolvedFiles = {}, onRejectFile, rejectingFile }) {
    const [expandedFiles, setExpandedFiles] = useState({});
    const [rejectFeedback, setRejectFeedback] = useState({});   // { [filePath]: string }
    const [showRejectForm, setShowRejectForm] = useState({});    // { [filePath]: bool }

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

    const handleRejectClick = (filePath) => {
        setShowRejectForm(prev => ({ ...prev, [filePath]: !prev[filePath] }));
    };

    const handleSubmitReject = (filePath) => {
        const feedback = (rejectFeedback[filePath] || '').trim();
        if (!feedback) return;
        if (onRejectFile) {
            onRejectFile(filePath, feedback);
        }
        // Clear form after submission (the parent will update resolvedFiles when done)
        setShowRejectForm(prev => ({ ...prev, [filePath]: false }));
        setRejectFeedback(prev => ({ ...prev, [filePath]: '' }));
    };

    if (sortedFiles.length === 0) return null;

    return (
        <div className="space-y-2.5">
            {sortedFiles.map(([filePath, vulns]) => {
                const isResolved = Boolean(resolvedFiles[filePath]);
                const patchedCode = resolvedFiles[filePath]?.patchedCode;
                const isRejecting = rejectingFile === filePath;
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
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-2 text-green-400 text-sm font-medium">
                                            <CheckCircle size={15} />
                                            <span>
                                                Patch applied — {vulns.length} {vulns.length === 1 ? 'vulnerability' : 'vulnerabilities'} resolved
                                            </span>
                                        </div>
                                        {/* Reject & Retry button */}
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleRejectClick(filePath); }}
                                            disabled={isRejecting}
                                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors bg-orange-500/15 text-orange-400 hover:bg-orange-500/25 border border-orange-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                                        >
                                            {isRejecting ? (
                                                <><Loader2 size={12} className="animate-spin" /> Regenerating…</>
                                            ) : (
                                                <><RotateCcw size={12} /> Reject &amp; Retry</>
                                            )}
                                        </button>
                                    </div>

                                    {/* Reject feedback form */}
                                    {showRejectForm[filePath] && !isRejecting && (
                                        <div className="rounded-lg border border-orange-500/30 bg-orange-950/20 p-3 space-y-2">
                                            <p className="text-xs text-orange-300 font-medium">
                                                What should the fix do differently?
                                            </p>
                                            <textarea
                                                value={rejectFeedback[filePath] || ''}
                                                onChange={(e) => setRejectFeedback(prev => ({ ...prev, [filePath]: e.target.value }))}
                                                placeholder={`e.g. "Use argon2id instead of bcrypt" or "Don't remove the logging statement"`}
                                                className="w-full bg-gray-900/70 border border-gray-700 rounded-lg p-2.5 text-xs text-gray-200 placeholder-gray-500 resize-none focus:outline-none focus:border-orange-500/50"
                                                rows={3}
                                            />
                                            <div className="flex justify-end gap-2">
                                                <button
                                                    onClick={() => setShowRejectForm(prev => ({ ...prev, [filePath]: false }))}
                                                    className="px-3 py-1.5 rounded-lg text-xs text-gray-400 hover:text-gray-200 transition-colors"
                                                >
                                                    Cancel
                                                </button>
                                                <button
                                                    onClick={() => handleSubmitReject(filePath)}
                                                    disabled={!(rejectFeedback[filePath] || '').trim()}
                                                    className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-xs font-medium bg-orange-500 text-white hover:bg-orange-400 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                                                >
                                                    <Send size={11} /> Regenerate
                                                </button>
                                            </div>
                                        </div>
                                    )}

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
