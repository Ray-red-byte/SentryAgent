import React from 'react';
import { ChevronRight, Info } from 'lucide-react';
import SeverityBadge from './SeverityBadge';
import { SEVERITY_STYLES, SEVERITY_DOT } from './severity';

export default function VulnCard({ vuln, showFile = false }) {
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
