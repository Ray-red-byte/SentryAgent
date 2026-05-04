import { useState, useEffect } from 'react';
import { TrendingUp } from 'lucide-react';
import { fetchSessionCost } from '../../api';

const NTD_RATE = 32; // 1 USD ≈ 32 NTD (approximate)

const SOURCE_BADGE = {
    redis:    'bg-orange-900/50 text-orange-300 border border-orange-700/60',
    postgres: 'bg-blue-900/50  text-blue-300  border border-blue-700/60',
};

/**
 * One-shot cost metrics card anchored to the bottom of the left sidebar.
 * Fetches cost exactly once on mount; re-fetches if sessionId changes.
 *
 * Props:
 *   sessionId — current session UUID
 */
export default function SessionCostSummary({ sessionId }) {
    const [data,  setData]  = useState(null);
    const [error, setError] = useState(false);

    useEffect(() => {
        if (!sessionId) return;
        setData(null);
        setError(false);

        // Delay the fetch by 1 s so sync_cost_to_db has time to commit
        // before we read from Postgres. Without this, the summary can
        // race the POST endpoint's final DB write and show stale data.
        const timer = setTimeout(() => {
            fetchSessionCost(sessionId)
                .then(setData)
                .catch(() => setError(true));
        }, 1000);

        return () => clearTimeout(timer);
    }, [sessionId]);

    // Hide while loading or on unrecoverable error
    if (!data) return null;

    const usd    = data.cost_usd;
    const ntd    = (usd * NTD_RATE).toFixed(2);
    const source = data.source ?? 'postgres';
    const badgeCls = SOURCE_BADGE[source] ?? SOURCE_BADGE.postgres;

    return (
        <div className="border-t border-gray-700/60 p-3 bg-gray-800/30">

            {/* Card header */}
            <div className="flex items-center justify-between mb-2.5">
                <div className="flex items-center gap-1.5">
                    <TrendingUp size={11} className="text-sentry-accent" />
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-400">
                        Session Cost
                    </span>
                </div>

                {/* Colored source badge */}
                <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${badgeCls}`}>
                    {source}
                </span>
            </div>

            {/* Primary USD figure */}
            <div className="flex items-baseline gap-1 mb-1">
                <span className="text-[11px] text-sentry-accent font-mono leading-none">$</span>
                <span className="text-lg font-bold font-mono tabular-nums text-white leading-none">
                    {usd.toFixed(5)}
                </span>
                <span className="text-[10px] text-gray-500 ml-0.5">USD</span>
            </div>

            {/* NTD conversion */}
            <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-700/40">
                <span className="text-[10px] text-gray-500">≈ NT$</span>
                <span className="font-mono text-[10px] tabular-nums text-gray-300 font-semibold">
                    {ntd}
                </span>
            </div>
            <p className="text-[9px] text-gray-600 mt-1">1 USD ≈ {NTD_RATE} NTD (est.)</p>

        </div>
    );
}
