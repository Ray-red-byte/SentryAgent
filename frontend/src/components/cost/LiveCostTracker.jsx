import { useState, useEffect, useRef } from 'react';
import { DollarSign } from 'lucide-react';
import { API_BASE_URL, tokenStore } from '../../api';

/**
 * Connects to GET /v2/status/{sessionId} (SSE) when isActive is true.
 * Reads cost_usd from each event and flashes green whenever the value increases.
 * Closes the SSE stream when isActive becomes false or the component unmounts.
 *
 * Uses native fetch + ReadableStream — no extra npm package required.
 * JWT is attached via the Authorization header (EventSource can't do this).
 *
 * Props:
 *   sessionId — current session UUID
 *   isActive  — true while any audit / fix / scan task is running
 */
export default function LiveCostTracker({ sessionId, isActive }) {
    const [cost,  setCost]  = useState(null);
    const [flash, setFlash] = useState(false);
    const flashTimer        = useRef(null);

    useEffect(() => {
        if (!isActive || !sessionId) return;

        const controller = new AbortController();

        (async () => {
            try {
                const resp = await fetch(`${API_BASE_URL}/status/${sessionId}`, {
                    headers: { Authorization: `Bearer ${tokenStore.get()}` },
                    signal:  controller.signal,
                });

                if (!resp.ok || !resp.body) return;

                const reader  = resp.body.getReader();
                const decoder = new TextDecoder();
                let   buffer  = '';

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    // Accumulate chunks — SSE boundaries may not align with fetch chunks
                    buffer += decoder.decode(value, { stream: true });

                    // Split on the SSE message delimiter (\n\n)
                    const messages = buffer.split('\n\n');
                    buffer = messages.pop(); // last element is the incomplete trailing chunk

                    for (const message of messages) {
                        const dataLine = message
                            .split('\n')
                            .find(l => l.startsWith('data: '));
                        if (!dataLine) continue;

                        let payload;
                        try {
                            payload = JSON.parse(dataLine.slice(6));
                        } catch {
                            continue; // malformed JSON — skip
                        }

                        // Update cost and flash green on increase
                        if (typeof payload.cost_usd === 'number') {
                            setCost(prev => {
                                if (prev !== null && payload.cost_usd > prev) {
                                    clearTimeout(flashTimer.current);
                                    setFlash(true);
                                    flashTimer.current = setTimeout(
                                        () => setFlash(false),
                                        500,
                                    );
                                }
                                return payload.cost_usd;
                            });
                        }

                        // Server signals end of stream
                        if (payload.stage === 'complete' || payload.stage === 'error') {
                            controller.abort();
                            return;
                        }
                    }
                }
            } catch (err) {
                if (err.name !== 'AbortError') {
                    console.warn('[LiveCostTracker] SSE error:', err.message);
                }
            }
        })();

        return () => {
            controller.abort();
            clearTimeout(flashTimer.current);
        };
    }, [sessionId, isActive]);

    // Nothing to show yet (SSE hasn't fired its first cost event)
    if (cost === null) return null;

    return (
        <div
            className={`flex items-center gap-2 rounded-lg px-3 py-1.5 border
                        transition-colors duration-300
                        ${flash
                            ? 'bg-green-900/30 border-green-700'
                            : 'bg-gray-800 border-gray-700'
                        }`}
            title={`Accumulated LLM cost — session ${sessionId?.slice(0, 8)}`}
        >
            {/* Indicator: pulsing red dot when live, static dollar when idle */}
            {isActive
                ? <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse flex-none" />
                : <DollarSign size={12} className="text-sentry-accent flex-none" />
            }

            {/* Cost label */}
            <span
                className={`font-mono text-xs tabular-nums transition-colors duration-300
                            ${flash ? 'text-green-300' : 'text-gray-300'}`}
            >
                API Cost:{' '}
                <span className="font-semibold">${cost.toFixed(5)}</span>{' '}
                <span className="text-gray-500">USD</span>
            </span>

            {/* LIVE badge — only while the SSE stream is open */}
            {isActive && (
                <span className="text-[10px] font-bold text-red-400 tracking-wider select-none">
                    · LIVE
                </span>
            )}
        </div>
    );
}
