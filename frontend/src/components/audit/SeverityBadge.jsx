import React from 'react';
import { SEVERITY_STYLES } from './severity';

export default function SeverityBadge({ severity }) {
    const s = (severity || 'INFO').toUpperCase();
    return (
        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase tracking-wide ${SEVERITY_STYLES[s] || SEVERITY_STYLES.INFO}`}>
            {s}
        </span>
    );
}
