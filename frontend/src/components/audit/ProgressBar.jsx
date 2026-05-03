import React from 'react';

export default function ProgressBar({ value, label }) {
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
