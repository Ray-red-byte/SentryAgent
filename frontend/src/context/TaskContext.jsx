import { createContext, useContext, useState, useCallback } from 'react';

/**
 * Universal background-task tracker.
 *
 * activeTasks: { [entityId]: { type, label } }
 *
 * entityId examples:
 *   - bundle domain name  → 'authentication'
 *   - relative file path  → 'app/routes.py'
 *   - session id          → '<uuid>'  (scanning)
 *
 * task types: 'scanning' | 'auditing' | 'fixing' | 'applying'
 */
const TaskContext = createContext(null);

export function TaskProvider({ children }) {
    const [activeTasks, setActiveTasks] = useState({});

    const startTask = useCallback((entityId, type, label = '') => {
        setActiveTasks(prev => ({ ...prev, [entityId]: { type, label } }));
    }, []);

    const endTask = useCallback((entityId) => {
        setActiveTasks(prev => {
            const next = { ...prev };
            delete next[entityId];
            return next;
        });
    }, []);

    return (
        <TaskContext.Provider value={{ activeTasks, startTask, endTask }}>
            {children}
        </TaskContext.Provider>
    );
}

export function useTaskContext() {
    const ctx = useContext(TaskContext);
    if (!ctx) throw new Error('useTaskContext must be inside TaskProvider');
    return ctx;
}
