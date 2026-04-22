import { useState, useEffect, useCallback } from 'react';
import api, { tokenStore, logout } from './api';
import LoginPage from './components/LoginPage';
import FileUpload from './components/FileUpload';
import AuditWorkspace from './components/AuditWorkspace';
import {
  ShieldCheck, AlertTriangle, FileText,
  Download, Loader2, LogOut, User,
} from 'lucide-react';

// ---------------------------------------------------------------------------
// Helper — check if we already have a valid-looking token in storage
// ---------------------------------------------------------------------------
function hasStoredToken() {
  return Boolean(tokenStore.get());
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
function App() {
  // ── Auth state ──────────────────────────────────────────────────────────
  const [isAuthenticated, setIsAuthenticated] = useState(hasStoredToken);

  // ── App state ───────────────────────────────────────────────────────────
  const [sessionId, setSessionId] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [appStatus, setAppStatus] = useState('Connecting…');
  const [isExporting, setIsExporting] = useState(false);

  // ── Listen for 401 events dispatched by the Axios interceptor ───────────
  useEffect(() => {
    const handleForceLogout = () => {
      setIsAuthenticated(false);
      setSessionId(null);
      setScanResults(null);
      setSelectedFile(null);
    };
    window.addEventListener('sentry:logout', handleForceLogout);
    return () => window.removeEventListener('sentry:logout', handleForceLogout);
  }, []);

  // ── Backend health probe (only when authenticated) ───────────────────────
  useEffect(() => {
    if (!isAuthenticated) return;
    api.get('/health')
      .then(res => setAppStatus(`Online · ${res.data.version}`))
      .catch(() => setAppStatus('Offline — check backend'));
  }, [isAuthenticated]);

  // ── Handlers ─────────────────────────────────────────────────────────────
  const handleLogin = useCallback(() => {
    setIsAuthenticated(true);
  }, []);

  const handleLogout = useCallback(() => {
    logout();
    setIsAuthenticated(false);
    setSessionId(null);
    setScanResults(null);
    setSelectedFile(null);
    setAppStatus('Connecting…');
  }, []);

  const handleFileUpload = async (file) => {
    setIsUploading(true);
    setAppStatus('Uploading codebase…');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const uploadRes = await api.post('/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });

      const newSessionId = uploadRes.data.session_id;
      setSessionId(newSessionId);
      setAppStatus('AI agents scanning for vulnerabilities…');

      const scanRes = await api.post('/scan', { session_id: newSessionId });
      const resultsArray = scanRes.data.report?.scan_results || [];

      setScanResults(resultsArray);
      setAppStatus('Scan complete');
    } catch (err) {
      const detail = err.response?.data?.detail || err.message;
      setAppStatus(`Error: ${detail}`);
    } finally {
      setIsUploading(false);
    }
  };

  const handleExport = async () => {
    if (!sessionId) return;
    setIsExporting(true);
    const prev = appStatus;
    setAppStatus('Generating PDF report…');

    try {
      const response = await api.post(
        '/export',
        { session_id: sessionId, scan_results: scanResults || [] },
        { responseType: 'blob' }
      );

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `sentry_report_${sessionId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);

      setAppStatus('Report downloaded!');
      setTimeout(() => setAppStatus(prev), 3000);
    } catch (err) {
      setAppStatus('Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  // ── Login gate ────────────────────────────────────────────────────────────
  if (!isAuthenticated) {
    return <LoginPage onLogin={handleLogin} />;
  }

  // ── Main app ──────────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen bg-sentry-dark text-white p-8 font-sans">

      {/* ── Header ── */}
      <header className="flex items-center justify-between mb-8 max-w-7xl mx-auto">

        {/* Brand */}
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-sentry-accent" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">Sentry Agent</h1>
          </div>
        </div>

        {/* Right-side controls */}
        <div className="flex items-center gap-3">

          {/* Status badge */}
          <div className="text-xs font-mono bg-gray-800 px-3 py-1.5 rounded border border-gray-700 text-gray-400">
            {appStatus}
          </div>

          {/* Export PDF (only when scan is done) */}
          {sessionId && scanResults && (
            <button
              id="export-pdf-btn"
              onClick={handleExport}
              disabled={isExporting}
              className="flex items-center gap-2 bg-sentry-accent text-sentry-dark px-4 py-2 rounded-lg
                         font-bold text-sm hover:bg-white transition-colors
                         disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isExporting
                ? <><Loader2 size={16} className="animate-spin" /> Generating…</>
                : <><Download size={16} /> Export PDF</>
              }
            </button>
          )}

          {/* User pill + Logout */}
          <div className="flex items-center gap-2 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5">
            <User size={14} className="text-gray-400" />
            <span className="text-xs text-gray-300 font-mono">admin</span>
            <button
              id="logout-btn"
              onClick={handleLogout}
              title="Sign out"
              className="ml-1 text-gray-500 hover:text-red-400 transition-colors"
            >
              <LogOut size={14} />
            </button>
          </div>

        </div>
      </header>

      {/* ── Main content ── */}
      <main className="max-w-7xl mx-auto h-[80vh]">

        {/* State 1: Not yet uploaded */}
        {!sessionId && (
          <div className="max-w-xl mx-auto mt-20">
            <FileUpload onUpload={handleFileUpload} isUploading={isUploading} />
          </div>
        )}

        {/* State 2: Scan in progress */}
        {sessionId && !scanResults && (
          <div className="h-full flex flex-col items-center justify-center space-y-4">
            <Loader2 className="w-16 h-16 text-sentry-accent animate-spin" />
            <p className="text-xl font-bold animate-pulse text-white">{appStatus}</p>
            <p className="text-gray-400 text-sm">Our AI agents are auditing your code…</p>
          </div>
        )}

        {/* State 3: Scan complete — show workspace */}
        {scanResults && (
          <div className="grid grid-cols-12 gap-6 h-full">

            {/* File list */}
            <div className="col-span-4 bg-sentry-card rounded-xl border border-gray-700 overflow-hidden flex flex-col">
              <div className="p-4 border-b border-gray-700 bg-gray-800/50">
                <h2 className="font-semibold flex items-center gap-2 text-sm text-gray-300">
                  <AlertTriangle size={16} className="text-red-400" /> High Risk Files
                </h2>
              </div>
              <div className="overflow-y-auto flex-1 p-2 space-y-2 custom-scrollbar">
                {scanResults.map((file) => (
                  <div
                    key={file.file || file.file_path}
                    onClick={() => setSelectedFile(file)}
                    className={`p-3 rounded-lg cursor-pointer transition-all border ${selectedFile?.file === file.file || selectedFile?.file_path === file.file_path
                        ? 'bg-sentry-accent/10 border-sentry-accent'
                        : 'bg-gray-800/30 border-transparent hover:bg-gray-800 hover:border-gray-600'
                      }`}
                  >
                    <div className="font-mono text-xs font-bold text-white truncate mb-2">
                      {file.file || file.file_path}
                    </div>
                    <div className="flex gap-2">
                      <span className="bg-red-900/40 text-red-300 text-[10px] px-2 py-0.5 rounded uppercase font-bold">
                        Score: {file.risk_score}
                      </span>
                      <span className="bg-gray-700 text-gray-300 text-[10px] px-2 py-0.5 rounded">
                        {file.hotspots?.length || 0} Hotspots
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Audit workspace */}
            <div className="col-span-8 bg-sentry-card rounded-xl border border-gray-700 p-6 overflow-hidden">
              {selectedFile ? (
                <AuditWorkspace sessionId={sessionId} file={selectedFile} />
              ) : (
                <div className="h-full flex flex-col items-center justify-center text-gray-500 opacity-50">
                  <FileText className="w-16 h-16 mb-4" />
                  <p>Select a file to begin auditing</p>
                </div>
              )}
            </div>

          </div>
        )}
      </main>
    </div>
  );
}

export default App;