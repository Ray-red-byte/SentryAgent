import { useState, useEffect, useCallback } from 'react';
import api, { tokenStore, logout } from './api';
import LoginPage from './components/LoginPage';
import FileUpload from './components/FileUpload';
import AuditWorkspace from './components/AuditWorkspace';
import { useTaskContext } from './context/TaskContext';
import {
  ShieldCheck, AlertTriangle, FileText,
  Download, Loader2, LogOut, User,
  ChevronDown, ChevronRight, Shield, Lock, Key, Filter, Globe, Database,
  Search, Wrench, RefreshCw,
} from 'lucide-react';

const TASK_ICONS = { auditing: Search, fixing: Wrench, applying: RefreshCw, scanning: Loader2 };
function TaskIndicator({ type }) {
  const Icon = TASK_ICONS[type] || Loader2;
  return <Icon size={12} className="animate-spin text-sentry-accent flex-none" />;
}

// ---------------------------------------------------------------------------
// Compiled-file guard — keeps __pycache__ / bytecode out of the UI
// ---------------------------------------------------------------------------
const COMPILED_EXTS = /\.(pyc|pyo|pyd)$/i;
function isSourceFile(filePath) {
  return !filePath.includes('__pycache__') && !COMPILED_EXTS.test(filePath);
}
function filterBundles(bundlesMap) {
  const out = {};
  for (const [domain, files] of Object.entries(bundlesMap)) {
    const clean = files.filter(isSourceFile);
    if (clean.length > 0) out[domain] = clean;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helper — check if we already have a valid-looking token in storage
// ---------------------------------------------------------------------------
function hasStoredToken() {
  return Boolean(tokenStore.get());
}

// ---------------------------------------------------------------------------
// Domain metadata — icons and display labels for each security domain
// ---------------------------------------------------------------------------
const DOMAIN_META = {
  authentication:     { label: 'Authentication',     Icon: Lock,     color: 'text-purple-400' },
  data_injection:     { label: 'Data Injection',     Icon: Database, color: 'text-red-400'    },
  rate_limiting:      { label: 'Rate Limiting',      Icon: Filter,   color: 'text-yellow-400' },
  secrets_management: { label: 'Secrets Management', Icon: Key,      color: 'text-orange-400' },
  input_validation:   { label: 'Input Validation',   Icon: Shield,   color: 'text-blue-400'   },
  access_control:     { label: 'Access Control',     Icon: Globe,    color: 'text-green-400'  },
};

function getDomainMeta(domain) {
  return DOMAIN_META[domain] || { label: domain, Icon: Shield, color: 'text-gray-400' };
}

// ---------------------------------------------------------------------------
// App
// ---------------------------------------------------------------------------
function App() {
  const { activeTasks } = useTaskContext();

  // ── Auth state ──────────────────────────────────────────────────────────
  const [isAuthenticated, setIsAuthenticated] = useState(hasStoredToken);

  // ── App state ───────────────────────────────────────────────────────────
  const [sessionId, setSessionId]           = useState(null);
  const [isUploading, setIsUploading]       = useState(false);
  const [scanResults, setScanResults]       = useState(null);      // per-file risk scores
  const [securityBundles, setSecurityBundles] = useState(null);    // domain → [files]
  const [selectedFile, setSelectedFile]     = useState(null);
  const [appStatus, setAppStatus]           = useState('Connecting…');
  const [isExporting, setIsExporting]       = useState(false);
  const [expandedDomains, setExpandedDomains] = useState({});      // domain → bool

  // ── Listen for 401 events dispatched by the Axios interceptor ───────────
  useEffect(() => {
    const handleForceLogout = () => {
      setIsAuthenticated(false);
      setSessionId(null);
      setScanResults(null);
      setSecurityBundles(null);
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

  // ── Helpers ───────────────────────────────────────────────────────────────

  // Build a risk-score lookup from per-file scan results
  const riskByFile = useCallback(() => {
    const map = {};
    (scanResults || []).forEach(sr => {
      map[sr.file || sr.file_path] = sr.risk_score || 0;
    });
    return map;
  }, [scanResults]);

  // Compute max risk score for a bundle
  const bundleMaxRisk = (files) => {
    const lookup = riskByFile();
    return files.reduce((max, fp) => Math.max(max, lookup[fp] || 0), 0);
  };

  // Toggle domain expansion
  const toggleDomain = (domain) =>
    setExpandedDomains(prev => ({ ...prev, [domain]: !prev[domain] }));

  // Select an entire security domain bundle for auditing
  const selectBundle = (domain, files) => {
    const primaryFile = files[0];
    setSelectedFile({
      bundleName: domain,
      involved_files: files,
      file: primaryFile,
      file_path: primaryFile,
      risk_score: bundleMaxRisk(files),
    });
  };

  // Select a single file (from within a bundle row or fallback list)
  const selectSingleFile = (fileObj) => setSelectedFile(fileObj);

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleLogin = useCallback(() => setIsAuthenticated(true), []);

  const handleLogout = useCallback(() => {
    logout();
    setIsAuthenticated(false);
    setSessionId(null);
    setScanResults(null);
    setSecurityBundles(null);
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
      const report = scanRes.data.report || {};

      // Strip any __pycache__ / bytecode entries that might have leaked through
      const resultsArray = (report.scan_results || []).filter(r => isSourceFile(r.file || r.file_path || ''));
      const bundlesMap = filterBundles(report.security_bundles || {});

      setScanResults(resultsArray);
      setSecurityBundles(Object.keys(bundlesMap).length > 0 ? bundlesMap : null);
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

            {/* ── Left panel ── */}
            <div className="col-span-4 bg-sentry-card rounded-xl border border-gray-700 overflow-hidden flex flex-col">

              {/* Panel header */}
              <div className="p-4 border-b border-gray-700 bg-gray-800/50">
                <h2 className="font-semibold flex items-center gap-2 text-sm text-gray-300">
                  {securityBundles
                    ? <><Shield size={15} className="text-sentry-accent" /> Security Domains</>
                    : <><AlertTriangle size={15} className="text-red-400" /> High Risk Files</>
                  }
                </h2>
              </div>

              <div className="overflow-y-auto flex-1 p-2 space-y-1 custom-scrollbar">

                {/* ── Security Domain Accordion ── */}
                {securityBundles && Object.entries(securityBundles).map(([domain, files]) => {
                  const { label, Icon, color } = getDomainMeta(domain);
                  const maxRisk = bundleMaxRisk(files);
                  const isExpanded = expandedDomains[domain];
                  const isSelected = selectedFile?.bundleName === domain;

                  return (
                    <div key={domain} className="rounded-lg overflow-hidden">

                      {/* Domain header row */}
                      <div
                        className={`flex items-center gap-2 px-3 py-2.5 cursor-pointer transition-all border
                          ${isSelected
                            ? 'bg-sentry-accent/10 border-sentry-accent'
                            : 'bg-gray-800/40 border-transparent hover:bg-gray-800 hover:border-gray-600'
                          }`}
                      >
                        {/* Expand/collapse chevron */}
                        <button
                          onClick={() => toggleDomain(domain)}
                          className="flex-none text-gray-500 hover:text-gray-300 transition-colors"
                          aria-label={isExpanded ? 'Collapse' : 'Expand'}
                        >
                          {isExpanded
                            ? <ChevronDown size={13} />
                            : <ChevronRight size={13} />
                          }
                        </button>

                        {/* Domain icon + label (click to select bundle) */}
                        <button
                          onClick={() => selectBundle(domain, files)}
                          className="flex-1 flex items-center gap-2 min-w-0 text-left"
                        >
                          <Icon size={14} className={`flex-none ${color}`} />
                          <span className="font-semibold text-xs text-white truncate">{label}</span>
                        </button>

                        {/* Badges */}
                        <div className="flex items-center gap-1.5 flex-none">
                          {activeTasks[domain] && <TaskIndicator type={activeTasks[domain].type} />}
                          <span className="text-[10px] text-gray-400">{files.length} file{files.length !== 1 ? 's' : ''}</span>
                          {maxRisk > 0 && (
                            <span className="bg-red-900/50 text-red-300 text-[10px] px-1.5 py-0.5 rounded font-bold">
                              {maxRisk}
                            </span>
                          )}
                        </div>
                      </div>

                      {/* Expanded file list */}
                      {isExpanded && (
                        <div className="bg-gray-900/60 border-l-2 border-gray-700 ml-3">
                          {files.map(fp => {
                            const riskScore = riskByFile()[fp] || 0;
                            const isFileSelected = !selectedFile?.bundleName && (selectedFile?.file === fp || selectedFile?.file_path === fp);
                            return (
                              <button
                                key={fp}
                                onClick={() => selectSingleFile({ file: fp, file_path: fp, risk_score: riskScore })}
                                className={`w-full text-left px-3 py-2 flex items-center gap-2 transition-all
                                  ${isFileSelected
                                    ? 'bg-sentry-accent/10 text-sentry-accent'
                                    : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                                  }`}
                              >
                                <FileText size={11} className="flex-none opacity-60" />
                                <span className="font-mono text-[10px] truncate">{fp}</span>
                                {activeTasks[fp] && <TaskIndicator type={activeTasks[fp].type} />}
                                {riskScore > 0 && (
                                  <span className="ml-auto text-[10px] text-gray-500">{riskScore}</span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* ── Fallback: flat file list (no bundles) ── */}
                {!securityBundles && scanResults.map((file) => (
                  <div
                    key={file.file || file.file_path}
                    onClick={() => selectSingleFile(file)}
                    className={`p-3 rounded-lg cursor-pointer transition-all border ${
                      selectedFile?.file === file.file || selectedFile?.file_path === file.file_path
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
                  <p>
                    {securityBundles
                      ? 'Select a security domain to begin auditing'
                      : 'Select a file to begin auditing'}
                  </p>
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
