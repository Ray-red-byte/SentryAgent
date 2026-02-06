import { useState, useEffect } from 'react';
import api from './api';
import FileUpload from './components/FileUpload';
import AuditWorkspace from './components/AuditWorkspace';
import { ShieldCheck, AlertTriangle, FileText, Download, Loader2 } from 'lucide-react';

function App() {
  const [sessionId, setSessionId] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [scanResults, setScanResults] = useState(null);
  const [selectedFile, setSelectedFile] = useState(null);
  const [status, setStatus] = useState("Connecting...");
  const [isExporting, setIsExporting] = useState(false); // <--- New State for Export loading

  useEffect(() => {
    api.get('/health')
      .then(res => setStatus(`Online: ${res.data.version}`))
      .catch(err => setStatus("Offline: Check Backend Connection"));
  }, []);

  const handleFileUpload = async (file) => {
    setIsUploading(true);
    setStatus("Uploading Codebase...");

    const formData = new FormData();
    formData.append("file", file);

    try {
      const uploadRes = await api.post("/upload", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const newSessionId = uploadRes.data.session_id;
      setSessionId(newSessionId);
      setStatus("Scanning for Vulnerabilities...");

      const scanRes = await api.post("/scan", { session_id: newSessionId });
      setScanResults(scanRes.data.results);
      setStatus("Scan Complete");

    } catch (error) {
      console.error(error);
      setStatus("Error: " + (error.response?.data?.detail || error.message));
    } finally {
      setIsUploading(false);
    }
  };

  // --- NEW: Handle PDF Export ---
  const handleExport = async () => {
    if (!sessionId) return;
    setIsExporting(true);
    const prevStatus = status;
    setStatus("Generating PDF Report...");

    try {
      const response = await api.post("/export", {
        session_id: sessionId,
        scan_results: scanResults || []
      }, {
        responseType: 'blob' // Crucial: Tells axios to handle binary data
      });

      // Create a temporary link to trigger the download
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `sentry_report_${sessionId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();

      // Cleanup
      link.remove();
      window.URL.revokeObjectURL(url);

      setStatus("Report Downloaded!");
      setTimeout(() => setStatus(prevStatus), 3000); // Revert status after 3s
    } catch (error) {
      console.error("Export failed:", error);
      setStatus("Export Failed");
    } finally {
      setIsExporting(false);
    }
  };

  return (
    <div className="min-h-screen bg-sentry-dark text-white p-8 font-sans">
      <header className="flex items-center justify-between mb-8 max-w-7xl mx-auto">
        <div className="flex items-center gap-3">
          <ShieldCheck className="w-8 h-8 text-sentry-accent" />
          <div>
            <h1 className="text-xl font-bold tracking-tight">Sentry Agent</h1>
          </div>
        </div>

        {/* Header Actions */}
        <div className="flex items-center gap-4">
          <div className="text-xs font-mono bg-gray-800 px-3 py-1 rounded text-gray-400 border border-gray-700">
            {status}
          </div>

          {/* Export Button (Only visible after scan) */}
          {sessionId && scanResults && (
            <button
              onClick={handleExport}
              disabled={isExporting}
              className="flex items-center gap-2 bg-sentry-accent text-sentry-dark px-4 py-2 rounded-lg font-bold hover:bg-white transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isExporting ? <Loader2 size={16} className="animate-spin" /> : <Download size={16} />}
              {isExporting ? "Generating..." : "Export PDF"}
            </button>
          )}
        </div>
      </header>

      <main className="max-w-7xl mx-auto h-[80vh]">
        {!sessionId && (
          <div className="max-w-xl mx-auto mt-20">
            <FileUpload onUpload={handleFileUpload} isUploading={isUploading} />
          </div>
        )}

        {scanResults && (
          <div className="grid grid-cols-12 gap-6 h-full">

            {/* Sidebar List */}
            <div className="col-span-4 bg-sentry-card rounded-xl border border-gray-700 overflow-hidden flex flex-col">
              <div className="p-4 border-b border-gray-700 bg-gray-800/50">
                <h2 className="font-semibold flex items-center gap-2 text-sm text-gray-300">
                  <AlertTriangle size={16} className="text-red-400" /> High Risk Files
                </h2>
              </div>
              <div className="overflow-y-auto flex-1 p-2 space-y-2 custom-scrollbar">
                {scanResults.map((file) => (
                  <div
                    key={file.file}
                    onClick={() => setSelectedFile(file)}
                    className={`p-3 rounded-lg cursor-pointer transition-all border ${selectedFile?.file === file.file
                      ? 'bg-sentry-accent/10 border-sentry-accent'
                      : 'bg-gray-800/30 border-transparent hover:bg-gray-800 hover:border-gray-600'
                      }`}
                  >
                    <div className="font-mono text-xs font-bold text-white truncate mb-2">
                      {file.file}
                    </div>
                    <div className="flex gap-2">
                      <span className="bg-red-900/40 text-red-300 text-[10px] px-2 py-0.5 rounded uppercase font-bold">
                        Score: {file.risk_score}
                      </span>
                      <span className="bg-gray-700 text-gray-300 text-[10px] px-2 py-0.5 rounded">
                        {file.hotspots.length} Hotspots
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Main Workspace */}
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