import { useEffect, useState } from 'react';
import { api } from '../../api/client';
import { Button } from '../../components/Button';

interface CodebaseSelectorModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScanComplete: (summary: string) => void;
}

export function CodebaseSelectorModal({ isOpen, onClose, onScanComplete }: CodebaseSelectorModalProps) {
  const [tab, setTab] = useState<'github' | 'manual' | 'upload'>('github');
  const [gitUrl, setGitUrl] = useState('');
  const [suggested, setSuggested] = useState<any[]>([]);
  const [manualFiles, setManualFiles] = useState<any[]>([]);
  const [busy, setBusy] = useState(false);
  const [statusMessage, setStatusMessage] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);

  useEffect(() => {
    if (!isOpen) return;
    setError(null);
    setStatusMessage('');
    api.suggestedCodebases().then(setSuggested).catch(() => {});
    loadManualFiles();
  }, [isOpen]);

  const loadManualFiles = async () => {
    try {
      const files = await api.manualCodebases();
      setManualFiles(files);
    } catch {
      setManualFiles([]);
    }
  };

  if (!isOpen) return null;

  const handleScanGit = async () => {
    if (!gitUrl.trim()) {
      setError('Please enter a GitHub repository HTTPS URL.');
      return;
    }
    setBusy(true);
    setError(null);
    setStatusMessage('Cloning repository and extracting Graphify code graph...');
    try {
      const res = await api.scanUrl(gitUrl.trim());
      onScanComplete(res.summary || `Scan finished: ${res.node_count} nodes, ${res.findings_count} findings.`);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Git repository scan failed.');
    } finally {
      setBusy(false);
      setStatusMessage('');
    }
  };

  const handleScanManual = async (filename: string) => {
    setBusy(true);
    setError(null);
    setStatusMessage(`Extracting ${filename} and generating Graphify code graph...`);
    try {
      const res = await api.scanManual(filename);
      onScanComplete(res.summary || `Scan finished: ${res.node_count} nodes, ${res.findings_count} findings.`);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'Manual archive scan failed.');
    } finally {
      setBusy(false);
      setStatusMessage('');
    }
  };

  const handleScanUpload = async () => {
    if (!selectedFile) {
      setError('Please select a ZIP file to upload.');
      return;
    }
    setBusy(true);
    setError(null);
    setStatusMessage(`Uploading ${selectedFile.name} and extracting Graphify code graph...`);
    try {
      const res = await api.scanUpload(selectedFile);
      onScanComplete(res.summary || `Scan finished: ${res.node_count} nodes, ${res.findings_count} findings.`);
      onClose();
    } catch (err: any) {
      setError(err?.message || 'ZIP upload scan failed.');
    } finally {
      setBusy(false);
      setStatusMessage('');
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        backgroundColor: 'rgba(0, 0, 0, 0.75)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
        backdropFilter: 'blur(3px)',
      }}
    >
      <div
        className="panel"
        style={{
          width: '90%',
          maxWidth: '680px',
          maxHeight: '85vh',
          display: 'flex',
          flexDirection: 'column',
          backgroundColor: 'var(--paper)',
          boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
        }}
      >
        <header className="panel-head" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-2)' }}>
            <span className="section-number">01</span>
            <h2 className="label">Select Codebase for Analysis</h2>
          </div>
          <Button icon="x" small variant="quiet" onClick={onClose} disabled={busy}>
            Close
          </Button>
        </header>

        <div style={{ display: 'flex', borderBottom: '1px solid var(--rule)', backgroundColor: 'var(--paper-subtle)' }}>
          <button
            type="button"
            className={`btn btn-quiet ${tab === 'github' ? 'btn-primary' : ''}`}
            style={{ borderRadius: 0, padding: 'var(--s-2) var(--s-3)' }}
            onClick={() => setTab('github')}
          >
            GitHub Repository
          </button>
          <button
            type="button"
            className={`btn btn-quiet ${tab === 'manual' ? 'btn-primary' : ''}`}
            style={{ borderRadius: 0, padding: 'var(--s-2) var(--s-3)' }}
            onClick={() => {
              setTab('manual');
              void loadManualFiles();
            }}
          >
            Manual ZIP (data/codebases/)
          </button>
          <button
            type="button"
            className={`btn btn-quiet ${tab === 'upload' ? 'btn-primary' : ''}`}
            style={{ borderRadius: 0, padding: 'var(--s-2) var(--s-3)' }}
            onClick={() => setTab('upload')}
          >
            Upload ZIP File
          </button>
        </div>

        <div className="panel-body" style={{ overflowY: 'auto', padding: 'var(--s-4)', display: 'flex', flexDirection: 'column', gap: 'var(--s-3)' }}>
          {error ? (
            <div className="error-block" style={{ margin: 0 }}>
              <span className="label">Error</span>
              <p className="error-detail" style={{ margin: 0 }}>{error}</p>
            </div>
          ) : null}

          {busy ? (
            <div className="well" style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-3)' }}>
              <div style={{ animation: 'spin 1s linear infinite' }}>⏳</div>
              <span className="mono-sm">{statusMessage}</span>
            </div>
          ) : null}

          {tab === 'github' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-3)' }}>
              <div>
                <label className="label" style={{ display: 'block', marginBottom: 'var(--s-1)' }}>
                  Public Git Repository URL
                </label>
                <div style={{ display: 'flex', gap: 'var(--s-2)' }}>
                  <input
                    type="text"
                    value={gitUrl}
                    onChange={(e) => setGitUrl(e.target.value)}
                    placeholder="https://github.com/owner/repository"
                    disabled={busy}
                    style={{
                      flex: 1,
                      padding: 'var(--s-2)',
                      background: 'var(--paper)',
                      border: '1px solid var(--rule)',
                      color: 'var(--c-fg)',
                      fontFamily: 'var(--f-mono)',
                      fontSize: '13px',
                    }}
                  />
                  <Button variant="primary" disabled={busy || !gitUrl.trim()} onClick={handleScanGit}>
                    Scan Repo
                  </Button>
                </div>
              </div>

              <div>
                <span className="label" style={{ display: 'block', marginBottom: 'var(--s-2)', color: 'var(--c-fg-dim)' }}>
                  Or Choose a Recommended Testbed:
                </span>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-2)' }}>
                  {suggested.map((item) => (
                    <div
                      key={item.url}
                      style={{
                        padding: 'var(--s-2) var(--s-3)',
                        border: '1px solid var(--rule)',
                        background: 'var(--paper-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer',
                      }}
                      onClick={() => setGitUrl(item.url)}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '13px' }}>{item.name}</div>
                        <div style={{ fontSize: '11px', color: 'var(--c-fg-dim)' }}>{item.architecture}</div>
                        <div style={{ fontSize: '11px', color: 'var(--c-fg-dim)', marginTop: 2 }}>{item.description}</div>
                      </div>
                      <Button
                        small
                        variant="default"
                        disabled={busy}
                        onClick={(e) => {
                          e.stopPropagation();
                          setGitUrl(item.url);
                          void api.scanUrl(item.url).then((res) => {
                            onScanComplete(res.summary);
                            onClose();
                          }).catch((err) => setError(err.message));
                        }}
                      >
                        Select & Scan
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {tab === 'manual' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-3)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span className="mono-sm" style={{ color: 'var(--c-fg-dim)' }}>
                  Folder: <code>Hacktober-Fest/data/codebases/</code>
                </span>
                <Button small variant="quiet" onClick={loadManualFiles} disabled={busy}>
                  Refresh
                </Button>
              </div>

              {manualFiles.length === 0 ? (
                <div className="well" style={{ textAlign: 'center', padding: 'var(--s-4)' }}>
                  <p style={{ margin: 0, fontWeight: 500 }}>No .zip files found in <code>data/codebases/</code></p>
                  <p style={{ margin: 'var(--s-1) 0 0 0', fontSize: '12px', color: 'var(--c-fg-dim)' }}>
                    Drop any codebase ZIP archive into <code>c:\Users\jaydo\Desktop\Hackathon\Hacktober-Fest\data\codebases\</code> and click Refresh!
                  </p>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-2)' }}>
                  {manualFiles.map((file) => (
                    <div
                      key={file.filename}
                      style={{
                        padding: 'var(--s-2) var(--s-3)',
                        border: '1px solid var(--rule)',
                        background: 'var(--paper-subtle)',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                      }}
                    >
                      <div>
                        <div style={{ fontWeight: 600, fontSize: '13px', fontFamily: 'var(--f-mono)' }}>
                          📦 {file.filename}
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--c-fg-dim)' }}>
                          {(file.size / (1024 * 1024)).toFixed(2)} MB · Codebase ID: {file.codebase_id}
                        </div>
                      </div>
                      <Button
                        variant="primary"
                        small
                        disabled={busy}
                        onClick={() => handleScanManual(file.filename)}
                      >
                        Scan This ZIP
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'upload' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--s-3)' }}>
              <label className="label">Select Local ZIP File</label>
              <input
                type="file"
                accept=".zip"
                disabled={busy}
                onChange={(e) => setSelectedFile(e.target.files?.[0] || null)}
                style={{
                  padding: 'var(--s-3)',
                  border: '1px dashed var(--rule)',
                  background: 'var(--paper-subtle)',
                  cursor: 'pointer',
                }}
              />
              {selectedFile && (
                <div style={{ fontSize: '12px', color: 'var(--c-fg-dim)' }}>
                  Selected: <strong>{selectedFile.name}</strong> ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)
                </div>
              )}
              <Button
                variant="primary"
                disabled={busy || !selectedFile}
                onClick={handleScanUpload}
              >
                Upload & Scan Codebase
              </Button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

