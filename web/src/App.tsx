import {
  AlertTriangle,
  Clipboard,
  Download,
  FileText,
  GitBranch,
  HardDrive,
  KeyRound,
  Lock,
  Plus,
  Save,
  Search,
  Settings,
  ShieldCheck,
  StickyNote,
  Upload,
} from 'lucide-react';
import { type DragEvent, type ElementType, type FormEvent, type ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import { api } from './api';
import { defaultMetrics, metricLabels, metricOptions, metricOrder, metricsFromVector, vectorFromMetrics } from './cvss';
import type { AssetDetail, AssetDuplicateGroup, AssetDuplicateItem, AttackPath, FindingPayload, FindingRecord, OCRStatus, RecordEnvelope, SearchHit } from './types';

type Module = 'findings' | 'assets' | 'evidence' | 'notes' | 'credentials' | 'search' | 'paths' | 'packets' | 'settings';

const modules: Array<{ id: Module; label: string; icon: ElementType }> = [
  { id: 'findings', label: 'Findings', icon: FileText },
  { id: 'assets', label: 'Assets', icon: HardDrive },
  { id: 'evidence', label: 'Evidence', icon: Upload },
  { id: 'notes', label: 'Notes', icon: StickyNote },
  { id: 'credentials', label: 'Credentials', icon: KeyRound },
  { id: 'search', label: 'Search', icon: Search },
  { id: 'paths', label: 'Attack Paths', icon: GitBranch },
  { id: 'packets', label: 'Packets', icon: Clipboard },
  { id: 'settings', label: 'Settings', icon: Settings },
];

const emptyFinding: FindingPayload = {
  title: '',
  status: 'draft',
  severity: 'Unscored',
  affected_scope: [],
  summary: '',
  technical_details: '',
  impact: '',
  remediation: '',
  validation: '',
  references: [],
  open_questions: [],
};

export function App() {
  const [unlocked, setUnlocked] = useState(false);
  const [vaultPath, setVaultPath] = useState('');
  const [active, setActive] = useState<Module>('findings');
  const [error, setError] = useState('');
  const [refreshKey, setRefreshKey] = useState(0);

  const refreshStatus = useCallback(async () => {
    const status = await api.status();
    setUnlocked(status.unlocked);
    setVaultPath(status.vault_path);
  }, []);

  useEffect(() => {
    refreshStatus().catch((err) => setError(err.message));
  }, [refreshStatus]);

  async function lock() {
    await api.lock();
    setUnlocked(false);
  }

  if (!unlocked) {
    return <UnlockScreen vaultPath={vaultPath} onUnlocked={() => refreshStatus().then(() => setRefreshKey((v) => v + 1))} />;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="mark">M</div>
          <div>
            <strong>Mnemox</strong>
            <span>Engagement memory</span>
          </div>
        </div>
        <nav>
          {modules.map((item) => {
            const Icon = item.icon;
            return (
              <button key={item.id} className={active === item.id ? 'active' : ''} onClick={() => setActive(item.id)}>
                <Icon size={17} />
                {item.label}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-footer">
          <span title={vaultPath}>{vaultPath}</span>
          <button className="ghost" onClick={lock}>
            <Lock size={15} /> Lock
          </button>
        </div>
      </aside>
      <main className="workspace">
        {error && <div className="notice error">{error}</div>}
        {active === 'findings' && <FindingWorkspace key={refreshKey} />}
        {active === 'assets' && <AssetsModule />}
        {active === 'evidence' && <EvidenceModule />}
        {active === 'notes' && <NotesModule />}
        {active === 'credentials' && <CredentialsModule />}
        {active === 'search' && <SearchModule />}
        {active === 'paths' && <AttackPathsModule />}
        {active === 'packets' && <PacketsModule />}
        {active === 'settings' && <SettingsModule onLock={lock} />}
      </main>
    </div>
  );
}

function UnlockScreen({ vaultPath, onUnlocked }: { vaultPath: string; onUnlocked: () => void }) {
  const [mode, setMode] = useState<'unlock' | 'init'>('unlock');
  const [name, setName] = useState('Pentest Engagement');
  const [passphrase, setPassphrase] = useState('');
  const [error, setError] = useState('');

  async function submit(event: FormEvent) {
    event.preventDefault();
    setError('');
    try {
      if (mode === 'init') await api.init(name, passphrase);
      else await api.unlock(passphrase);
      setPassphrase('');
      onUnlocked();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  return (
    <div className="unlock-screen">
      <form className="unlock-card" onSubmit={submit}>
        <div className="brand large">
          <div className="mark">M</div>
          <div>
            <strong>Mnemox</strong>
            <span>Local evidence memory</span>
          </div>
        </div>
        <div className="segmented">
          <button type="button" className={mode === 'unlock' ? 'active' : ''} onClick={() => setMode('unlock')}>
            Unlock
          </button>
          <button type="button" className={mode === 'init' ? 'active' : ''} onClick={() => setMode('init')}>
            Initialize
          </button>
        </div>
        {mode === 'init' && <input value={name} onChange={(event) => setName(event.target.value)} placeholder="Engagement name" />}
        <input
          autoFocus
          type="password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          placeholder="Vault passphrase"
        />
        <button className="primary" type="submit">
          <ShieldCheck size={16} /> {mode === 'init' ? 'Create vault' : 'Unlock vault'}
        </button>
        <p className="muted path">{vaultPath}</p>
        {error && <div className="notice error">{error}</div>}
      </form>
    </div>
  );
}

function FindingWorkspace() {
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState<FindingRecord | null>(null);
  const [allAssets, setAllAssets] = useState<RecordEnvelope[]>([]);
  const [form, setForm] = useState<FindingPayload>(emptyFinding);
  const [scopeText, setScopeText] = useState('');
  const [refsText, setRefsText] = useState('');
  const [questionsText, setQuestionsText] = useState('');
  const [noteText, setNoteText] = useState('');
  const [noteAsset, setNoteAsset] = useState('');
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [evidenceCaption, setEvidenceCaption] = useState('');
  const [evidenceDragging, setEvidenceDragging] = useState(false);
  const [metrics, setMetrics] = useState(defaultMetrics());
  const [vector, setVector] = useState('');
  const [cvssNotes, setCvssNotes] = useState('');
  const [selectedAssetIds, setSelectedAssetIds] = useState<string[]>([]);
  const [assetFilter, setAssetFilter] = useState('');
  const [syncAssetScope, setSyncAssetScope] = useState(true);
  const [assetBulkMessage, setAssetBulkMessage] = useState('');
  const [error, setError] = useState('');

  const loadFindings = useCallback(async () => {
    const [response, assets] = await Promise.all([api.listFindings(), api.assets()]);
    setFindings(response.items);
    setAllAssets(assets.items);
    if (!selectedId && response.items[0]) setSelectedId(response.items[0].id);
  }, [selectedId]);

  const loadDetail = useCallback(async () => {
    if (!selectedId) {
      setDetail(null);
      setForm(emptyFinding);
      return;
    }
    const response = await api.getFinding(selectedId);
    setDetail(response);
    setForm(response.payload);
    setScopeText(listToText(response.payload.affected_scope));
    setRefsText(listToText(response.payload.references));
    setQuestionsText(listToText(response.payload.open_questions));
    const existingMetrics = response.payload.cvss?.metrics || defaultMetrics();
    setMetrics({ ...defaultMetrics(), ...existingMetrics });
    setVector(response.payload.cvss?.vector || '');
    setCvssNotes(response.payload.cvss?.notes || '');
    setSelectedAssetIds((response.assets || []).map((asset) => asset.id));
    setAssetBulkMessage('');
  }, [selectedId]);

  useEffect(() => {
    loadFindings().catch((err) => setError(err.message));
  }, [loadFindings]);

  useEffect(() => {
    loadDetail().catch((err) => setError(err.message));
  }, [loadDetail]);

  const currentVector = vector || vectorFromMetrics(metrics);

  async function newFinding() {
    const title = window.prompt('Finding title');
    if (!title) return;
    const created = await api.createFinding({ ...emptyFinding, title });
    await loadFindings();
    setSelectedId(created.id);
  }

  async function saveFinding() {
    if (!selectedId) return;
    const payload = {
      ...form,
      affected_scope: textToList(scopeText),
      references: textToList(refsText),
      open_questions: textToList(questionsText),
    };
    await api.updateFinding(selectedId, payload);
    await loadFindings();
    await loadDetail();
  }

  async function addNote() {
    if (!selectedId || !noteText.trim()) return;
    await api.addNote(selectedId, { text: noteText, asset: noteAsset, tags: [] });
    setNoteText('');
    setNoteAsset('');
    await loadDetail();
  }

  async function uploadEvidence() {
    if (!selectedId || !evidenceFile) return;
    const data = new FormData();
    data.append('file', evidenceFile);
    data.append('caption', evidenceCaption);
    data.append('kind', evidenceFile.type.startsWith('image/') ? 'screenshot' : 'file');
    await api.uploadEvidence(selectedId, data);
    setEvidenceFile(null);
    setEvidenceCaption('');
    await loadFindings();
    await loadDetail();
  }

  function selectEvidenceFile(file: File | null) {
    setEvidenceFile(file);
    if (file && !evidenceCaption.trim()) {
      setEvidenceCaption(file.name.replace(/\.[^.]+$/, ''));
    }
  }

  function dropEvidenceFile(event: DragEvent<HTMLLabelElement>) {
    event.preventDefault();
    event.stopPropagation();
    setEvidenceDragging(false);
    selectEvidenceFile(event.dataTransfer.files?.[0] || null);
  }

  async function saveAffectedAssets() {
    if (!selectedId) return;
    const updated = await api.setFindingAssets(selectedId, selectedAssetIds, syncAssetScope);
    setDetail(updated);
    setForm(updated.payload);
    setScopeText(listToText(updated.payload.affected_scope));
    setSelectedAssetIds((updated.assets || []).map((asset) => asset.id));
    setAssetBulkMessage(`Saved ${updated.assets?.length || 0} affected assets.`);
    await loadFindings();
  }

  async function scoreCvss() {
    if (!selectedId) return;
    await api.scoreCvss(selectedId, { vector: vector || undefined, metrics, notes: cvssNotes });
    await loadFindings();
    await loadDetail();
  }

  const filteredAssets = useMemo(() => {
    const query = assetFilter.trim().toLowerCase();
    if (!query) return allAssets;
    return allAssets.filter((asset) => assetSearchText(asset).includes(query));
  }, [allAssets, assetFilter]);

  function toggleAssetSelection(assetId: string) {
    setSelectedAssetIds((current) => current.includes(assetId) ? current.filter((id) => id !== assetId) : [...current, assetId]);
    setAssetBulkMessage('');
  }

  function selectFilteredAssets() {
    setSelectedAssetIds((current) => Array.from(new Set([...current, ...filteredAssets.map((asset) => asset.id)])));
    setAssetBulkMessage('');
  }

  function clearFilteredAssets() {
    const filteredIds = new Set(filteredAssets.map((asset) => asset.id));
    setSelectedAssetIds((current) => current.filter((assetId) => !filteredIds.has(assetId)));
    setAssetBulkMessage('');
  }

  async function copyPacket() {
    if (!detail?.packet_markdown) return;
    await navigator.clipboard.writeText(detail.packet_markdown);
  }

  return (
    <div className="finding-layout">
      <section className="list-pane">
        <div className="pane-header">
          <div>
            <h1>Findings</h1>
            <p>{findings.length} records</p>
          </div>
          <button className="icon-button" onClick={newFinding} title="New finding">
            <Plus size={18} />
          </button>
        </div>
        <div className="finding-list">
          {findings.map((finding) => (
            <button key={finding.id} className={selectedId === finding.id ? 'selected' : ''} onClick={() => setSelectedId(finding.id)}>
              <strong>{finding.payload.title}</strong>
              <span>{finding.payload.severity} · {finding.payload.status}</span>
              <small>{finding.evidence_count || 0} evidence · {formatDate(finding.updated_at)}</small>
            </button>
          ))}
        </div>
      </section>

      <section className="editor-pane">
        {error && <div className="notice error">{error}</div>}
        {!detail ? (
          <EmptyState title="No finding selected" />
        ) : (
          <>
            <div className="editor-toolbar">
              <input className="title-input" value={form.title} onChange={(event) => setForm({ ...form, title: event.target.value })} />
              <button className="primary" onClick={saveFinding}>
                <Save size={16} /> Save
              </button>
            </div>
            <div className="form-grid">
              <Select label="Status" value={form.status} onChange={(status) => setForm({ ...form, status })} options={['draft', 'confirmed', 'needs validation', 'false positive', 'accepted risk']} />
              <Select label="Severity" value={form.severity} onChange={(severity) => setForm({ ...form, severity })} options={['Unscored', 'INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']} />
              <TextArea label="Affected Scope" value={scopeText} onChange={setScopeText} compact />
              <TextArea label="References" value={refsText} onChange={setRefsText} compact />
              <MarkdownTextArea label="Summary" value={form.summary} onChange={(summary) => setForm({ ...form, summary })} />
              <MarkdownTextArea label="Technical Details" value={form.technical_details} onChange={(technical_details) => setForm({ ...form, technical_details })} />
              <MarkdownTextArea label="Impact" value={form.impact} onChange={(impact) => setForm({ ...form, impact })} />
              <MarkdownTextArea label="Remediation" value={form.remediation} onChange={(remediation) => setForm({ ...form, remediation })} />
              <MarkdownTextArea label="Validation" value={form.validation} onChange={(validation) => setForm({ ...form, validation })} />
              <MarkdownTextArea label="Open Questions" value={questionsText} onChange={setQuestionsText} />
            </div>
          </>
        )}
      </section>

      <aside className="detail-pane">
        {detail && (
          <>
            <Panel title="CVSS v4.0 Base">
              <input
                value={currentVector}
                onChange={(event) => {
                  setVector(event.target.value);
                  setMetrics(metricsFromVector(event.target.value));
                }}
                placeholder="CVSS:4.0/..."
              />
              <div className="metric-stack">
                {metricOrder.map((metric) => (
                  <div key={metric} className="metric-row">
                    <span>{metricLabels[metric]}</span>
                    <div>
                      {metricOptions[metric].map((option) => (
                        <button
                          key={option.value}
                          aria-label={`${metricLabels[metric]}: ${option.label} (${option.value})`}
                          className={metrics[metric] === option.value ? 'active' : ''}
                          onClick={() => {
                            setVector('');
                            setMetrics({ ...metrics, [metric]: option.value });
                          }}
                        >
                          {option.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
              <input value={cvssNotes} onChange={(event) => setCvssNotes(event.target.value)} placeholder="Scoring notes" />
              <button className="primary full" onClick={scoreCvss}>Score finding</button>
              {detail.payload.cvss && <p className="score-line">{detail.payload.cvss.score} · {detail.payload.cvss.severity}</p>}
            </Panel>

            <Panel title="Affected Assets">
              <div className="bulk-asset-editor">
                <input
                  value={assetFilter}
                  onChange={(event) => setAssetFilter(event.target.value)}
                  placeholder="Filter imported assets, tags, host, URL"
                />
                <div className="bulk-asset-toolbar">
                  <span>{selectedAssetIds.length} selected · {filteredAssets.length} shown</span>
                  <button type="button" onClick={selectFilteredAssets}>Select shown</button>
                  <button type="button" onClick={clearFilteredAssets}>Clear shown</button>
                </div>
                <div className="bulk-asset-list">
                  {filteredAssets.map((asset) => (
                    <label key={asset.id} className="bulk-asset-row">
                      <input
                        type="checkbox"
                        checked={selectedAssetIds.includes(asset.id)}
                        onChange={() => toggleAssetSelection(asset.id)}
                      />
                      <span>
                        <strong>{assetLabel(asset)}</strong>
                        <small>{assetSummary(asset)}</small>
                      </span>
                    </label>
                  ))}
                </div>
                <label className="check-row">
                  <input type="checkbox" checked={syncAssetScope} onChange={(event) => setSyncAssetScope(event.target.checked)} />
                  <span>Sync affected scope from selected assets</span>
                </label>
                <button className="primary full" onClick={saveAffectedAssets}>Save affected assets</button>
                {assetBulkMessage && <p className="muted">{assetBulkMessage}</p>}
              </div>
              <div className="chip-list">
                {(detail.assets || []).map((asset) => <span key={asset.id} className="static-chip">{assetLabel(asset)}</span>)}
              </div>
            </Panel>

            <Panel title="Notes">
              <div className="inline-form">
                <input value={noteText} onChange={(event) => setNoteText(event.target.value)} placeholder="Quick note" />
                <input value={noteAsset} onChange={(event) => setNoteAsset(event.target.value)} placeholder="Asset" />
                <button onClick={addNote}>Add</button>
              </div>
              <MiniList records={detail.notes || []} primary="text" />
            </Panel>

            <Panel title="Evidence">
              <label
                className={`drop-zone ${evidenceDragging ? 'active' : ''}`}
                onDragEnter={(event) => {
                  event.preventDefault();
                  setEvidenceDragging(true);
                }}
                onDragOver={(event) => {
                  event.preventDefault();
                  setEvidenceDragging(true);
                }}
                onDragLeave={() => setEvidenceDragging(false)}
                onDrop={dropEvidenceFile}
              >
                <Upload size={20} />
                <strong>{evidenceFile ? evidenceFile.name : 'Drop evidence here'}</strong>
                <span>{evidenceFile ? formatBytes(evidenceFile.size) : 'Screenshot, proof file, or exported artifact'}</span>
                <input type="file" onChange={(event) => selectEvidenceFile(event.target.files?.[0] || null)} />
              </label>
              <input value={evidenceCaption} onChange={(event) => setEvidenceCaption(event.target.value)} placeholder="Caption" />
              <button onClick={uploadEvidence} disabled={!evidenceFile}>Attach evidence</button>
              <EvidenceCards records={detail.evidence || []} />
            </Panel>

            <Panel title="Finding Packet">
              <div className="packet-actions">
                <button onClick={copyPacket}><Clipboard size={15} /> Copy</button>
                <a className="button-link" href={`/api/findings/${detail.id}/packet?download=1`}>
                  <Download size={15} /> Download
                </a>
              </div>
              <pre className="packet-preview">{detail.packet_markdown}</pre>
            </Panel>
          </>
        )}
      </aside>
    </div>
  );
}

function RecordTable({ title, loader }: { title: string; loader: () => Promise<{ items: RecordEnvelope[] }> }) {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  useEffect(() => {
    loader().then((response) => setItems(response.items));
  }, [loader]);
  return (
    <section className="module-page">
      <h1>{title}</h1>
      <div className="table">
        {items.map((item) => (
          <div className="table-row" key={item.id}>
            <strong>{String(item.payload.title || item.payload.name || item.payload.caption || item.payload.text || item.id)}</strong>
            <span>{item.kind}</span>
            <small>{formatDate(item.updated_at)}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function NotesModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [assets, setAssets] = useState<RecordEnvelope[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [form, setForm] = useState({ text: '', asset: '', tags: '' });
  const [assetToLink, setAssetToLink] = useState('');

  async function load() {
    const [notesResponse, assetResponse] = await Promise.all([api.notes(), api.assets()]);
    setItems(notesResponse.items);
    setAssets(assetResponse.items);
    setSelectedId((current) => current || notesResponse.items[0]?.id || '');
  }

  useEffect(() => {
    load();
  }, []);

  const selected = items.find((item) => item.id === selectedId) || null;

  useEffect(() => {
    if (!selected) return;
    setForm({
      text: String(selected.payload.text || ''),
      asset: String(selected.payload.asset || ''),
      tags: listToCSV(selected.payload.tags as string[] | undefined),
    });
  }, [selected]);

  async function save() {
    if (!selected) return;
    await api.updateNote(selected.id, { ...form, tags: textToList(form.tags) });
    await load();
  }

  async function linkAsset() {
    if (!selected || !assetToLink) return;
    await api.linkNoteAsset(selected.id, assetToLink);
    setAssetToLink('');
    await load();
  }

  async function unlinkAsset(assetId: string) {
    if (!selected) return;
    await api.unlinkNoteAsset(selected.id, assetId);
    await load();
  }

  return (
    <section className="module-page two-column">
      <div>
        <h1>Notes</h1>
        <div className="table">
          {items.map((item) => (
            <button className={`table-row selectable-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelectedId(item.id)}>
              <strong>{recordTitle(item)}</strong>
              <span>{String(item.payload.asset || 'no asset')}</span>
              <small>{item.assets?.length || 0} linked</small>
            </button>
          ))}
        </div>
      </div>
      <div className="stack">
        {selected ? (
          <>
            <div className="side-form">
              <h2>Edit Note</h2>
              <textarea value={form.text} onChange={(event) => setForm({ ...form, text: event.target.value })} placeholder="note" />
              <input value={form.asset} onChange={(event) => setForm({ ...form, asset: event.target.value })} placeholder="asset label" />
              <input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="tags" />
              <button className="primary" onClick={save}>Save note</button>
            </div>
            <Panel title="Linked Assets">
              <AssetLinkEditor
                assets={assets}
                linked={selected.assets || []}
                value={assetToLink}
                onChange={setAssetToLink}
                onLink={linkAsset}
                onUnlink={unlinkAsset}
              />
            </Panel>
          </>
        ) : (
          <EmptyState title="No note selected" />
        )}
      </div>
    </section>
  );
}

function EvidenceModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [assets, setAssets] = useState<RecordEnvelope[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [form, setForm] = useState({ kind: 'file', caption: '', original_path: '', tags: '' });
  const [assetToLink, setAssetToLink] = useState('');
  const [ocrStatus, setOcrStatus] = useState<OCRStatus | null>(null);
  const [ocrError, setOcrError] = useState('');

  async function load() {
    const [evidenceResponse, assetResponse] = await Promise.all([api.evidence(), api.assets()]);
    setItems(evidenceResponse.items);
    setAssets(assetResponse.items);
    setSelectedId((current) => current || evidenceResponse.items[0]?.id || '');
  }

  useEffect(() => {
    load();
    api.ocrStatus().then(setOcrStatus).catch((error) => setOcrError(error.message));
  }, []);

  const selected = items.find((item) => item.id === selectedId) || null;

  useEffect(() => {
    if (!selected) return;
    setForm({
      kind: String(selected.payload.kind || 'file'),
      caption: String(selected.payload.caption || ''),
      original_path: String(selected.payload.original_path || ''),
      tags: listToCSV(selected.payload.tags as string[] | undefined),
    });
  }, [selected]);

  async function save() {
    if (!selected) return;
    await api.updateEvidence(selected.id, { ...form, tags: textToList(form.tags) });
    await load();
  }

  async function linkAsset() {
    if (!selected || !assetToLink) return;
    await api.linkEvidenceAsset(selected.id, assetToLink);
    setAssetToLink('');
    await load();
  }

  async function unlinkAsset(assetId: string) {
    if (!selected) return;
    await api.unlinkEvidenceAsset(selected.id, assetId);
    await load();
  }

  async function extractOCR() {
    if (!selected) return;
    setOcrError('');
    try {
      const updated = await api.extractEvidenceOCR(selected.id);
      setItems((current) => current.map((item) => item.id === updated.id ? updated : item));
      setSelectedId(updated.id);
    } catch (error) {
      setOcrError(error instanceof Error ? error.message : String(error));
      await load();
    }
  }

  return (
    <section className="module-page two-column">
      <div>
        <h1>Evidence</h1>
        <div className="table">
          {items.map((item) => (
            <button className={`table-row selectable-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelectedId(item.id)}>
              <strong>{recordTitle(item)}</strong>
              <span>{String(item.payload.kind || 'file')}</span>
              <small>{item.assets?.length || 0} assets</small>
            </button>
          ))}
        </div>
      </div>
      <div className="stack">
        {selected ? (
          <>
            <EvidenceCard record={selected} />
            <div className="side-form">
              <h2>Edit Evidence</h2>
              <select value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value })}>
                {['screenshot', 'file', 'request', 'response', 'log', 'other'].map((option) => <option key={option}>{option}</option>)}
              </select>
              <input value={form.caption} onChange={(event) => setForm({ ...form, caption: event.target.value })} placeholder="caption" />
              <input value={form.original_path} onChange={(event) => setForm({ ...form, original_path: event.target.value })} placeholder="original path" />
              <input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="tags" />
              <button className="primary" onClick={save}>Save evidence</button>
            </div>
            <OCRPanel record={selected} status={ocrStatus} error={ocrError} onExtract={extractOCR} />
            <Panel title="Linked Assets">
              <AssetLinkEditor
                assets={assets}
                linked={selected.assets || []}
                value={assetToLink}
                onChange={setAssetToLink}
                onLink={linkAsset}
                onUnlink={unlinkAsset}
              />
            </Panel>
          </>
        ) : (
          <EmptyState title="No evidence selected" />
        )}
      </div>
    </section>
  );
}

function AssetsModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [duplicateGroups, setDuplicateGroups] = useState<AssetDuplicateGroup[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [form, setForm] = useState({ name: '', type: 'host', value: '', notes: '', tags: '' });
  const [importMessage, setImportMessage] = useState('');
  const [screenshotPath, setScreenshotPath] = useState('');
  const [mergeTarget, setMergeTarget] = useState('');
  const [mergeMessage, setMergeMessage] = useState('');

  async function load() {
    const [assetResponse, duplicateResponse] = await Promise.all([api.assets(), api.assetDuplicates()]);
    setItems(assetResponse.items);
    setDuplicateGroups(duplicateResponse.items || []);
    setSelectedId((current) => current || assetResponse.items[0]?.id || '');
  }

  useEffect(() => {
    load();
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      return;
    }
    api.asset(selectedId).then(setDetail);
  }, [selectedId]);

  const duplicateOptions = duplicateCandidatesForAsset(selectedId, duplicateGroups);
  const selectedMergeTarget = duplicateOptions.find((item) => item.id === mergeTarget) || null;

  async function create(event: FormEvent) {
    event.preventDefault();
    const created = await api.createAsset({ ...form, tags: textToList(form.tags) });
    setForm({ name: '', type: 'host', value: '', notes: '', tags: '' });
    setSelectedId(created.id);
    await load();
  }

  async function importFile(kind: 'nmap' | 'nuclei' | 'burp' | 'nessus' | 'bloodhound', file: File | null) {
    if (!file) return;
    const data = new FormData();
    data.append('file', file);
    const importers = {
      nmap: api.importNmap,
      nuclei: api.importNuclei,
      burp: api.importBurp,
      nessus: api.importNessus,
      bloodhound: api.importBloodHound,
    };
    const result = await importers[kind](data);
    setImportMessage(importSummary(result));
    await load();
  }

  async function importScreenshots() {
    const result = await api.importScreenshots(screenshotPath);
    setImportMessage(importSummary(result));
    setScreenshotPath('');
  }

  async function mergeSelectedAsset() {
    if (!selectedId || !mergeTarget || !detail || !selectedMergeTarget) return;
    const ok = window.confirm(
      `Merge ${assetLabel(selectedMergeTarget)} into ${assetLabel(detail)}?\n\n` +
        `${selectedMergeTarget.relation_count || 0} linked records will move to the selected asset. This removes the duplicate asset record.`,
    );
    if (!ok) return;
    const merged = await api.mergeAsset(selectedId, mergeTarget);
    setDetail(merged);
    setMergeTarget('');
    setMergeMessage(`Merged ${assetLabel(selectedMergeTarget)} into ${assetLabel(merged)}.`);
    await load();
  }

  return (
    <section className="module-page two-column">
      <div>
        <h1>Assets</h1>
        <div className="table">
          {items.map((item) => (
            <button className={`table-row asset-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelectedId(item.id)}>
              <strong>{String(item.payload.name)}</strong>
              <span>{String(item.payload.type || 'asset')}</span>
              <small>{String(item.payload.value || '')}</small>
            </button>
          ))}
        </div>
        {detail && (
          <div className="asset-detail">
            <Panel title="Asset Context">
              <div className="record-head">
                <strong>{assetLabel(detail)}</strong>
                <span>{String(detail.payload.type || 'asset')} · {String(detail.payload.value || '')}</span>
              </div>
              {Array.isArray(detail.payload.aliases) && detail.payload.aliases.length > 0 && (
                <div className="chip-list">
                  {(detail.payload.aliases as string[]).map((alias) => (
                    <span className="static-chip" key={alias}>{alias}</span>
                  ))}
                </div>
              )}
              {detail.payload.notes ? <p className="muted">{String(detail.payload.notes)}</p> : null}
            </Panel>
            <RelationPanel title="Linked Findings" records={detail.findings || []} empty="No findings linked to this asset yet." />
            <RelationPanel title="Linked Evidence" records={detail.evidence || []} empty="No evidence linked to this asset yet." />
            <RelationPanel title="Linked Notes" records={detail.notes || []} empty="No notes linked to this asset yet." />
            <RelationPanel title="Linked Credentials" records={detail.credentials || []} empty="No credentials linked to this asset yet." />
          </div>
        )}
      </div>
      <div className="stack">
        <form className="side-form" onSubmit={create}>
          <h2>Add Asset</h2>
          <input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="name" />
          <select value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value })}>
            {['host', 'domain', 'url', 'user', 'cloud', 'repo', 'service', 'other'].map((option) => <option key={option}>{option}</option>)}
          </select>
          <input value={form.value} onChange={(event) => setForm({ ...form, value: event.target.value })} placeholder="value" />
          <input value={form.tags} onChange={(event) => setForm({ ...form, tags: event.target.value })} placeholder="tags" />
          <textarea value={form.notes} onChange={(event) => setForm({ ...form, notes: event.target.value })} placeholder="notes" />
          <button className="primary">Save asset</button>
        </form>
        <div className="side-form">
          <h2>Import Data</h2>
          <label className="compact">
            <span>Nmap XML</span>
            <input type="file" accept=".xml,text/xml" onChange={(event) => importFile('nmap', event.target.files?.[0] || null)} />
          </label>
          <label className="compact">
            <span>nuclei JSONL</span>
            <input type="file" accept=".json,.jsonl,application/json" onChange={(event) => importFile('nuclei', event.target.files?.[0] || null)} />
          </label>
          <label className="compact">
            <span>Burp XML</span>
            <input type="file" accept=".xml,text/xml,application/xml" onChange={(event) => importFile('burp', event.target.files?.[0] || null)} />
          </label>
          <label className="compact">
            <span>Nessus</span>
            <input type="file" accept=".nessus,.xml,text/xml,application/xml" onChange={(event) => importFile('nessus', event.target.files?.[0] || null)} />
          </label>
          <label className="compact">
            <span>BloodHound JSON</span>
            <input type="file" accept=".json,application/json" onChange={(event) => importFile('bloodhound', event.target.files?.[0] || null)} />
          </label>
          <label className="compact">
            <span>Screenshot Folder Path</span>
            <input value={screenshotPath} onChange={(event) => setScreenshotPath(event.target.value)} placeholder="/path/to/screenshots" />
          </label>
          <button onClick={importScreenshots}>Import screenshots</button>
          {importMessage && <p className="muted">{importMessage}</p>}
        </div>
        <div className="side-form">
          <h2>Merge Duplicates</h2>
          {detail && duplicateOptions.length > 0 ? (
            <>
              <select value={mergeTarget} onChange={(event) => setMergeTarget(event.target.value)}>
                <option value="">Select duplicate candidate</option>
                {duplicateOptions.map((candidate) => (
                  <option key={candidate.id} value={candidate.id}>
                    {assetLabel(candidate)} · {candidate.reason} · {candidate.relation_count || 0} links
                  </option>
                ))}
              </select>
              {selectedMergeTarget && (
                <div className="merge-card">
                  <strong>{assetLabel(selectedMergeTarget)}</strong>
                  <span>{String(selectedMergeTarget.payload.type || 'asset')} · {String(selectedMergeTarget.payload.value || '')}</span>
                  <small>{selectedMergeTarget.relation_count || 0} linked records will move to {assetLabel(detail)}.</small>
                </div>
              )}
              <button className="danger" onClick={mergeSelectedAsset} disabled={!mergeTarget}>Merge into selected asset</button>
            </>
          ) : (
            <p className="muted">No duplicate candidates for the selected asset.</p>
          )}
          {mergeMessage && <p className="muted">{mergeMessage}</p>}
        </div>
      </div>
    </section>
  );
}

function CredentialsModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [assets, setAssets] = useState<RecordEnvelope[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [form, setForm] = useState({ name: '', username: '', secret: '', scope: '', tags: '' });
  const [editForm, setEditForm] = useState({ name: '', username: '', secret: '', scope: '', tags: '' });
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [assetToLink, setAssetToLink] = useState('');
  async function load() {
    const [credentialResponse, assetResponse] = await Promise.all([api.credentials(), api.assets()]);
    setItems(credentialResponse.items);
    setAssets(assetResponse.items);
    setSelectedId((current) => current || credentialResponse.items[0]?.id || '');
  }
  useEffect(() => {
    load();
  }, []);

  const selected = items.find((item) => item.id === selectedId) || null;

  useEffect(() => {
    if (!selected) return;
    setEditForm({
      name: String(selected.payload.name || ''),
      username: String(selected.payload.username || ''),
      secret: '',
      scope: String(selected.payload.scope || ''),
      tags: listToCSV(selected.payload.tags as string[] | undefined),
    });
  }, [selected]);

  async function create(event: FormEvent) {
    event.preventDefault();
    const created = await api.createCredential({ ...form, tags: textToList(form.tags) });
    setForm({ name: '', username: '', secret: '', scope: '', tags: '' });
    setSelectedId(created.id);
    await load();
  }
  async function save() {
    if (!selected) return;
    await api.updateCredential(selected.id, { ...editForm, tags: textToList(editForm.tags) });
    setEditForm({ ...editForm, secret: '' });
    await load();
  }
  async function reveal(id: string) {
    const response = await api.revealCredential(id);
    setRevealed({ ...revealed, [id]: response.secret });
  }
  async function linkAsset() {
    if (!selected || !assetToLink) return;
    await api.linkCredentialAsset(selected.id, assetToLink);
    setAssetToLink('');
    await load();
  }
  async function unlinkAsset(assetId: string) {
    if (!selected) return;
    await api.unlinkCredentialAsset(selected.id, assetId);
    await load();
  }
  return (
    <section className="module-page two-column">
      <div>
        <h1>Credentials</h1>
        <div className="table">
          {items.map((item) => (
            <button className={`table-row selectable-row ${selectedId === item.id ? 'selected' : ''}`} key={item.id} onClick={() => setSelectedId(item.id)}>
              <strong>{String(item.payload.name)}</strong>
              <span>{String(item.payload.username || 'no username')}</span>
              <small>{item.assets?.length || 0} assets</small>
            </button>
          ))}
        </div>
      </div>
      <div className="stack">
        {selected && (
          <>
            <div className="side-form">
              <h2>Edit Credential</h2>
              {(['name', 'username', 'scope', 'tags'] as const).map((key) => (
                <input key={key} value={editForm[key]} onChange={(event) => setEditForm({ ...editForm, [key]: event.target.value })} placeholder={key} />
              ))}
              <input type="password" value={editForm.secret} onChange={(event) => setEditForm({ ...editForm, secret: event.target.value })} placeholder="new secret" />
              <div className="packet-actions">
                <button className="primary" onClick={save}>Save credential</button>
                <button onClick={() => reveal(selected.id)}>{revealed[selected.id] ? revealed[selected.id] : 'Reveal secret'}</button>
              </div>
            </div>
            <Panel title="Linked Assets">
              <AssetLinkEditor
                assets={assets}
                linked={selected.assets || []}
                value={assetToLink}
                onChange={setAssetToLink}
                onLink={linkAsset}
                onUnlink={unlinkAsset}
              />
            </Panel>
          </>
        )}
        <form className="side-form" onSubmit={create}>
          <h2>Add Credential</h2>
          {(['name', 'username', 'secret', 'scope', 'tags'] as const).map((key) => (
            <input key={key} type={key === 'secret' ? 'password' : 'text'} value={form[key]} onChange={(event) => setForm({ ...form, [key]: event.target.value })} placeholder={key} />
          ))}
          <button className="primary">Save credential</button>
        </form>
      </div>
    </section>
  );
}

function SearchModule() {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState('all');
  const [assetId, setAssetId] = useState('');
  const [mode, setMode] = useState<'keyword' | 'semantic'>('keyword');
  const [tag, setTag] = useState('');
  const [status, setStatus] = useState('all');
  const [assets, setAssets] = useState<RecordEnvelope[]>([]);
  const [items, setItems] = useState<SearchHit[]>([]);
  useEffect(() => {
    api.assets().then((response) => setAssets(response.items));
  }, []);
  async function runSearch() {
    const response = await api.search(query, { kind, assetId, mode, tag: tag.trim(), status });
    setItems(response.items);
  }
  return (
    <section className="module-page">
      <h1>Search</h1>
      <div className="search-bar">
        <input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && runSearch()} placeholder="Search findings, notes, evidence, credential metadata" />
        <button className="primary" onClick={runSearch}>Search</button>
      </div>
      <div className="filter-row">
        <div className="segmented compact" role="tablist" aria-label="Search mode">
          <button type="button" className={mode === 'keyword' ? 'active' : ''} onClick={() => setMode('keyword')}>Keyword</button>
          <button type="button" className={mode === 'semantic' ? 'active' : ''} onClick={() => setMode('semantic')}>Semantic</button>
        </div>
        <select value={kind} onChange={(event) => setKind(event.target.value)}>
          {['all', 'finding', 'evidence', 'credential', 'asset', 'note'].map((option) => (
            <option key={option} value={option}>{option}</option>
          ))}
        </select>
        <select value={assetId} onChange={(event) => setAssetId(event.target.value)}>
          <option value="">Any asset relationship</option>
          {assets.map((asset) => (
            <option key={asset.id} value={asset.id}>{assetLabel(asset)}</option>
          ))}
        </select>
        <input value={tag} onChange={(event) => setTag(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && runSearch()} placeholder="Tag filter" />
        <select value={status} onChange={(event) => setStatus(event.target.value)}>
          {['all', 'draft', 'confirmed', 'fixed', 'accepted-risk'].map((option) => (
            <option key={option} value={option}>{option}</option>
          ))}
        </select>
      </div>
      <div className="table">
        {items.map((item) => (
          <div className="table-row tall" key={item.ID}>
            <strong>[{item.Kind}:{item.ID.slice(0, 8)}] {item.Title}</strong>
            <span>{item.Excerpt}</span>
            <small>score {item.Score}</small>
          </div>
        ))}
      </div>
    </section>
  );
}

function AttackPathsModule() {
  const [items, setItems] = useState<AttackPath[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [selectedRecordId, setSelectedRecordId] = useState('');
  const [included, setIncluded] = useState<Record<string, boolean>>({});

  useEffect(() => {
    api.attackPaths().then((response) => {
      setItems(response.items);
      setSelectedId((current) => current || response.items[0]?.id || '');
    });
  }, []);

  const selected = useMemo(() => items.find((item) => item.id === selectedId) || items[0] || null, [items, selectedId]);
  const related = useMemo(() => (selected ? attackPathRecords(selected) : []), [selected]);
  const activeRecord = useMemo(() => {
    if (!selected) return null;
    if (selectedRecordId === selected.id) return selected;
    return related.find((record) => record.id === selectedRecordId) || selected;
  }, [related, selected, selectedRecordId]);
  const packetMarkdown = useMemo(() => (selected ? buildAttackPathMarkdown(selected, included) : ''), [included, selected]);
  const downloadHref = packetMarkdown ? `data:text/markdown;charset=utf-8,${encodeURIComponent(packetMarkdown)}` : '';

  useEffect(() => {
    if (!selected) return;
    setSelectedRecordId(selected.id);
    setIncluded(Object.fromEntries(attackPathRecords(selected).map((record) => [record.id, true])));
  }, [selected?.id]);

  function toggleRecord(id: string) {
    setIncluded((current) => ({ ...current, [id]: !current[id] }));
  }

  return (
    <section className="module-page attack-workspace">
      <div className="workspace-head">
        <div>
          <h1>Attack Paths</h1>
          <p className="muted">Risk hubs, linked context, completeness checks, and copy-ready chain packets.</p>
        </div>
        {selected && <b className="risk-pill">Risk {selected.risk_score}</b>}
      </div>
      {items.length === 0 ? (
        <div className="empty-panel">
          <GitBranch size={28} />
          <p>No linked asset chains yet.</p>
        </div>
      ) : (
        <>
          <div className="attack-layout">
            <aside className="risk-hubs">
              <h2>Risk Hubs</h2>
              {items.map((path) => (
                <button className={`risk-hub ${selected?.id === path.id ? 'selected' : ''}`} key={path.id} onClick={() => setSelectedId(path.id)}>
                  <strong>{assetLabel(path)}</strong>
                  <span>{attackPathRecords(path).length} linked records</span>
                  <b>Risk {path.risk_score}</b>
                </button>
              ))}
            </aside>
            {selected && (
              <main className="chain-workbench">
                <AttackPathMap path={selected} included={included} selectedId={activeRecord?.id || selected.id} onSelect={setSelectedRecordId} />
                <section className="chain-builder">
                  <div className="section-head">
                    <h2>Chain Builder</h2>
                    <span>{related.filter((record) => included[record.id]).length} selected</span>
                  </div>
                  <div className="chain-groups">
                    <ChainGroup title="Findings" records={selected.findings || []} included={included} onToggle={toggleRecord} onSelect={setSelectedRecordId} />
                    <ChainGroup title="Evidence" records={selected.evidence || []} included={included} onToggle={toggleRecord} onSelect={setSelectedRecordId} />
                    <ChainGroup title="Notes" records={selected.notes || []} included={included} onToggle={toggleRecord} onSelect={setSelectedRecordId} />
                    <ChainGroup title="Credentials" records={selected.credentials || []} included={included} onToggle={toggleRecord} onSelect={setSelectedRecordId} />
                  </div>
                </section>
              </main>
            )}
            <aside className="path-inspector">
              {selected && activeRecord ? (
                <>
                  <Panel title="Inspector">
                    <div className="record-head">
                      <strong>{recordTitle(activeRecord)}</strong>
                      <span>{activeRecord.kind} · {activeRecord.id.slice(0, 8)}</span>
                    </div>
                    <p className="muted">{relationSummary(activeRecord) || 'No summary yet.'}</p>
                  </Panel>
                  <Panel title="Completeness Checks">
                    <div className="check-list">
                      {(selected.checks || []).map((check) => (
                        <span key={check} className={check.includes('ready') ? 'ready' : ''}>{check}</span>
                      ))}
                    </div>
                  </Panel>
                  <Panel title="Attack Path Packet">
                    <div className="packet-actions">
                      <button onClick={() => navigator.clipboard.writeText(packetMarkdown)}><Clipboard size={15} /> Copy Markdown</button>
                      <a className="button-link" href={downloadHref} download={`${assetLabel(selected)}-attack-path.md`}><Download size={15} /> Download</a>
                    </div>
                    <pre className="packet-preview">{packetMarkdown}</pre>
                  </Panel>
                </>
              ) : null}
            </aside>
          </div>
          <div className="path-grid">
            {items.map((path) => (
              <section className="path-card" key={path.id}>
                <div className="path-header">
                <div>
                  <strong>{assetLabel(path)}</strong>
                  <span>{String(path.payload.type || 'asset')} · {String(path.payload.value || '')}</span>
                </div>
                <b>Risk {path.risk_score}</b>
                </div>
                <div className="path-columns">
                  <PathColumn title="Findings" records={path.findings || []} />
                  <PathColumn title="Evidence" records={path.evidence || []} />
                  <PathColumn title="Notes" records={path.notes || []} />
                  <PathColumn title="Credentials" records={path.credentials || []} />
                </div>
              </section>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

function AttackPathMap({ path, included, selectedId, onSelect }: { path: AttackPath; included: Record<string, boolean>; selectedId: string; onSelect: (id: string) => void }) {
  const nodes = attackPathMapNodes(path, included);
  const assetNode = nodes.find((node) => node.record.id === path.id);
  return (
    <section className="path-map">
      <div className="section-head">
        <h2>Visual Map</h2>
        <span>{assetLabel(path)}</span>
      </div>
      <svg viewBox="0 0 620 300" role="img" aria-label={`Attack path map for ${assetLabel(path)}`}>
        <defs>
          {nodes.map((node) => (
            <clipPath key={`${node.record.id}-clip`} id={nodeClipId(node.record.id)}>
              <rect x={node.x - 68} y={node.y - 20} width="136" height="40" />
            </clipPath>
          ))}
        </defs>
        {assetNode && nodes.filter((node) => node.record.id !== path.id).map((node) => (
          <line key={`${node.record.id}-edge`} x1={assetNode.x} y1={assetNode.y} x2={node.x} y2={node.y} className={`map-edge ${node.kind}`} />
        ))}
        {nodes.map((node) => (
          <g key={node.record.id} className={`map-node ${node.kind} ${selectedId === node.record.id ? 'selected' : ''}`} onClick={() => onSelect(node.record.id)} tabIndex={0} role="button" aria-label={recordTitle(node.record)}>
            <title>{recordTitle(node.record)}</title>
            <rect x={node.x - 78} y={node.y - 27} width="156" height="54" rx="7" />
            <text x={node.x} y={node.y - 5} clipPath={`url(#${nodeClipId(node.record.id)})`}>{truncate(recordTitle(node.record), 17)}</text>
            <text x={node.x} y={node.y + 15} className="node-subtitle">{node.kind}</text>
          </g>
        ))}
      </svg>
    </section>
  );
}

function ChainGroup({ title, records, included, onToggle, onSelect }: { title: string; records: RecordEnvelope[]; included: Record<string, boolean>; onToggle: (id: string) => void; onSelect: (id: string) => void }) {
  return (
    <div className="chain-group">
      <h3>{title}</h3>
      {records.length === 0 ? (
        <span className="muted">None</span>
      ) : (
        records.map((record) => (
          <div key={record.id} className="chain-item">
            <input type="checkbox" checked={included[record.id] !== false} onChange={() => onToggle(record.id)} />
            <button type="button" onClick={() => onSelect(record.id)}>
              <strong>{recordTitle(record)}</strong>
              <small>{relationSummary(record) || record.kind}</small>
            </button>
          </div>
        ))
      )}
    </div>
  );
}

function PacketsModule() {
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [assets, setAssets] = useState<RecordEnvelope[]>([]);
  const [assetId, setAssetId] = useState('');
  const [selected, setSelected] = useState('');
  const [packetMode, setPacketMode] = useState<'packet' | 'citation'>('packet');
  const [markdown, setMarkdown] = useState('');
  useEffect(() => {
    api.assets().then((response) => setAssets(response.items));
  }, []);
  useEffect(() => {
    api.listFindings(assetId).then((response) => {
      setFindings(response.items);
      setSelected((current) => (response.items.some((finding) => finding.id === current) ? current : response.items[0]?.id || ''));
    });
  }, [assetId]);
  useEffect(() => {
    if (!selected) {
      setMarkdown('');
      return;
    }
    const loader = packetMode === 'citation' ? api.citationBundle(selected, assetId) : api.packet(selected);
    loader.then((response) => setMarkdown(response.markdown));
  }, [selected, assetId, packetMode]);
  const downloadHref = selected
    ? packetMode === 'citation'
      ? `/api/findings/${selected}/citation-bundle?download=1${assetId ? `&asset_id=${encodeURIComponent(assetId)}` : ''}`
      : `/api/findings/${selected}/packet?download=1`
    : '';
  return (
    <section className="module-page two-column">
      <div>
        <h1>Packets</h1>
        <div className="segmented">
          <button type="button" className={packetMode === 'packet' ? 'active' : ''} onClick={() => setPacketMode('packet')}>
            Finding Packet
          </button>
          <button type="button" className={packetMode === 'citation' ? 'active' : ''} onClick={() => setPacketMode('citation')}>
            Citation Bundle
          </button>
        </div>
        <select value={assetId} onChange={(event) => setAssetId(event.target.value)}>
          <option value="">All assets</option>
          {assets.map((asset) => <option key={asset.id} value={asset.id}>{assetLabel(asset)}</option>)}
        </select>
        <select value={selected} onChange={(event) => setSelected(event.target.value)}>
          <option value="">Select finding</option>
          {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.payload.title}</option>)}
        </select>
        <div className="packet-actions">
          <button onClick={() => navigator.clipboard.writeText(markdown)}><Clipboard size={15} /> Copy Markdown</button>
          {selected && <a className="button-link" href={downloadHref}><Download size={15} /> Download</a>}
        </div>
      </div>
      <pre className="packet-preview large">{markdown}</pre>
    </section>
  );
}

function SettingsModule({ onLock }: { onLock: () => void }) {
  const [settings, setSettings] = useState<Record<string, unknown>>({});
  useEffect(() => {
    api.settings().then(setSettings);
  }, []);
  return (
    <section className="module-page">
      <h1>Settings</h1>
      <div className="settings-grid">
        {Object.entries(settings).map(([key, value]) => (
          <div key={key}>
            <span>{key.replaceAll('_', ' ')}</span>
            <strong>{String(value)}</strong>
          </div>
        ))}
      </div>
      <button className="danger" onClick={onLock}><Lock size={15} /> Lock vault</button>
    </section>
  );
}

function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  );
}

function TextArea({ label, value, onChange, compact = false }: { label: string; value: string; onChange: (value: string) => void; compact?: boolean }) {
  return (
    <label className={compact ? 'compact' : ''}>
      <span>{label}</span>
      <textarea value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );
}

function MarkdownTextArea({ label, value, onChange }: { label: string; value: string; onChange: (value: string) => void }) {
  const [mode, setMode] = useState<'write' | 'preview'>('write');
  return (
    <div className="markdown-field">
      <div className="markdown-field-head">
        <span>{label}</span>
        <div className="mini-tabs" role="tablist" aria-label={`${label} mode`}>
          <button type="button" className={mode === 'write' ? 'active' : ''} onClick={() => setMode('write')}>
            Write
          </button>
          <button type="button" className={mode === 'preview' ? 'active' : ''} onClick={() => setMode('preview')}>
            Preview
          </button>
        </div>
      </div>
      {mode === 'write' ? (
        <textarea value={value} onChange={(event) => onChange(event.target.value)} />
      ) : (
        <div className="markdown-preview">{renderMarkdown(value)}</div>
      )}
    </div>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: string[] }) {
  return (
    <label className="compact">
      <span>{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => <option key={option}>{option}</option>)}
      </select>
    </label>
  );
}

function MiniList({ records, primary }: { records: RecordEnvelope[]; primary: string }) {
  return (
    <div className="mini-list">
      {records.map((record) => (
        <div key={record.id}>
          <strong>{String(record.payload[primary] || record.payload.original_path || record.id)}</strong>
          <small>{record.id.slice(0, 8)}</small>
        </div>
      ))}
    </div>
  );
}

function RelationPanel({ title, records, empty }: { title: string; records: RecordEnvelope[]; empty: string }) {
  return (
    <Panel title={`${title} (${records.length})`}>
      {records.length === 0 ? (
        <p className="muted">{empty}</p>
      ) : (
        <div className="relation-list">
          {records.map((record) => (
            <div key={record.id}>
              <strong>{recordTitle(record)}</strong>
              <span>{relationSummary(record)}</span>
              <small>{record.kind} · {record.id.slice(0, 8)}</small>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function AssetLinkEditor({
  assets,
  linked,
  value,
  onChange,
  onLink,
  onUnlink,
}: {
  assets: RecordEnvelope[];
  linked: RecordEnvelope[];
  value: string;
  onChange: (value: string) => void;
  onLink: () => void;
  onUnlink: (assetId: string) => void;
}) {
  const linkedIds = new Set(linked.map((asset) => asset.id));
  return (
    <>
      <div className="asset-linker">
        <select value={value} onChange={(event) => onChange(event.target.value)}>
          <option value="">Select asset</option>
          {assets.filter((asset) => !linkedIds.has(asset.id)).map((asset) => (
            <option key={asset.id} value={asset.id}>{assetLabel(asset)}</option>
          ))}
        </select>
        <button onClick={onLink}>Link</button>
      </div>
      <div className="chip-list">
        {linked.map((asset) => (
          <button key={asset.id} onClick={() => onUnlink(asset.id)} title="Unlink asset">
            {assetLabel(asset)}
          </button>
        ))}
      </div>
    </>
  );
}

function attackPathRecords(path: AttackPath) {
  return [...(path.findings || []), ...(path.evidence || []), ...(path.notes || []), ...(path.credentials || [])];
}

function attackPathMapNodes(path: AttackPath, included: Record<string, boolean>) {
  const linked = attackPathRecords(path).filter((record) => included[record.id] !== false);
  const findings = linked.filter((record) => record.kind === 'finding');
  const evidence = linked.filter((record) => record.kind === 'evidence');
  const notes = linked.filter((record) => record.kind === 'note');
  const credentials = linked.filter((record) => record.kind === 'credential');
  return [
    { record: path, kind: 'asset', x: 310, y: 150 },
    ...spreadNodes(findings, 'finding', 110, 150),
    ...spreadNodes(evidence, 'evidence', 510, 75),
    ...spreadNodes(notes, 'note', 510, 150),
    ...spreadNodes(credentials, 'credential', 510, 225),
  ];
}

function spreadNodes(records: RecordEnvelope[], kind: string, x: number, centerY: number) {
  const gap = records.length > 2 ? 58 : 70;
  const start = centerY - ((records.length - 1) * gap) / 2;
  return records.map((record, index) => ({ record, kind, x, y: start + index * gap }));
}

export function buildAttackPathMarkdown(path: AttackPath, included: Record<string, boolean>) {
  const sections: Array<[string, RecordEnvelope[]]> = [
    ['Findings', path.findings || []],
    ['Evidence', path.evidence || []],
    ['Notes', path.notes || []],
    ['Credential Context', path.credentials || []],
  ];
  const lines = [
    `# Attack Path: ${assetLabel(path)}`,
    '',
    '## Asset',
    '',
    `- Name: ${assetLabel(path)}`,
    `- Type: ${String(path.payload.type || 'asset')}`,
    `- Value: ${String(path.payload.value || '')}`,
    `- Risk Score: ${path.risk_score}`,
    '',
  ];
  sections.forEach(([title, records]) => {
    lines.push(`## ${title}`, '');
    const selected = records.filter((record) => included[record.id] !== false);
    if (selected.length === 0) {
      lines.push('- None', '');
      return;
    }
    selected.forEach((record) => {
      const summary = relationSummary(record);
      lines.push(`- [${record.kind}:${record.id.slice(0, 8)}] ${recordTitle(record)}${summary ? ` - ${summary}` : ''}`);
    });
    lines.push('');
  });
  lines.push('## Completeness Checks', '');
  (path.checks || []).forEach((check) => lines.push(`- ${check}`));
  return `${lines.join('\n').trim()}\n`;
}

function truncate(value: string, limit: number) {
  return value.length > limit ? `${value.slice(0, limit - 1)}...` : value;
}

function nodeClipId(id: string) {
  return `node-clip-${id.replace(/[^a-zA-Z0-9_-]/g, '-')}`;
}

function PathColumn({ title, records }: { title: string; records: RecordEnvelope[] }) {
  return (
    <div className="path-column">
      <h2>{title}</h2>
      {records.length === 0 ? (
        <span className="muted">None</span>
      ) : (
        records.map((record) => (
          <div key={record.id}>
            <strong>{recordTitle(record)}</strong>
            <small>{relationSummary(record) || record.kind}</small>
          </div>
        ))
      )}
    </div>
  );
}

function EvidenceCards({ records }: { records: RecordEnvelope[] }) {
  return (
    <div className="evidence-grid compact-grid">
      {records.map((record) => (
        <EvidenceCard key={record.id} record={record} />
      ))}
    </div>
  );
}

function EvidenceCard({ record }: { record: RecordEnvelope }) {
  const kind = String(record.payload.kind || 'file');
  const caption = String(record.payload.caption || record.payload.original_path || record.id);
  const isImage = isImageEvidence(record);
  return (
    <div className="evidence-card">
      {isImage ? (
        <img src={`/api/evidence/${record.id}/preview`} alt={caption} />
      ) : (
        <div className="file-preview">
          <FileText size={26} />
        </div>
      )}
      <div>
        <strong>{caption}</strong>
        <small>{kind} · {record.id.slice(0, 8)}</small>
      </div>
      <a className="button-link" href={`/api/evidence/${record.id}/download`}>
        <Download size={14} /> Export
      </a>
    </div>
  );
}

export function OCRPanel({
  record,
  status,
  error,
  onExtract,
}: {
  record: RecordEnvelope;
  status: OCRStatus | null;
  error?: string;
  onExtract: () => void;
}) {
  const canOCR = isImageEvidence(record);
  const ocrState = String(record.payload.ocr_status || 'not_run');
  const text = String(record.payload.ocr_text || '');
  const unavailable = status && !status.available;
  return (
    <Panel title="OCR">
      <div className="ocr-panel">
        <div className="ocr-status-row">
          <span className={`status-pill ${ocrState}`}>{ocrState}</span>
          <small>{status?.version || status?.engine || 'tesseract'}</small>
        </div>
        {!canOCR && <p className="muted">OCR is available for screenshot and image evidence.</p>}
        {unavailable && <p className="muted">{status?.error || 'Install tesseract to enable local OCR.'}</p>}
        {error && <div className="notice error">{error}</div>}
        <button className="primary full" onClick={onExtract} disabled={!canOCR || !!unavailable}>
          Extract OCR
        </button>
        {text && (
          <>
            <textarea className="ocr-text" readOnly value={text} />
            <button onClick={() => navigator.clipboard.writeText(text)}>
              <Clipboard size={14} /> Copy OCR text
            </button>
          </>
        )}
      </div>
    </Panel>
  );
}

function isImageEvidence(record: RecordEnvelope) {
  const kind = String(record.payload.kind || 'file');
  return kind === 'screenshot' || /\.(png|jpe?g|webp|gif|bmp|tiff?)$/i.test(String(record.payload.original_path || ''));
}

function EmptyState({ title }: { title: string }) {
  return <div className="empty-panel"><AlertTriangle size={24} /><p>{title}</p></div>;
}

function listToText(values?: string[]) {
  return (values || []).join('\n');
}

function listToCSV(values?: string[]) {
  return (values || []).join(', ');
}

function textToList(value: string) {
  return value.split(/\n|,/).map((item) => item.trim()).filter(Boolean);
}

function importSummary(result: { assets: number; findings: number; evidence: number; notes?: number }) {
  const parts = [
    `${result.assets} assets`,
    `${result.findings} findings`,
    `${result.evidence} evidence`,
  ];
  if (result.notes) parts.push(`${result.notes} notes`);
  return `Imported ${parts.join(', ')}.`;
}

function duplicateCandidatesForAsset(assetId: string, groups: AssetDuplicateGroup[]) {
  const candidates = new Map<string, AssetDuplicateItem & { reason: string }>();
  if (!assetId) return [];
  groups.forEach((group) => {
    if (!group.items.some((item) => item.id === assetId)) return;
    group.items.forEach((item) => {
      if (item.id === assetId || candidates.has(item.id)) return;
      candidates.set(item.id, { ...item, reason: group.reason });
    });
  });
  return Array.from(candidates.values()).sort((left, right) => assetLabel(left).localeCompare(assetLabel(right)));
}

function renderMarkdown(value: string) {
  if (!value.trim()) return <p className="muted">No content yet.</p>;

  const blocks: ReactNode[] = [];
  const lines = value.replace(/\r\n/g, '\n').split('\n');
  let paragraph: string[] = [];
  let unordered: string[] = [];
  let ordered: string[] = [];
  let code: string[] = [];
  let inCode = false;

  const flushParagraph = () => {
    if (!paragraph.length) return;
    blocks.push(<p key={`p-${blocks.length}`}>{formatInlineMarkdown(paragraph.join(' '))}</p>);
    paragraph = [];
  };
  const flushUnordered = () => {
    if (!unordered.length) return;
    blocks.push(<ul key={`ul-${blocks.length}`}>{unordered.map((item, index) => <li key={index}>{formatInlineMarkdown(item)}</li>)}</ul>);
    unordered = [];
  };
  const flushOrdered = () => {
    if (!ordered.length) return;
    blocks.push(<ol key={`ol-${blocks.length}`}>{ordered.map((item, index) => <li key={index}>{formatInlineMarkdown(item)}</li>)}</ol>);
    ordered = [];
  };
  const flushTextBlocks = () => {
    flushParagraph();
    flushUnordered();
    flushOrdered();
  };

  lines.forEach((line) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('```')) {
      if (inCode) {
        blocks.push(<pre key={`code-${blocks.length}`}><code>{code.join('\n')}</code></pre>);
        code = [];
        inCode = false;
      } else {
        flushTextBlocks();
        inCode = true;
      }
      return;
    }
    if (inCode) {
      code.push(line);
      return;
    }
    if (!trimmed) {
      flushTextBlocks();
      return;
    }
    const heading = /^(#{1,3})\s+(.+)$/.exec(trimmed);
    if (heading) {
      flushTextBlocks();
      const content = formatInlineMarkdown(heading[2]);
      if (heading[1].length === 1) blocks.push(<h3 key={`h-${blocks.length}`}>{content}</h3>);
      else if (heading[1].length === 2) blocks.push(<h4 key={`h-${blocks.length}`}>{content}</h4>);
      else blocks.push(<h5 key={`h-${blocks.length}`}>{content}</h5>);
      return;
    }
    const bullet = /^[-*]\s+(.+)$/.exec(trimmed);
    if (bullet) {
      flushParagraph();
      flushOrdered();
      unordered.push(bullet[1]);
      return;
    }
    const numbered = /^\d+\.\s+(.+)$/.exec(trimmed);
    if (numbered) {
      flushParagraph();
      flushUnordered();
      ordered.push(numbered[1]);
      return;
    }
    if (trimmed.startsWith('>')) {
      flushTextBlocks();
      blocks.push(<blockquote key={`quote-${blocks.length}`}>{formatInlineMarkdown(trimmed.replace(/^>\s?/, ''))}</blockquote>);
      return;
    }
    flushUnordered();
    flushOrdered();
    paragraph.push(trimmed);
  });

  if (inCode) blocks.push(<pre key={`code-${blocks.length}`}><code>{code.join('\n')}</code></pre>);
  flushTextBlocks();
  return blocks;
}

function formatInlineMarkdown(value: string) {
  return value.split(/(`[^`]+`|\*\*[^*]+\*\*)/g).filter(Boolean).map((part, index) => {
    if (part.startsWith('`') && part.endsWith('`')) return <code key={index}>{part.slice(1, -1)}</code>;
    if (part.startsWith('**') && part.endsWith('**')) return <strong key={index}>{part.slice(2, -2)}</strong>;
    return <span key={index}>{part}</span>;
  });
}

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KB', 'MB', 'GB'];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index += 1;
  }
  return `${value.toFixed(value >= 10 ? 0 : 1)} ${units[index]}`;
}

function recordTitle(record: RecordEnvelope) {
  return String(
    record.payload.title ||
      record.payload.name ||
      record.payload.caption ||
      record.payload.username ||
      record.payload.original_path ||
      record.payload.text ||
      record.id,
  );
}

function assetLabel(record: RecordEnvelope) {
  return String(record.payload.name || record.payload.value || record.id);
}

function assetSummary(record: RecordEnvelope) {
  return [
    record.payload.type,
    record.payload.value,
    ...(Array.isArray(record.payload.tags) ? record.payload.tags : []),
  ].filter(Boolean).join(' · ');
}

function assetSearchText(record: RecordEnvelope) {
  return [
    assetLabel(record),
    record.payload.type,
    record.payload.value,
    record.payload.notes,
    ...(Array.isArray(record.payload.tags) ? record.payload.tags : []),
  ].filter(Boolean).join(' ').toLowerCase();
}

function relationSummary(record: RecordEnvelope) {
  if (record.kind === 'finding') {
    return [record.payload.severity, record.payload.status, record.payload.summary].filter(Boolean).join(' · ');
  }
  if (record.kind === 'evidence') {
    return [record.payload.kind, record.payload.caption, record.payload.original_path].filter(Boolean).join(' · ');
  }
  if (record.kind === 'credential') {
    return [record.payload.username, record.payload.scope].filter(Boolean).join(' · ');
  }
  if (record.kind === 'note') {
    return [record.payload.asset, record.payload.text].filter(Boolean).join(' · ');
  }
  return [record.payload.type, record.payload.value].filter(Boolean).join(' · ');
}

function formatDate(value: string) {
  if (!value) return '';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
}
