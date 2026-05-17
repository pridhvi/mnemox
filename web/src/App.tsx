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
import { type ElementType, type FormEvent, useCallback, useEffect, useState } from 'react';
import { api } from './api';
import { defaultMetrics, metricLabels, metricOptions, metricOrder, metricsFromVector, vectorFromMetrics } from './cvss';
import type { FindingPayload, FindingRecord, RecordEnvelope, SearchHit } from './types';

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
        {active === 'evidence' && <RecordTable title="Evidence" loader={api.evidence} />}
        {active === 'notes' && <RecordTable title="Notes" loader={api.notes} />}
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
  const [form, setForm] = useState<FindingPayload>(emptyFinding);
  const [scopeText, setScopeText] = useState('');
  const [refsText, setRefsText] = useState('');
  const [questionsText, setQuestionsText] = useState('');
  const [noteText, setNoteText] = useState('');
  const [noteAsset, setNoteAsset] = useState('');
  const [evidenceFile, setEvidenceFile] = useState<File | null>(null);
  const [evidenceCaption, setEvidenceCaption] = useState('');
  const [metrics, setMetrics] = useState(defaultMetrics());
  const [vector, setVector] = useState('');
  const [cvssNotes, setCvssNotes] = useState('');
  const [error, setError] = useState('');

  const loadFindings = useCallback(async () => {
    const response = await api.listFindings();
    setFindings(response.items);
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

  async function scoreCvss() {
    if (!selectedId) return;
    await api.scoreCvss(selectedId, { vector: vector || undefined, metrics, notes: cvssNotes });
    await loadFindings();
    await loadDetail();
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
              <TextArea label="Summary" value={form.summary} onChange={(summary) => setForm({ ...form, summary })} />
              <TextArea label="Technical Details" value={form.technical_details} onChange={(technical_details) => setForm({ ...form, technical_details })} />
              <TextArea label="Impact" value={form.impact} onChange={(impact) => setForm({ ...form, impact })} />
              <TextArea label="Remediation" value={form.remediation} onChange={(remediation) => setForm({ ...form, remediation })} />
              <TextArea label="Validation" value={form.validation} onChange={(validation) => setForm({ ...form, validation })} />
              <TextArea label="Open Questions" value={questionsText} onChange={setQuestionsText} />
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
                          className={metrics[metric] === option.value ? 'active' : ''}
                          onClick={() => {
                            setVector('');
                            setMetrics({ ...metrics, [metric]: option.value });
                          }}
                        >
                          {option.value}
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

            <Panel title="Notes">
              <div className="inline-form">
                <input value={noteText} onChange={(event) => setNoteText(event.target.value)} placeholder="Quick note" />
                <input value={noteAsset} onChange={(event) => setNoteAsset(event.target.value)} placeholder="Asset" />
                <button onClick={addNote}>Add</button>
              </div>
              <MiniList records={detail.notes || []} primary="text" />
            </Panel>

            <Panel title="Evidence">
              <input type="file" onChange={(event) => setEvidenceFile(event.target.files?.[0] || null)} />
              <input value={evidenceCaption} onChange={(event) => setEvidenceCaption(event.target.value)} placeholder="Caption" />
              <button onClick={uploadEvidence}>Attach evidence</button>
              <MiniList records={detail.evidence || []} primary="caption" />
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

function AssetsModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [form, setForm] = useState({ name: '', type: 'host', value: '', notes: '', tags: '' });
  const [importMessage, setImportMessage] = useState('');
  const [screenshotPath, setScreenshotPath] = useState('');

  async function load() {
    const response = await api.assets();
    setItems(response.items);
  }

  useEffect(() => {
    load();
  }, []);

  async function create(event: FormEvent) {
    event.preventDefault();
    await api.createAsset({ ...form, tags: textToList(form.tags) });
    setForm({ name: '', type: 'host', value: '', notes: '', tags: '' });
    await load();
  }

  async function importFile(kind: 'nmap' | 'nuclei', file: File | null) {
    if (!file) return;
    const data = new FormData();
    data.append('file', file);
    const result = kind === 'nmap' ? await api.importNmap(data) : await api.importNuclei(data);
    setImportMessage(`Imported ${result.assets} assets, ${result.findings} findings, ${result.evidence} evidence items.`);
    await load();
  }

  async function importScreenshots() {
    const result = await api.importScreenshots(screenshotPath);
    setImportMessage(`Imported ${result.evidence} screenshots.`);
    setScreenshotPath('');
  }

  return (
    <section className="module-page two-column">
      <div>
        <h1>Assets</h1>
        <div className="table">
          {items.map((item) => (
            <div className="table-row" key={item.id}>
              <strong>{String(item.payload.name)}</strong>
              <span>{String(item.payload.type || 'asset')}</span>
              <small>{String(item.payload.value || '')}</small>
            </div>
          ))}
        </div>
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
            <span>Screenshot Folder Path</span>
            <input value={screenshotPath} onChange={(event) => setScreenshotPath(event.target.value)} placeholder="/path/to/screenshots" />
          </label>
          <button onClick={importScreenshots}>Import screenshots</button>
          {importMessage && <p className="muted">{importMessage}</p>}
        </div>
      </div>
    </section>
  );
}

function CredentialsModule() {
  const [items, setItems] = useState<RecordEnvelope[]>([]);
  const [form, setForm] = useState({ name: '', username: '', secret: '', scope: '', tags: '' });
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  async function load() {
    const response = await api.credentials();
    setItems(response.items);
  }
  useEffect(() => {
    load();
  }, []);
  async function create(event: FormEvent) {
    event.preventDefault();
    await api.createCredential({ ...form, tags: textToList(form.tags) });
    setForm({ name: '', username: '', secret: '', scope: '', tags: '' });
    await load();
  }
  async function reveal(id: string) {
    const response = await api.revealCredential(id);
    setRevealed({ ...revealed, [id]: response.secret });
  }
  return (
    <section className="module-page two-column">
      <div>
        <h1>Credentials</h1>
        <div className="table">
          {items.map((item) => (
            <div className="table-row" key={item.id}>
              <strong>{String(item.payload.name)}</strong>
              <span>{String(item.payload.username || 'no username')}</span>
              <button onClick={() => reveal(item.id)}>{revealed[item.id] ? revealed[item.id] : 'Reveal'}</button>
            </div>
          ))}
        </div>
      </div>
      <form className="side-form" onSubmit={create}>
        <h2>Add Credential</h2>
        {(['name', 'username', 'secret', 'scope', 'tags'] as const).map((key) => (
          <input key={key} type={key === 'secret' ? 'password' : 'text'} value={form[key]} onChange={(event) => setForm({ ...form, [key]: event.target.value })} placeholder={key} />
        ))}
        <button className="primary">Save credential</button>
      </form>
    </section>
  );
}

function SearchModule() {
  const [query, setQuery] = useState('');
  const [items, setItems] = useState<SearchHit[]>([]);
  async function runSearch() {
    const response = await api.search(query);
    setItems(response.items);
  }
  return (
    <section className="module-page">
      <h1>Search</h1>
      <div className="search-bar">
        <input value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={(event) => event.key === 'Enter' && runSearch()} placeholder="Search findings, notes, evidence, credential metadata" />
        <button className="primary" onClick={runSearch}>Search</button>
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
  return (
    <section className="module-page">
      <h1>Attack Paths</h1>
      <div className="empty-panel">
        <GitBranch size={28} />
        <p>Relationship hooks are available through linked notes and evidence. Graph visualization comes after the finding and evidence model settles.</p>
      </div>
    </section>
  );
}

function PacketsModule() {
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [selected, setSelected] = useState('');
  const [markdown, setMarkdown] = useState('');
  useEffect(() => {
    api.listFindings().then((response) => {
      setFindings(response.items);
      setSelected(response.items[0]?.id || '');
    });
  }, []);
  useEffect(() => {
    if (selected) api.packet(selected).then((response) => setMarkdown(response.markdown));
  }, [selected]);
  return (
    <section className="module-page two-column">
      <div>
        <h1>Packets</h1>
        <select value={selected} onChange={(event) => setSelected(event.target.value)}>
          {findings.map((finding) => <option key={finding.id} value={finding.id}>{finding.payload.title}</option>)}
        </select>
        <div className="packet-actions">
          <button onClick={() => navigator.clipboard.writeText(markdown)}><Clipboard size={15} /> Copy Markdown</button>
          {selected && <a className="button-link" href={`/api/findings/${selected}/packet?download=1`}><Download size={15} /> Download</a>}
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

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
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

function EmptyState({ title }: { title: string }) {
  return <div className="empty-panel"><AlertTriangle size={24} /><p>{title}</p></div>;
}

function listToText(values?: string[]) {
  return (values || []).join('\n');
}

function textToList(value: string) {
  return value.split(/\n|,/).map((item) => item.trim()).filter(Boolean);
}

function formatDate(value: string) {
  if (!value) return '';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }).format(new Date(value));
}
