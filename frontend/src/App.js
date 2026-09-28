import { useEffect, useRef, useState } from "react";
import { BrowserRouter, Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";
import { Html5Qrcode } from "html5-qrcode";
import axios from "axios";
import "@/App.css";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const client = axios.create({ baseURL: API });
const headers = () => ({ Authorization: `Bearer ${sessionStorage.getItem("euphoria_token") || ""}` });
const errorText = (e) => typeof e?.response?.data?.detail === "string" ? e.response.data.detail : "Something went wrong. Please try again.";

function currentUser() { try { return JSON.parse(sessionStorage.getItem("euphoria_user") || "null"); } catch { return null; } }
function homeFor(role) { return role === "SCANNER" ? "/scanner" : "/"; }

function Login() {
  const [email, setEmail] = useState("admin@euphoria.local"); const [password, setPassword] = useState("EuphoriaAdmin!2026"); const [error, setError] = useState(""); const navigate = useNavigate();
  async function submit(e) {
    e.preventDefault(); setError("");
    try {
      const r = await client.post("/auth/login", { email, password }, { withCredentials: true });
      if (r.data.user.role !== "ADMIN") { setError("Scanner operators must use the scanner portal at /scanner/login"); return; }
      sessionStorage.setItem("euphoria_token", r.data.token); sessionStorage.setItem("euphoria_user", JSON.stringify(r.data.user)); navigate("/");
    } catch (err) { setError(errorText(err)); }
  }
  return <main className="auth-shell"><section className="auth-panel">
    <img src="/logos/sage-naac.png" alt="SAGE University Indore · NAAC A+" className="sage-lockup" />
    <p className="eyebrow">CULTURAL FEST OPERATIONS</p>
    <div className="euphoria-hero"><img src="/logos/euphoria-logo.png" alt="SAGE EUPHORIA" /></div>
    <p className="muted">Admin control room for the EUPHORIA entry system.</p>
    <form onSubmit={submit} data-testid="login-form">
      <label>Admin email or username<input data-testid="login-email-input" value={email} onChange={e => setEmail(e.target.value)} /></label>
      <label>Password<input data-testid="login-password-input" type="password" value={password} onChange={e => setPassword(e.target.value)} /></label>
      {error && <div className="alert danger" data-testid="login-error">{error}</div>}
      <button className="primary full" data-testid="login-submit-button">Enter control room →</button>
    </form>
    <p className="hint">Scanner operator? Open <Link className="link" data-testid="go-scanner-login" to="/scanner/login">/scanner/login</Link></p>
  </section><div className="auth-art"><div><p className="eyebrow cyan">ONE GATE. EVERY ENTRY.</p><h2>Make the moment<br /><span>count.</span></h2></div></div></main>;
}

function ScannerLogin() {
  const [username, setUsername] = useState(""); const [password, setPassword] = useState(""); const [error, setError] = useState(""); const navigate = useNavigate();
  async function submit(e) {
    e.preventDefault(); setError("");
    try {
      const r = await client.post("/auth/login", { email: username, password }, { withCredentials: true });
      if (r.data.user.role !== "SCANNER") { setError("Please use a scanner account. Admins use /login instead."); return; }
      sessionStorage.setItem("euphoria_token", r.data.token); sessionStorage.setItem("euphoria_user", JSON.stringify(r.data.user)); navigate("/scanner");
    } catch (err) { setError(errorText(err)); }
  }
  return <main className="scanner-login-shell">
    <div className="scanner-login-card">
      <img src="/logos/euphoria-logo.png" alt="SAGE Euphoria" className="scanner-login-logo" />
      <p className="eyebrow cyan">ENTRY SCANNER PORTAL</p>
      <h1>Operator sign in</h1>
      <p className="muted">Scanner accounts only. This device will keep the camera active for high-speed scans.</p>
      <form onSubmit={submit} data-testid="scanner-login-form">
        <label>Scanner username<input data-testid="scanner-login-username" autoFocus autoCapitalize="none" autoComplete="username" value={username} onChange={e => setUsername(e.target.value)} /></label>
        <label>Password<input data-testid="scanner-login-password" type="password" autoComplete="current-password" value={password} onChange={e => setPassword(e.target.value)} /></label>
        {error && <div className="alert danger" data-testid="scanner-login-error">{error}</div>}
        <button className="primary full" data-testid="scanner-login-submit">Start scanning →</button>
      </form>
      <p className="hint">Admin? Return to <Link className="link" to="/login">admin login</Link></p>
    </div>
  </main>;
}

function Shell({ children }) {
  const navigate = useNavigate(); const user = currentUser() || {};
  async function logout() { const goto = user.role === "SCANNER" ? "/scanner/login" : "/login"; try { await client.post("/auth/logout", {}, { headers: headers(), withCredentials: true }); } finally { sessionStorage.clear(); navigate(goto); } }
  return <div className="app-shell"><aside>
    <img src="/logos/euphoria-logo.png" alt="SAGE Euphoria" className="side-euphoria" />
    <div className="side-label">CONTROL ROOM</div>
    <nav>
      <Link data-testid="nav-dashboard" to="/">◈ <span>Overview</span></Link>
      <Link data-testid="nav-registrations" to="/registrations">▦ <span>Registrations</span></Link>
      <Link data-testid="nav-entries" to="/entries">✓ <span>Entries</span></Link>
      <Link data-testid="nav-import" to="/import">↥ <span>Import CSV</span></Link>
      <Link data-testid="nav-scanner-users" to="/scanner-users">⌗ <span>Scanner accounts</span></Link>
    </nav>
    <div className="side-bottom">
      <img src="/logos/sage-naac.png" alt="SAGE University · NAAC A+" className="side-sage" />
      <div className="operator"><span className="status-dot" />{user.display_name || "Admin"}<small>{user.role || "ADMIN"}</small></div>
      <button className="ghost" data-testid="logout-button" onClick={logout}>↪ Sign out</button>
    </div>
  </aside><main className="content">{children}</main></div>;
}

function Dashboard() { const [stats, setStats] = useState({}); const [activity, setActivity] = useState([]); useEffect(() => { Promise.all([client.get("/dashboard/stats", { headers: headers() }), client.get("/dashboard/recent-scans", { headers: headers() })]).then(([a, b]) => { setStats(a.data); setActivity(b.data); }); }, []); return <Shell><header className="topbar"><div><p className="eyebrow">TUESDAY · OPERATIONS</p><h1>Good morning, <em>team.</em></h1></div><Link className="primary compact" data-testid="open-scanner-button" to="/scanner">Open scanner ↗</Link></header><section className="hero-band"><div><p className="eyebrow cyan">EUPHORIA 2026</p><h2>Entry, <span>in rhythm.</span></h2><p className="muted">One gate. Multiple operators. Zero duplicate entries.</p></div><div className="hero-orbit">E<span>•</span></div></section><div className="metric-grid"><Metric label="Registered" value={stats.total_registrations ?? "—"} tone="cyan"/><Metric label="Entered today" value={stats.entries_today ?? "—"} tone="green"/><Metric label="Entry rate" value={`${stats.entry_percentage ?? 0}%`} tone="gold"/><Metric label="Duplicate attempts" value={stats.duplicate_attempts ?? "—"} tone="red"/></div><section className="section-heading"><div><p className="eyebrow">LIVE ACTIVITY</p><h2>Recent scans</h2></div><span className="live-pill"><i /> LIVE</span></section><div className="activity-list">{activity.length ? activity.map((item, i) => <div className="activity-row" key={item.id || i} data-testid={`activity-row-${i}`}><span className={`scan-icon ${item.status === "ENTRY_ALLOWED" ? "ok" : "warn"}`}>{item.status === "ENTRY_ALLOWED" ? "✓" : "!"}</span><div><strong>{item.message}</strong><small>{item.registration_id || item.token_fingerprint}</small></div><time>{new Date(item.attempted_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time><b className={item.status === "ENTRY_ALLOWED" ? "text-green" : "text-gold"}>{item.status.replaceAll("_", " ")}</b></div>) : <div className="empty">No scans yet. The gate is ready.</div>}</div></Shell>; }
function Metric({ label, value, tone }) { return <div className={`metric ${tone}`} data-testid={`metric-${label.toLowerCase().replaceAll(" ", "-")}`}><small>{label}</small><strong>{value}</strong><span>system count</span></div>; }

const EMPTY_PARTICIPANT = { registration_number: "", participant_full_name: "", email: "", phone: "", event_name: "EUPHORIA 2026", event_category: "GENERAL" };

function Registrations() {
  const [data, setData] = useState({ items: [], total: 0 });
  const [search, setSearch] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [form, setForm] = useState(EMPTY_PARTICIPANT);
  const [saving, setSaving] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [sending, setSending] = useState(false);
  const [sendReport, setSendReport] = useState(null);
  async function load(q = search) { const r = await client.get(`/registrations?page=1&page_size=50&search=${encodeURIComponent(q)}`, { headers: headers() }); setData(r.data); setSelected(new Set()); }
  useEffect(() => { load(""); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  async function generate(id) { setError(""); try { const r = await client.post(`/passes/${id}/generate`, {}, { headers: headers() }); setMessage(`Pass ready · QR ending ${r.data.pass.qr_token_last4}`); await load(); } catch (e) { setError(errorText(e)); } }
  async function downloadPdf(passId, regNo) {
    try { const r = await client.get(`/passes/${passId}/pdf`, { headers: headers(), responseType: "blob" });
      const url = URL.createObjectURL(new Blob([r.data], { type: "application/pdf" }));
      const a = document.createElement("a"); a.href = url; a.download = `euphoria-${regNo}.pdf`; a.click(); URL.revokeObjectURL(url);
    } catch (e) { setError(errorText(e)); }
  }
  async function saveParticipant(e) {
    e.preventDefault(); setSaving(true); setError(""); setMessage("");
    try {
      const created = await client.post("/registrations", form, { headers: headers() });
      const genRes = await client.post(`/passes/${created.data.id}/generate`, {}, { headers: headers() });
      setShowAdd(false); setForm(EMPTY_PARTICIPANT);
      setMessage(`${created.data.participant_full_name} added · Pass ready · QR ending ${genRes.data.pass.qr_token_last4}`);
      await load();
    } catch (e2) { setError(errorText(e2)); }
    finally { setSaving(false); }
  }
  function toggleOne(id) { setSelected(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; }); }
  function toggleAll() { const eligible = data.items.filter(r => r.pass_id).map(r => r.id); setSelected(s => s.size === eligible.length ? new Set() : new Set(eligible)); }
  async function bulkSend(scope) {
    setSending(true); setError(""); setMessage(""); setSendReport(null);
    const payload = scope === "PENDING_ALL" ? { scope: "PENDING_ALL", registration_ids: [] } : { scope: "SELECTED", registration_ids: [...selected] };
    try { const r = await client.post("/passes/bulk-send", payload, { headers: headers() }); setSendReport(r.data); await load(); }
    catch (e) { setError(errorText(e)); }
    finally { setSending(false); }
  }
  const eligibleIds = data.items.filter(r => r.pass_id).map(r => r.id);
  const allSelected = eligibleIds.length > 0 && selected.size === eligibleIds.length;
  return <Shell>
    <PageTitle eyebrow="PARTICIPANTS" title="Registrations" action={<div className="header-actions"><Link className="ghost compact" data-testid="import-csv-link" to="/import">Import CSV ↥</Link><button className="primary compact" data-testid="add-participant-button" onClick={() => { setShowAdd(true); setError(""); }}>+ Add participant</button></div>} />
    <div className="toolbar"><input data-testid="registration-search-input" placeholder="Search name, registration, email or phone" value={search} onChange={e => { setSearch(e.target.value); load(e.target.value); }} /><span>{data.total} records</span></div>
    <div className="bulk-bar">
      <button className="ghost compact" data-testid="bulk-send-selected" disabled={sending || selected.size === 0} onClick={() => bulkSend("SELECTED")}>{sending ? "Sending…" : `✉ Send to selected (${selected.size})`}</button>
      <button className="ghost compact" data-testid="bulk-send-pending" disabled={sending} onClick={() => bulkSend("PENDING_ALL")}>{sending ? "Sending…" : "✉ Send to all pending"}</button>
      <span className="muted">Only rows with an active pass can be emailed.</span>
    </div>
    {message && <div className="alert success" data-testid="registration-success">{message}</div>}
    {error && <div className="alert danger" data-testid="registration-error">{error}</div>}
    <div className="table-wrap"><table><thead><tr><th className="check-col"><input type="checkbox" data-testid="select-all-checkbox" checked={allSelected} onChange={toggleAll} aria-label="Select all with passes" /></th><th>Registration</th><th>Participant</th><th>Event</th><th>Category</th><th>Pass</th><th>Email</th><th>Actions</th></tr></thead><tbody>
      {data.items.map(row => <tr key={row.id} data-testid={`registration-row-${row.id}`} className={selected.has(row.id) ? "row-selected" : ""}>
        <td className="check-col"><input type="checkbox" data-testid={`select-row-${row.id}`} disabled={!row.pass_id} checked={selected.has(row.id)} onChange={() => toggleOne(row.id)} aria-label={`Select ${row.registration_number}`} /></td>
        <td className="mono">{row.registration_number}</td>
        <td><strong>{row.participant_full_name}</strong><small>{row.email}</small></td>
        <td>{row.event_name}</td>
        <td><span className="tag">{row.event_category}</span></td>
        <td><span className={`badge ${row.pass_status === "ACTIVE" ? "green" : "muted-badge"}`}>{row.pass_status}</span></td>
        <td>{row.last_sent_at ? <span className="badge green" title={new Date(row.last_sent_at).toLocaleString()}>SENT</span> : row.last_send_status === "FAILED" ? <span className="badge red-badge">FAILED</span> : <span className="badge muted-badge">—</span>}</td>
        <td className="row-actions">
          {row.pass_id
            ? <button className="table-action" data-testid={`download-pdf-${row.id}`} onClick={() => downloadPdf(row.pass_id, row.registration_number)}>Download PDF ↓</button>
            : <button className="table-action" data-testid={`generate-pass-${row.id}`} onClick={() => generate(row.id)}>Generate pass</button>}
        </td>
      </tr>)}
    </tbody></table>{!data.items.length && <div className="empty">No participants match this search.</div>}</div>
    {showAdd && <div className="modal-overlay" data-testid="add-participant-modal" onClick={() => !saving && setShowAdd(false)}>
      <form className="modal-card" onClick={e => e.stopPropagation()} onSubmit={saveParticipant}>
        <div className="modal-head"><p className="eyebrow cyan">SINGLE ENTRY</p><h2>Add participant</h2><p className="muted">Creates the registration and generates a fresh EUPHORIA pass instantly.</p></div>
        <div className="modal-grid">
          <label>Registration number<input data-testid="add-reg-number" required value={form.registration_number} onChange={e => setForm({ ...form, registration_number: e.target.value })} /></label>
          <label>Participant full name<input data-testid="add-full-name" required value={form.participant_full_name} onChange={e => setForm({ ...form, participant_full_name: e.target.value })} /></label>
          <label>Email<input data-testid="add-email" required type="email" value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} /></label>
          <label>Phone<input data-testid="add-phone" required value={form.phone} onChange={e => setForm({ ...form, phone: e.target.value })} /></label>
          <label>Event name<input data-testid="add-event-name" required value={form.event_name} onChange={e => setForm({ ...form, event_name: e.target.value })} /></label>
          <label>Event category<input data-testid="add-event-category" required value={form.event_category} onChange={e => setForm({ ...form, event_category: e.target.value })} /></label>
        </div>
        {error && <div className="alert danger" data-testid="add-error">{error}</div>}
        <div className="modal-actions">
          <button type="button" className="ghost" data-testid="add-cancel" disabled={saving} onClick={() => setShowAdd(false)}>Cancel</button>
          <button type="submit" className="primary" data-testid="add-save" disabled={saving}>{saving ? "Saving…" : "Save & generate pass"}</button>
        </div>
      </form>
    </div>}
    {sendReport && <div className="modal-overlay" data-testid="bulk-report-modal" onClick={() => setSendReport(null)}>
      <div className="modal-card" onClick={e => e.stopPropagation()}>
        <div className="modal-head"><p className="eyebrow cyan">DISPATCH SUMMARY</p><h2>Bulk email complete</h2></div>
        <div className="bulk-stats">
          <div className="bulk-stat green-stat"><small>SENT</small><strong data-testid="bulk-sent-count">{sendReport.sent}</strong></div>
          <div className="bulk-stat red-stat"><small>FAILED</small><strong data-testid="bulk-failed-count">{sendReport.failed}</strong></div>
          <div className="bulk-stat gold-stat"><small>SKIPPED</small><strong>{sendReport.skipped}</strong></div>
          <div className="bulk-stat cyan-stat"><small>TOTAL</small><strong>{sendReport.total}</strong></div>
        </div>
        {sendReport.results?.some(r => r.status === "FAILED") && <div className="failed-list"><small>DELIVERY FAILURES</small>{sendReport.results.filter(r => r.status === "FAILED").slice(0, 8).map((r, i) => <div key={i} className="failed-row"><span className="mono">{r.email}</span><span>{r.message}</span></div>)}</div>}
        <div className="modal-actions"><button className="primary" data-testid="bulk-report-close" onClick={() => setSendReport(null)}>Done</button></div>
      </div>
    </div>}
  </Shell>;
}

function PageTitle({ eyebrow, title, action }) { return <header className="topbar"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1></div>{action}</header>; }

function ImportPage() { const [preview, setPreview] = useState(null); const [busy, setBusy] = useState(false); const [result, setResult] = useState(""); async function upload(e) { const file = e.target.files[0]; if (!file) return; setBusy(true); const form = new FormData(); form.append("file", file); try { const r = await client.post("/imports/preview", form, { headers: { ...headers(), "Content-Type": "multipart/form-data" } }); setPreview(r.data); setResult(""); } catch (err) { setResult(errorText(err)); } finally { setBusy(false); } } async function confirm() { const r = await client.post(`/imports/${preview.import_id}/confirm`, {}, { headers: headers() }); setResult(`${r.data.imported} participants imported successfully.`); setPreview(null); } return <Shell><PageTitle eyebrow="DATA INTAKE" title="Import registrations" action={<Link className="ghost compact" to="/registrations">View registrations →</Link>} /><div className="import-grid"><div className="upload-zone"><div className="upload-symbol">↥</div><h2>Upload the source file</h2><p>CSV with the six required EUPHORIA registration fields.</p><label className="primary upload-button" data-testid="csv-upload-label">{busy ? "Reading file…" : "Choose CSV file"}<input data-testid="csv-file-input" type="file" accept=".csv" onChange={upload} hidden /></label><div className="expected"><small>EXPECTED COLUMNS</small><code>Registration Number · Participant Full Name · Email · Phone · Event Name · Event Category</code></div></div>{preview && <div className="preview-panel"><div className="section-heading"><div><p className="eyebrow">STEP 2 · REVIEW</p><h2>{preview.filename}</h2></div><span className="tag">{preview.summary.valid} valid</span></div><div className="import-stats"><Metric label="Total" value={preview.summary.total} tone="cyan"/><Metric label="Invalid" value={preview.summary.invalid} tone="red"/><Metric label="Duplicates" value={preview.summary.duplicates} tone="gold"/></div><div className="preview-rows">{preview.rows.map(row => <div className="preview-row" key={row.row_number}><span className={`status-chip ${row.status.toLowerCase()}`}>{row.status}</span><strong>{row.data["Participant Full Name"]}</strong><small>{row.errors.join(" · ") || row.data.Email}</small></div>)}</div><button className="primary full" data-testid="confirm-import-button" disabled={!preview.summary.valid} onClick={confirm}>Confirm import · {preview.summary.valid} rows</button></div>}{result && <div className="alert success" data-testid="import-result">{result}</div>}</div></Shell>; }

function Scanner() {
  const [result, setResult] = useState({ status: "READY", message: "Ready to scan" });
  const [count, setCount] = useState(0); const scannerRef = useRef(null); const lock = useRef(false);
  const navigate = useNavigate(); const user = currentUser() || {};
  async function signOut() { try { await client.post("/auth/logout", {}, { headers: headers(), withCredentials: true }); } finally { sessionStorage.clear(); navigate("/scanner/login"); } }
  useEffect(() => { const qr = new Html5Qrcode("reader"); scannerRef.current = qr; let started = false; qr.start({ facingMode: "environment" }, { fps: 12, qrbox: { width: 280, height: 280 } }, async decoded => { if (lock.current) return; lock.current = true; try { const r = await client.post("/scanner/verify", { token: decoded }, { headers: headers(), withCredentials: true }); setResult(r.data); if (r.data.success) setCount(c => c + 1); } catch (e) { setResult({ status: "CONNECTION_LOST", message: "ENTRY CANNOT BE VERIFIED" }); } finally { setTimeout(() => { lock.current = false; setResult(s => s.status === "ENTRY_ALLOWED" || s.status === "ALREADY_SCANNED" || s.status === "INVALID_QR" ? s : { status: "READY", message: "Ready to scan" }); }, 1800); } }, () => {}).then(() => { started = true; }).catch(() => setResult({ status: "CAMERA_ERROR", message: "Camera unavailable — allow camera access and retry." })); return () => { if (started) qr.stop().catch(() => {}); }; }, []);
  const tone = result.status === "ENTRY_ALLOWED" ? "scanner-success" : result.status === "READY" ? "scanner-ready" : "scanner-danger";
  return <div className="scanner-page">
    <header className="scanner-header">
      <img src="/logos/euphoria-logo.png" alt="SAGE Euphoria" className="scanner-brand-logo" />
      <div><p className="eyebrow cyan">ENTRY SCANNER</p><strong data-testid="scanner-operator-name">{user.display_name || user.username || "Operator"}</strong></div>
      <button className="ghost" data-testid="scanner-signout" onClick={signOut}>↪ Sign out</button>
    </header>
    <main className="scanner-main">
      <div className="scanner-copy"><p className="eyebrow cyan">ONE GATE · ONLINE</p><h1>Scan the<br /><em>moment.</em></h1><p className="muted">Keep the pass inside the frame. Verification is server-side.</p><div className="scanner-counter"><strong>{count}</strong><span>successful scans this session</span></div></div>
      <div className="scanner-stage"><div id="reader" data-testid="camera-preview" /><div className={`scan-result ${tone}`} data-testid="scan-result"><div className="result-symbol">{result.status === "ENTRY_ALLOWED" ? "✓" : result.status === "READY" ? "⌁" : "!"}</div><div><p className="eyebrow">{result.status.replaceAll("_", " ")}</p><h2>{result.message}</h2>{result.participant && <p data-testid="scan-participant">{result.participant.name} · {result.participant.registration_number}</p>}{result.entry_time && <small data-testid="scan-entry-time">{new Date(result.entry_time).toLocaleTimeString()}</small>}</div></div></div>
    </main>
  </div>;
}

function EntriesPage() {
  const [data, setData] = useState({ items: [], total: 0 });
  const [search, setSearch] = useState("");
  async function load(q = search) { const r = await client.get(`/entries?page=1&page_size=100&search=${encodeURIComponent(q)}`, { headers: headers() }); setData(r.data); }
  useEffect(() => { load(""); }, []); // eslint-disable-line react-hooks/exhaustive-deps
  async function exportCsv() {
    const r = await client.get("/entries/export", { headers: headers(), responseType: "blob" });
    const url = URL.createObjectURL(new Blob([r.data], { type: "text/csv" }));
    const a = document.createElement("a"); a.href = url; a.download = "euphoria-entries.csv"; a.click(); URL.revokeObjectURL(url);
  }
  return <Shell>
    <PageTitle eyebrow="GATE LOG" title="Entries" action={<button className="primary compact" data-testid="entries-export" onClick={exportCsv}>Export CSV ↓</button>} />
    <div className="toolbar"><input data-testid="entries-search-input" placeholder="Search name, registration, email or phone" value={search} onChange={e => { setSearch(e.target.value); load(e.target.value); }} /><span>{data.total} entries</span></div>
    <div className="table-wrap"><table><thead><tr><th>Registration</th><th>Participant</th><th>Event</th><th>Category</th><th>Entry date</th><th>Entry time</th><th>Scanner</th></tr></thead><tbody>
      {data.items.map(row => <tr key={row.id} data-testid={`entry-row-${row.id}`}>
        <td className="mono">{row.registration_number}</td>
        <td><strong>{row.participant_full_name}</strong><small>{row.email}</small></td>
        <td>{row.event_name}</td>
        <td><span className="tag">{row.event_category}</span></td>
        <td className="muted-cell">{row.server_date}</td>
        <td className="muted-cell">{row.server_time}</td>
        <td>{row.scanner_display_name || row.scanner_username || "—"}</td>
      </tr>)}
    </tbody></table>{!data.items.length && <div className="empty">No entries yet. Scans will appear here in real time.</div>}</div>
  </Shell>;
}

function ScannerUsersPage() {
  const [users, setUsers] = useState([]); const [form, setForm] = useState({ username: "", display_name: "", password: "" }); const [saving, setSaving] = useState(false); const [error, setError] = useState(""); const [message, setMessage] = useState("");
  async function load() { const r = await client.get("/scanner-users", { headers: headers() }); setUsers(r.data); }
  useEffect(() => { load(); }, []);
  async function save(e) { e.preventDefault(); setSaving(true); setError(""); setMessage(""); try { await client.post("/scanner-users", form, { headers: headers() }); setMessage(`Scanner account "${form.username}" created.`); setForm({ username: "", display_name: "", password: "" }); await load(); } catch (err) { setError(errorText(err)); } finally { setSaving(false); } }
  async function toggle(id) { try { await client.patch(`/scanner-users/${id}/toggle`, {}, { headers: headers() }); await load(); } catch (err) { setError(errorText(err)); } }
  async function reset(id, username) { const pw = window.prompt(`New password for ${username} (min 8 chars):`); if (!pw) return; try { await client.post(`/scanner-users/${id}/reset-password`, { password: pw }, { headers: headers() }); setMessage(`Password reset for ${username}.`); } catch (err) { setError(errorText(err)); } }
  return <Shell>
    <PageTitle eyebrow="OPERATORS" title="Scanner accounts" />
    <div className="scanner-users-grid">
      <form className="scanner-user-form" onSubmit={save} data-testid="scanner-user-form">
        <h2>Create scanner operator</h2>
        <p className="muted">Each device at the gate should log in with its own operator account.</p>
        <label>Username<input required data-testid="new-scanner-username" placeholder="scanner01" autoCapitalize="none" value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></label>
        <label>Display name<input required data-testid="new-scanner-name" placeholder="Gate Operator 1" value={form.display_name} onChange={e => setForm({ ...form, display_name: e.target.value })} /></label>
        <label>Password<input required data-testid="new-scanner-password" type="password" placeholder="min 8 characters" value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /></label>
        {error && <div className="alert danger" data-testid="scanner-user-error">{error}</div>}
        {message && <div className="alert success" data-testid="scanner-user-success">{message}</div>}
        <button className="primary full" type="submit" data-testid="save-scanner-user" disabled={saving}>{saving ? "Creating…" : "Create scanner account"}</button>
        <p className="hint">Scanners sign in at <code>/scanner/login</code></p>
      </form>
      <div className="table-wrap"><table><thead><tr><th>Username</th><th>Display name</th><th>Status</th><th>Last login</th><th>Actions</th></tr></thead><tbody>
        {users.map(u => <tr key={u.id} data-testid={`scanner-user-row-${u.id}`}>
          <td className="mono">{u.username}</td>
          <td>{u.display_name}</td>
          <td><span className={`badge ${u.is_active ? "green" : "red-badge"}`}>{u.is_active ? "ACTIVE" : "DISABLED"}</span></td>
          <td className="muted-cell">{u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "—"}</td>
          <td className="row-actions">
            <button className="table-action" data-testid={`toggle-scanner-${u.id}`} onClick={() => toggle(u.id)}>{u.is_active ? "Disable" : "Enable"}</button>
            <button className="table-action" data-testid={`reset-scanner-${u.id}`} onClick={() => reset(u.id, u.username)}>Reset password</button>
          </td>
        </tr>)}
      </tbody></table>{!users.length && <div className="empty">No scanner accounts yet. Create one to hand out to a gate operator.</div>}</div>
    </div>
  </Shell>;
}

function RoleRoute({ role, children }) {
  const token = sessionStorage.getItem("euphoria_token"); const user = currentUser();
  if (!token || !user) return <Navigate to={role === "SCANNER" ? "/scanner/login" : "/login"} replace />;
  if (user.role !== role) return <Navigate to={homeFor(user.role)} replace />;
  return children;
}
export default function App() {
  return <BrowserRouter><Routes>
    <Route path="/login" element={<Login />} />
    <Route path="/scanner/login" element={<ScannerLogin />} />
    <Route path="/scanner" element={<RoleRoute role="SCANNER"><Scanner /></RoleRoute>} />
    <Route path="/" element={<RoleRoute role="ADMIN"><Dashboard /></RoleRoute>} />
    <Route path="/registrations" element={<RoleRoute role="ADMIN"><Registrations /></RoleRoute>} />
    <Route path="/entries" element={<RoleRoute role="ADMIN"><EntriesPage /></RoleRoute>} />
    <Route path="/import" element={<RoleRoute role="ADMIN"><ImportPage /></RoleRoute>} />
    <Route path="/scanner-users" element={<RoleRoute role="ADMIN"><ScannerUsersPage /></RoleRoute>} />
    <Route path="*" element={<Navigate to="/login" replace />} />
  </Routes></BrowserRouter>;
}