import type { ReviewerCredential } from './api';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { EvidenceSearch } from './EvidenceSearch';
import { downloadExport, exportErrorMessage, getExport, requestExport, type EvidenceExport } from './api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const POLL_LIMIT = 60;
const POLL_MS = 2000;

function expiryTime(item: EvidenceExport) {
  const value = Date.parse(item.expires_at);
  return Number.isFinite(value) ? value : 0;
}

export function ExportPanel({ token, sessionSignal, onOpenDetail }: { token: ReviewerCredential; sessionSignal: AbortSignal; onOpenDetail: (connectionId: string, actionId: string) => void }) {
  const [connection, setConnection] = useState('');
  const [actions, setActions] = useState('');
  const [resumeId, setResumeId] = useState('');
  const [trackedId, setTrackedId] = useState('');
  const [refresh, setRefresh] = useState(0);
  const [info, setInfo] = useState<EvidenceExport | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [polling, setPolling] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [now, setNow] = useState(Date.now());
  const live = useRef(false);
  const pending = useRef(new Set<AbortController>());
  const pollController = useRef<AbortController | null>(null);

  useEffect(() => {
    live.current = true;
    const abort = () => { pending.current.forEach((controller) => controller.abort()); };
    sessionSignal.addEventListener('abort', abort);
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => {
      live.current = false;
      abort();
      sessionSignal.removeEventListener('abort', abort);
      window.clearInterval(timer);
    };
  }, [token, sessionSignal]);

  function active(controller: AbortController) {
    return live.current && !sessionSignal.aborted && !controller.signal.aborted;
  }

  useEffect(() => {
    if (!trackedId || sessionSignal.aborted) return;
    const controller = new AbortController();
    pending.current.add(controller);
    pollController.current = controller;
    const abort = () => controller.abort();
    sessionSignal.addEventListener('abort', abort);
    let timer: number | undefined;
    let attempts = 0;
    const deadline = Date.now() + 120000;
    setPolling(true);
    async function poll() {
      if (controller.signal.aborted) return;
      try {
        const item = await getExport(token, trackedId, controller.signal);
        if (controller.signal.aborted || sessionSignal.aborted || !live.current) return;
        if (item.id.toLowerCase() !== trackedId.toLowerCase()) throw new Error('Export unavailable');
        setInfo(item);
        setError('');
        setNow(Date.now());
        attempts += 1;
        if (expiryTime(item) <= Date.now() || item.status === 'ready' || item.status === 'failed') {
          setPolling(false);
        } else if (attempts >= POLL_LIMIT || Date.now() >= deadline) {
          setPolling(false);
          setNotice('Automatic checks paused after two minutes. Check again to continue.');
        } else {
          timer = window.setTimeout(() => void poll(), POLL_MS);
        }
      } catch (error) {
        if (!controller.signal.aborted && !sessionSignal.aborted && live.current) {
          setInfo(null);
          setPolling(false);
          setError(exportErrorMessage(error));
        }
      }
    }
    void poll();
    return () => {
      controller.abort();
      pending.current.delete(controller);
      if (pollController.current === controller) pollController.current = null;
      sessionSignal.removeEventListener('abort', abort);
      window.clearTimeout(timer);
    };
  }, [trackedId, refresh, token, sessionSignal]);

  function stopTracking() {
    pollController.current?.abort();
    setTrackedId('');
    setInfo(null);
    setPolling(false);
    setError('');
    setNotice('');
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || sessionSignal.aborted) return;
    const connectionId = connection.trim().toLowerCase();
    const actionIds = actions.trim().split(/[\s,]+/).filter(Boolean).map((id) => id.toLowerCase());
    if (!UUID.test(connectionId) || actionIds.length < 1 || actionIds.length > 1000
      || actionIds.some((id) => !UUID.test(id)) || new Set(actionIds).size !== actionIds.length) {
      setError('Enter one connection UUID and 1–1,000 unique action UUIDs separated by spaces, commas, or new lines.');
      return;
    }
    stopTracking();
    const controller = new AbortController();
    pending.current.add(controller);
    setBusy(true);
    try {
      const item = await requestExport(token, { connection_id: connectionId, action_ids: actionIds }, controller.signal);
      if (!active(controller)) return;
      setInfo(item);
      setResumeId(item.id);
      setTrackedId(item.id);
      setNotice('Export requested. Keep its ID to check it again later.');
    } catch (error) {
      if (active(controller)) setError(exportErrorMessage(error));
    } finally {
      if (active(controller)) setBusy(false);
      pending.current.delete(controller);
    }
  }

  function resume(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || downloading || sessionSignal.aborted) return;
    const id = resumeId.trim().toLowerCase();
    if (!UUID.test(id)) { setError('Enter a valid export UUID.'); return; }
    stopTracking();
    setTrackedId(id);
    setRefresh((value) => value + 1);
  }

  async function download() {
    if (!info || info.status !== 'ready' || expiryTime(info) <= Date.now() || downloading || sessionSignal.aborted) return;
    const item = info;
    const controller = new AbortController();
    pending.current.add(controller);
    setDownloading(true);
    setError('');
    setNotice('');
    try {
      const blob = await downloadExport(token, item.id, controller.signal);
      if (!active(controller)) return;
      if (expiryTime(item) <= Date.now()) { setNow(Date.now()); throw new Error('Export expired'); }
      const url = URL.createObjectURL(blob);
      try {
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = 'evidence-export.json';
        document.body.append(anchor);
        anchor.click();
        anchor.remove();
      } finally {
        URL.revokeObjectURL(url);
      }
      setNotice('Evidence download requested. Treat the saved JSON as sensitive.');
    } catch (error) {
      if (active(controller)) { setInfo(null); setError(exportErrorMessage(error)); }
    } finally {
      if (active(controller)) setDownloading(false);
      pending.current.delete(controller);
    }
  }

  const expired = info ? expiryTime(info) <= now : false;
  return <section aria-labelledby="evidence-title">
    <div className="queue-toolbar"><h2 id="evidence-title">Evidence exports</h2></div>
    <p className="muted export-help">Exports require a separate evidence grant. Select 1–1,000 actions from one connection. Exports are limited to 20,000 history rows and 20 MiB of redacted JSON, and expire after one hour. Large selections may need to be split.</p>
    <EvidenceSearch onOpenDetail={onOpenDetail} token={token} sessionSignal={sessionSignal} disabled={busy || downloading} onUseSelection={(connectionId, actionIds) => {
      stopTracking();
      setConnection(connectionId);
      setActions(actionIds.join('\n'));
      setError('');
      setNotice('Review the selected connection and action IDs before requesting the export.');
      requestAnimationFrame(() => document.getElementById('export-connection')?.focus());
    }} />
    <div className="export-forms">
      <form className="card export-form" onSubmit={(event) => void submit(event)}>
        <h3>Request an export</h3>
        <label htmlFor="export-connection">Connection UUID</label>
        <input id="export-connection" value={connection} onChange={(event) => setConnection(event.target.value)} autoComplete="off" spellCheck={false} required disabled={busy || downloading} />
        <label htmlFor="export-actions">Action UUIDs</label>
        <textarea id="export-actions" value={actions} onChange={(event) => setActions(event.target.value)} maxLength={40000} autoComplete="off" spellCheck={false} rows={6} required disabled={busy || downloading} aria-describedby="export-actions-help" />
        <p id="export-actions-help" className="muted">Separate unique UUIDs with spaces, commas, or new lines.</p>
        <button className="primary" type="submit" disabled={busy || downloading}>{busy ? 'Requesting export…' : 'Request export'}</button>
      </form>
      <form className="card export-form" onSubmit={resume}>
        <h3>Track an existing export</h3>
        <label htmlFor="export-id">Export UUID</label>
        <input id="export-id" value={resumeId} onChange={(event) => setResumeId(event.target.value)} autoComplete="off" spellCheck={false} required disabled={busy || downloading} />
        <p className="muted">An export is visible only to its requester with current access. Nothing is saved in this browser.</p>
        <button type="submit" disabled={busy || downloading}>Check export</button>
      </form>
    </div>
    {error && <p className="notice error" role="alert">{error}</p>}
    {notice && <p className="notice" role="status">{notice}</p>}
    {info && <div className="card export-status" aria-live="polite">
      <div className="card-header"><h3>Export status</h3><span className="badge">{expired ? 'Expired' : info.status}</span></div>
      <dl className="facts">
        <div><dt>Export ID</dt><dd><code>{info.id}</code></dd></div>
        <div><dt>Connection</dt><dd><code>{info.connection_id}</code></dd></div>
        <div><dt>Expires</dt><dd><time dateTime={info.expires_at}>{new Date(info.expires_at).toLocaleString()}</time></dd></div>
      </dl>
      {expired ? <p role="status">This export has expired. Request a new export if needed.</p>
        : info.status === 'failed' ? <p role="status">The export could not be prepared. Request a new export or contact your operator.</p>
        : <div className="buttons">
          {polling && <p className="muted" role="status">Checking export status…</p>}
          {info.status === 'ready' && <button className="primary" type="button" onClick={() => void download()} disabled={downloading}>{downloading ? 'Downloading…' : 'Download JSON'}</button>}
        </div>}
    </div>}
  </section>;
}
