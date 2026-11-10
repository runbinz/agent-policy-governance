import { useEffect, useRef, useState, type FormEvent } from 'react';
import { DispatchControlPanel } from './DispatchControlPanel';
import { RecoveryPanel } from './RecoveryPanel';
import { ReconciliationPanel } from './ReconciliationPanel';
import { getOperations, operationsErrorMessage, type OperationsSnapshot, type ReviewerCredential } from './api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const age = (seconds: number | null) => seconds === null ? 'Unavailable' : `${seconds.toLocaleString()} seconds`;
const amount = (value: number | null) => value === null ? 'No configured limit' : `${value.toLocaleString()} minor units`;

export function OperationsPanel({ token, sessionSignal }: { token: ReviewerCredential; sessionSignal: AbortSignal }) {
  const [connection, setConnection] = useState('');
  const [snapshot, setSnapshot] = useState<OperationsSnapshot | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const pending = useRef<AbortController | null>(null);
  useEffect(() => {
    const abort = () => pending.current?.abort();
    sessionSignal.addEventListener('abort', abort);
    return () => { abort(); sessionSignal.removeEventListener('abort', abort); };
  }, [token, sessionSignal]);

  function changeScope(value: string) {
    pending.current?.abort();
    setConnection(value); setSnapshot(null); setError(''); setBusy(false);
  }
  async function refresh(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    pending.current?.abort();
    setSnapshot(null); setError('');
    const id = connection.trim();
    if (!UUID.test(id)) { setError('Enter a valid connection UUID.'); return; }
    if (sessionSignal.aborted) return;
    const controller = new AbortController();
    pending.current = controller;
    setBusy(true);
    const signal = AbortSignal.any([controller.signal, sessionSignal]);
    try {
      const result = await getOperations(token, id, signal);
      if (signal.aborted) return;
      if (result.connection_id.toLowerCase() !== id.toLowerCase()) throw new Error('Snapshot unavailable');
      setSnapshot(result);
    } catch (error) {
      if (!signal.aborted) setError(operationsErrorMessage(error));
    } finally {
      if (!signal.aborted) setBusy(false);
    }
  }

  return <section aria-labelledby="operations-title">
    <h2 id="operations-title">Operations</h2>
    <DispatchControlPanel token={token} sessionSignal={sessionSignal} />
    <ReconciliationPanel token={token} sessionSignal={sessionSignal} />
    <p className="muted">Read-only snapshot for a connection with explicit operations access. Refresh to see current state.</p>
    <form className="operations-filter" onSubmit={(event) => void refresh(event)}>
      <label htmlFor="operations-connection">Connection UUID</label>
      <input id="operations-connection" value={connection} onChange={(event) => changeScope(event.target.value)} autoComplete="off" spellCheck={false} required />
      <button type="submit" disabled={busy || !connection.trim()}>Refresh operations</button>
    </form>
    {error && <p className="notice error" role="alert">{error}</p>}
    {busy && <p className="state" role="status">Loading operations…</p>}
    {!snapshot && !busy && !error && <p className="state" role="status">Choose a connection and refresh to load its operations snapshot.</p>}
    {snapshot && <>
      <p role="status">Snapshot sampled at {new Date(snapshot.sampled_at_unix * 1000).toLocaleString()}.</p>
      <div className="operations-grid">
        <article className="card"><h3>Budget and exposure</h3><dl className="facts">
          <div><dt>Held exposure (all days)</dt><dd>{amount(snapshot.held_minor)}</dd></div>
          <div><dt>Committed today (UTC)</dt><dd>{amount(snapshot.committed_today_minor)}</dd></div>
          <div><dt>Daily usage (UTC)</dt><dd>{amount(snapshot.daily_used_minor)}</dd></div>
          <div><dt>Daily limit</dt><dd>{amount(snapshot.daily_limit_minor)}</dd></div>
          <div><dt>Exposure limit</dt><dd>{amount(snapshot.exposure_limit_minor)}</dd></div>
        </dl><p className="muted">Amounts are authoritative USD minor units (100 minor units = USD 1.00).</p></article>
        <article className="card"><h3>Paused scopes</h3><dl className="facts">
          <div><dt>Tenant</dt><dd>{snapshot.tenant_paused ? 'Paused' : 'Not paused'}</dd></div>
          <div><dt>Connection</dt><dd>{snapshot.connection_paused ? 'Paused' : 'Not paused'}</dd></div>
          <div><dt>Paused granted workloads</dt><dd>{snapshot.workloads_paused}</dd></div>
        </dl><p className="muted">Use the independently authorized controls above for pause or reconciliation requests.</p></article>
      </div>
      <div className="operations-table-wrap"><table className="operations-table"><caption>Queues, unresolved outcomes, and failures</caption><thead><tr><th scope="col">Measure</th><th scope="col">Count</th><th scope="col">Age or lag</th></tr></thead><tbody>
        <tr><th scope="row">Pending approvals</th><td>{snapshot.pending_approvals}</td><td>{age(snapshot.oldest_approval_age_seconds)}</td></tr>
        <tr><th scope="row">Unknown outcomes</th><td>{snapshot.unknown_outcomes}</td><td rowSpan={3}>Oldest unresolved state: {age(snapshot.oldest_unresolved_age_seconds)}</td></tr>
        <tr><th scope="row">Pending provider</th><td>{snapshot.pending_provider}</td></tr>
        <tr><th scope="row">Manual review</th><td>{snapshot.manual_review}</td></tr>
        <tr><th scope="row">Ready jobs</th><td>{snapshot.ready_jobs}</td><td>{age(snapshot.oldest_ready_lag_seconds)}</td></tr>
        <tr><th scope="row">Queued notifications</th><td>{snapshot.queued_notifications}</td><td>—</td></tr>
        <tr><th scope="row">Failed notifications</th><td>{snapshot.failed_notifications}</td><td>—</td></tr>
        <tr><th scope="row">Failed exports</th><td>{snapshot.failed_exports}</td><td>—</td></tr>
      </tbody></table></div>
      <p className="muted">{snapshot.unknown_age_records} records have unknown historical ages. Age values exclude missing timestamps; unavailable ages do not imply a healthy or empty queue. Unresolved age measures time in the current state.</p>
    </>}
    <RecoveryPanel token={token} sessionSignal={sessionSignal} connectionId={connection.trim()} />
  </section>;
}
