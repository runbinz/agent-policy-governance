import { useEffect, useId, useRef, useState } from 'react';
import { ApiError, getRecoveryItems, type RecoveryKind, type RecoveryPage, type ReviewerCredential } from './api';
import { ActionDetail } from './ActionDetail';
import { ReconciliationPanel, recoveryDispatchStates, recoveryUuid } from './ReconciliationPanel';

const statuses = ['received', 'denied', 'pending_approval', 'ready', 'rejected', 'expired', 'cancelled', 'dispatching', 'failed_confirmed', 'succeeded'];
const integer = (value: unknown) => typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
const date = (value: unknown) => value === null || (typeof value === 'string' && value.length <= 40 && /^\d{4}-\d{2}-\d{2}T/.test(value) && Number.isFinite(Date.parse(value)));
const time = (value: string | null) => value === null ? 'Unavailable' : new Date(value).toLocaleString();
function validPage(value: RecoveryPage, connectionId: string, kind: RecoveryKind) {
  return value && recoveryUuid(value.connection_id) && value.connection_id.toLowerCase() === connectionId.toLowerCase() && value.kind === kind
    && (value.next_cursor === null || (typeof value.next_cursor === 'string' && value.next_cursor.length > 0 && value.next_cursor.length <= 1024 && !/[\u0000-\u001f\u007f]/.test(value.next_cursor)))
    && Array.isArray(value.items) && value.items.length <= 100 && new Set(value.items.map(row => row.action_id)).size === value.items.length
    && value.items.every(row => row && recoveryUuid(row.action_id) && recoveryUuid(row.workload_id) && statuses.includes(row.action_status)
      && (row.dispatch_state === null || recoveryDispatchStates.includes(row.dispatch_state)) && date(row.queue_due_at) && date(row.state_changed_at)
      && (row.queue_lag_seconds === null || integer(row.queue_lag_seconds)) && (row.lease_expired === null || typeof row.lease_expired === 'boolean')
      && (row.hold_state === null || ['held', 'settled', 'released'].includes(row.hold_state)) && integer(row.held_minor) && typeof row.can_reconcile === 'boolean'
      && (!row.can_reconcile || row.dispatch_state === 'manual_review'));
}

export function RecoveryPanel({ token, sessionSignal, connectionId }: { token: ReviewerCredential; sessionSignal: AbortSignal; connectionId: string }) {
  const id = useId();
  const [authority, setAuthority] = useState({ token, sessionSignal, connectionId });
  const [kind, setKind] = useState<RecoveryKind>('dispatches');
  const [page, setPage] = useState<RecoveryPage | null>(null);
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const [index, setIndex] = useState(0);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [detail, setDetail] = useState<string | null>(null);
  const [reconcile, setReconcile] = useState<string | null>(null);
  const pending = useRef<AbortController | null>(null);
  const visible = authority.token === token && authority.sessionSignal === sessionSignal && authority.connectionId === connectionId && !sessionSignal.aborted;
  function clear() { pending.current?.abort(); setPage(null); setBusy(false); setMessage(''); setDetail(null); setReconcile(null); }
  useEffect(() => {
    clear(); setCursors([null]); setIndex(0); setAuthority({ token, sessionSignal, connectionId });
    sessionSignal.addEventListener('abort', clear);
    return () => { pending.current?.abort(); sessionSignal.removeEventListener('abort', clear); };
    // Reset all scope-bound data and children when authority changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionSignal, connectionId]);
  async function load(after: string | null, nextIndex: number, history: Array<string | null>) {
    if (!visible || busy) return;
    clear();
    if (!recoveryUuid(connectionId)) { setMessage('Enter a valid connection UUID to load recovery rows.'); return; }
    const controller = new AbortController(); pending.current = controller;
    const signal = AbortSignal.any([controller.signal, sessionSignal]); setBusy(true);
    try {
      const result = await getRecoveryItems(token, connectionId, kind, after, signal);
      if (signal.aborted) return;
      if (!validPage(result, connectionId, kind) || (result.next_cursor !== null && history.includes(result.next_cursor))) throw new Error('Invalid recovery page');
      setPage(result); setIndex(nextIndex); setCursors(history);
    } catch (error) {
      if (!signal.aborted) setMessage(error instanceof ApiError && [401, 403, 404].includes(error.status)
        ? 'Recovery access is unavailable. Check your session and connection, then explicitly load rows again.' : 'Recovery rows unavailable. Explicitly load rows again.');
    } finally { if (!signal.aborted) setBusy(false); }
  }
  const data = visible ? page : null;
  return <section aria-labelledby={id + '-title'}>
    <h2 id={id + '-title'}>Recovery items</h2>
    <p>Unknown outcomes may already have executed and retain exposure. Ready-job lag measures current due-time lag, not total human waiting time. Paused scopes can retain ready work.</p>
    <label htmlFor={id + '-kind'}>Recovery queue</label> <select id={id + '-kind'} value={kind} disabled={!visible} onChange={event => { clear(); setKind(event.target.value as RecoveryKind); setCursors([null]); setIndex(0); }}><option value="dispatches">Unresolved dispatches</option><option value="ready_jobs">Ready jobs</option></select> <button disabled={!visible || busy} onClick={() => void load(null, 0, [null])}>Load recovery rows</button>
    {visible && busy && <p role="status">Loading recovery rows…</p>}
    {visible && message && <p className="notice" role="status">{message}</p>}
    {data && <><div className="operations-table-wrap"><table className="operations-table"><caption>{kind === 'dispatches' ? 'Unresolved dispatches' : 'Currently due ready jobs'} — page {index + 1}</caption><thead><tr>{['Action', 'Workload', 'Action status', 'Dispatch state', 'Queue due', 'Current due-time lag', 'State changed', 'Lease expired', 'Hold', 'Held exposure', 'Review'].map(label => <th scope="col" key={label}>{label}</th>)}</tr></thead><tbody>
      {data.items.map(row => <tr key={row.action_id}><th scope="row">{row.action_id}</th><td>{row.workload_id}</td><td>{row.action_status}</td><td>{row.dispatch_state ?? 'Unavailable'}</td><td>{time(row.queue_due_at)}</td><td>{row.queue_lag_seconds === null ? 'Unavailable' : `${row.queue_lag_seconds.toLocaleString()} seconds`}</td><td>{time(row.state_changed_at)}</td><td>{row.lease_expired === null ? 'Unavailable' : row.lease_expired ? 'Yes' : 'No'}</td><td>{row.hold_state ?? 'Unavailable'}</td><td>{row.held_minor.toLocaleString()} minor units</td><td><button onClick={() => { setReconcile(null); setDetail(row.action_id); }}>Open authorized detail</button>{row.can_reconcile && <button onClick={() => { setDetail(null); setReconcile(row.action_id); }}>Open reconciliation preview</button>}</td></tr>)}
    </tbody></table></div>{data.items.length === 0 && <p role="status">No recovery items on this page.</p>}
      <div className="buttons"><button disabled={busy || index === 0} onClick={() => void load(cursors[index - 1], index - 1, cursors.slice(0, index))}>Previous recovery page</button><button disabled={busy || data.next_cursor === null} onClick={() => { if (data.next_cursor) void load(data.next_cursor, index + 1, [...cursors.slice(0, index + 1), data.next_cursor]); }}>Next recovery page</button></div>
    </>}
    {visible && detail && <ActionDetail key={detail} token={token} sessionSignal={sessionSignal} connectionId={connectionId} actionId={detail} onBack={() => setDetail(null)} onQueue={() => setDetail(null)} />}
    {visible && reconcile && <><button onClick={() => setReconcile(null)}>Close reconciliation preview</button><ReconciliationPanel key={reconcile} token={token} sessionSignal={sessionSignal} initialActionId={reconcile} /></>}
  </section>;
}
