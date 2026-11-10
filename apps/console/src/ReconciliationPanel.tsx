import { useEffect, useId, useRef, useState } from 'react';
import { ApiError, getReconciliationState, requestReconciliation, type ReconciliationState, type ReviewerCredential } from './api';

export const recoveryUuid = (value: unknown): value is string => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value);
export const recoveryDispatchStates = ['authorized', 'in_flight', 'pending', 'unknown', 'manual_review', 'succeeded', 'failed_confirmed'];
function validPreview(value: ReconciliationState, action: string) {
  return value && recoveryUuid(value.action_id) && value.action_id.toLowerCase() === action.toLowerCase()
    && recoveryUuid(value.connection_id) && typeof value.can_request === 'boolean'
    && (value.dispatch_state === null || recoveryDispatchStates.includes(value.dispatch_state))
    && ['ELIGIBLE', 'NOT_MANUAL_REVIEW', 'ALREADY_QUEUED', 'NO_DISPATCH'].includes(value.reason_code)
    && (value.can_request ? value.dispatch_state === 'manual_review' && value.reason_code === 'ELIGIBLE' : value.reason_code !== 'ELIGIBLE');
}

export function ReconciliationPanel({ token, sessionSignal, initialActionId = '' }: {
  token: ReviewerCredential; sessionSignal: AbortSignal; initialActionId?: string;
}) {
  const id = useId();
  const [action, setAction] = useState(initialActionId);
  const [authority, setAuthority] = useState({ token, sessionSignal, initialActionId });
  const [preview, setPreview] = useState<ReconciliationState | null>(null);
  const [confirmation, setConfirmation] = useState<ReconciliationState | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const visible = authority.token === token && authority.sessionSignal === sessionSignal && authority.initialActionId === initialActionId && !sessionSignal.aborted;
  function clear() { pending.current?.abort(); pending.current = null; setPreview(null); setConfirmation(null); setBusy(false); setMessage(''); }
  useEffect(() => {
    clear(); setAuthority({ token, sessionSignal, initialActionId }); setAction(initialActionId);
    sessionSignal.addEventListener('abort', clear);
    return () => { pending.current?.abort(); sessionSignal.removeEventListener('abort', clear); };
    // Invalidate captured authority on every credential, session or selected action change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionSignal, initialActionId]);
  useEffect(() => { if (visible && confirmation) dialog.current?.showModal(); else dialog.current?.close(); }, [visible, confirmation]);
  function begin() {
    pending.current?.abort(); const controller = new AbortController(); pending.current = controller;
    setPreview(null); setConfirmation(null); setMessage(''); setBusy(true);
    return AbortSignal.any([controller.signal, sessionSignal]);
  }
  async function read(signal: AbortSignal, actionId: string) {
    const result = await getReconciliationState(token, actionId, signal);
    if (signal.aborted) return;
    if (!validPreview(result, actionId)) throw new Error('Invalid preview');
    setPreview(result);
  }
  function fail(error: unknown, writing: boolean) {
    setPreview(null); setConfirmation(null);
    if (error instanceof ApiError && [401, 403, 404].includes(error.status)) setMessage('Reconciliation access is unavailable. Check your session and action, then explicitly load preview again.');
    else if (writing && (!(error instanceof ApiError) || error.status >= 500)) setMessage('Request outcome is unknown. Preview cleared. Explicitly refresh before another decision. No retry was sent.');
    else setMessage('Request failed. Preview cleared. Explicitly load preview before another decision.');
  }
  async function refresh() {
    if (!visible || busy) return;
    const actionId = action.trim(); clear();
    if (!recoveryUuid(actionId)) { setMessage('Enter a valid action UUID.'); return; }
    const signal = begin();
    try { await read(signal, actionId); } catch (error) { if (!signal.aborted) fail(error, false); }
    finally { if (!signal.aborted) setBusy(false); }
  }
  async function submit() {
    if (!visible || busy || !confirmation) return;
    const captured = confirmation; const signal = begin();
    try {
      await requestReconciliation(token, captured.action_id, signal);
      if (!signal.aborted) setMessage('Evidence collection scheduled. Explicitly refresh preview to see current eligibility. Exposure remains governed by verified outcomes.');
    } catch (error) {
      if (signal.aborted) return;
      if (error instanceof ApiError && error.status === 409) {
        try { await read(signal, captured.action_id); if (!signal.aborted) setMessage('State conflict. Confirmation discarded and current preview loaded. Review again before requesting.'); }
        catch (refreshError) { if (!signal.aborted) fail(refreshError, false); }
      } else fail(error, true);
    } finally { if (!signal.aborted) setBusy(false); }
  }
  function facts(value: ReconciliationState) {
    const reason = { ELIGIBLE: 'Eligible for evidence collection', NOT_MANUAL_REVIEW: 'Not in manual review', ALREADY_QUEUED: 'Evidence collection already queued', NO_DISPATCH: 'No dispatch available' };
    return <dl className="facts"><div><dt>Action UUID</dt><dd>{value.action_id}</dd></div><div><dt>Connection UUID</dt><dd>{value.connection_id}</dd></div><div><dt>Dispatch state</dt><dd>{value.dispatch_state ?? 'Unavailable'}</dd></div><div><dt>Request eligibility</dt><dd>{reason[value.reason_code]}</dd></div></dl>;
  }
  return <section aria-labelledby={id + '-title'}>
    <h2 id={id + '-title'}>Reconciliation</h2>
    <p>Requires an independent reconciliation grant. Load a preview by action UUID, including when operations or detail access is unavailable.</p>
    <form onSubmit={event => { event.preventDefault(); void refresh(); }} className="operations-filter">
      <label htmlFor={id + '-action'}>Reconciliation action UUID</label><input id={id + '-action'} value={action} maxLength={36} autoComplete="off" spellCheck={false} disabled={!visible} onChange={event => { clear(); setAction(event.target.value); }} required />
      <button disabled={!visible || busy}>Load reconciliation preview</button>
    </form>
    {visible && busy && <p role="status">Reconciliation request in progress…</p>}
    {visible && message && <p className="notice" role="status">{message}</p>}
    {visible && preview && <article className="card">{facts(preview)}<button disabled={busy || !preview.can_request} onClick={() => setConfirmation({ ...preview })}>Review reconciliation request</button></article>}
    <dialog ref={dialog} aria-labelledby={id + '-confirm'} onCancel={() => setConfirmation(null)} onClose={() => setConfirmation(null)}>{visible && confirmation && <>
      <h2 id={id + '-confirm'}>Confirm evidence collection</h2>{facts(confirmation)}
      <p>This requests evidence collection for this exact action and connection. Execution may already have occurred. It does not unconditionally retry a refund, reset the provider key or release held exposure.</p>
      <div className="buttons"><button autoFocus onClick={() => setConfirmation(null)}>Cancel</button><button disabled={busy} onClick={() => void submit()}>Confirm reconciliation request</button></div>
    </>}</dialog>
  </section>;
}
