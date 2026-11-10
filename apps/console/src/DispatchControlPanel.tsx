import { useEffect, useId, useRef, useState } from 'react';
import { ApiError, getControlState, setDispatchControl, type ControlState, type ControlTarget, type ReviewerCredential } from './api';

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const validUuid = (value: unknown): value is string => typeof value === 'string' && value.length === 36 && uuid.test(value);
const targetKey = (target?: ControlTarget) => `${target?.kind ?? 'tenant'}:${target?.id ?? ''}`;
function validState(value: ControlState, target: ControlTarget) {
  return value && value.kind === target.kind && validUuid(value.target_id) && validUuid(value.tenant_id)
    && validUuid(value.environment_id) && typeof value.enabled === 'boolean' && typeof value.paused === 'boolean'
    && Number.isSafeInteger(value.revision) && value.revision > 0
    && (target.kind === 'tenant' ? value.target_id === value.tenant_id : value.target_id.toLowerCase() === target.id?.toLowerCase());
}

export function DispatchControlPanel({ token, sessionSignal, initialTarget }: {
  token: ReviewerCredential; sessionSignal: AbortSignal; initialTarget?: ControlTarget;
}) {
  const id = useId();
  const initialKey = targetKey(initialTarget);
  const [target, setTarget] = useState<ControlTarget>(initialTarget ?? { kind: 'tenant', id: null });
  const [authority, setAuthority] = useState({ token, sessionSignal, initialKey });
  const [state, setState] = useState<ControlState | null>(null);
  const [confirmation, setConfirmation] = useState<{ state: ControlState; paused: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  const visible = authority.token === token && authority.sessionSignal === sessionSignal
    && authority.initialKey === initialKey && !sessionSignal.aborted;
  function stop() { pending.current?.abort(); pending.current = null; setBusy(false); }
  function clear() { stop(); setState(null); setConfirmation(null); setMessage(''); }
  useEffect(() => {
    clear(); setAuthority({ token, sessionSignal, initialKey });
    setTarget(initialTarget ?? { kind: 'tenant', id: null });
    const abort = () => clear();
    sessionSignal.addEventListener('abort', abort);
    return () => { pending.current?.abort(); sessionSignal.removeEventListener('abort', abort); };
    // A new credential or initial scope invalidates all captured authority.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionSignal, initialKey]);
  useEffect(() => {
    if (visible && confirmation) dialog.current?.showModal(); else dialog.current?.close();
  }, [visible, confirmation]);
  function begin() {
    stop(); setConfirmation(null); setMessage(''); setBusy(true);
    const controller = new AbortController(); pending.current = controller;
    return AbortSignal.any([controller.signal, sessionSignal]);
  }
  async function read(signal: AbortSignal, scope: ControlTarget) {
    const result = await getControlState(token, scope.kind, scope.id, signal);
    if (signal.aborted) return;
    if (!validState(result, scope)) throw new Error('Invalid control state');
    setState(result);
  }
  function fail(error: unknown, writing = false) {
    setState(null); setConfirmation(null);
    if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
      setMessage('Dispatch control access is unavailable. Check your session and target, then explicitly load state again.');
    } else if (writing && (!(error instanceof ApiError) || error.status >= 500)) {
      setMessage('Change outcome is unknown. State was cleared. Explicitly load state before another decision. No retry was sent.');
    } else setMessage('Request failed. State was cleared. Explicitly load state and review before another decision.');
  }
  async function refresh() {
    if (!visible || busy) return;
    clear();
    if (target.kind !== 'tenant' && !validUuid(target.id)) {
      setMessage('Enter a valid target UUID.'); return;
    }
    const scope = { ...target, id: target.kind === 'tenant' ? null : target.id };
    const signal = begin();
    try { await read(signal, scope); }
    catch (error) { if (!signal.aborted) fail(error); }
    finally { if (!signal.aborted) setBusy(false); }
  }
  async function mutate() {
    if (!visible || busy || !confirmation) return;
    const captured = confirmation;
    const scope: ControlTarget = { kind: captured.state.kind, id: captured.state.kind === 'tenant' ? null : captured.state.target_id };
    const signal = begin(); setState(null);
    try {
      const result = await setDispatchControl(token, captured.state, captured.paused, signal);
      if (signal.aborted) return;
      if (!validState(result, scope) || result.tenant_id !== captured.state.tenant_id
        || result.environment_id !== captured.state.environment_id || result.paused !== captured.paused
        || result.revision < captured.state.revision) throw new Error('Invalid change acknowledgement');
      setState(result); setMessage('Change acknowledged. Review the current state before another change.');
    } catch (error) {
      if (signal.aborted) return;
      if (error instanceof ApiError && error.status === 409) {
        try {
          await read(signal, scope);
          if (!signal.aborted) setMessage('Revision conflict. Confirmation discarded and current state loaded. Review again before changing dispatch.');
        } catch (refreshError) { if (!signal.aborted) fail(refreshError); }
      } else fail(error, true);
    } finally { if (!signal.aborted) setBusy(false); }
  }
  const data = visible ? state : null;
  function facts(value: ControlState) {
    return <dl className="facts"><div><dt>Scope</dt><dd>{value.kind}</dd></div><div><dt>Target UUID</dt><dd>{value.target_id}</dd></div><div><dt>Tenant UUID</dt><dd>{value.tenant_id}</dd></div><div><dt>Authenticated environment UUID</dt><dd>{value.environment_id}</dd></div><div><dt>Scope enabled</dt><dd>{String(value.enabled)}</dd></div><div><dt>Scope paused</dt><dd>{String(value.paused)}</dd></div><div><dt>Control revision</dt><dd>{value.revision}</dd></div></dl>;
  }
  return <section aria-labelledby={id + '-title'}>
    <h2 id={id + '-title'}>Dispatch controls</h2>
    <p className="muted">Requires an independent dispatch control grant. Load the authorized target before reviewing a change.</p>
    <p>Pause stops future dispatch according to server ordering. It is not cancellation or proof of non-execution. Pause and resume do not release uncertain holds or reset provider keys.</p>
    <form className="operations-filter" onSubmit={event => { event.preventDefault(); void refresh(); }}>
      <label htmlFor={id + '-scope'}>Control scope</label><select id={id + '-scope'} value={target.kind} disabled={!visible} onChange={event => { clear(); setTarget({ kind: event.target.value as ControlTarget['kind'], id: null }); }}>
        <option value="tenant">Tenant (all environments)</option><option value="connection">Connection</option><option value="workload">Workload</option>
      </select>
      {target.kind !== 'tenant' && <><label htmlFor={id + '-target'}>Target UUID</label><input id={id + '-target'} value={target.id ?? ''} maxLength={36} disabled={!visible} onChange={event => { clear(); setTarget({ ...target, id: event.target.value }); }} autoComplete="off" spellCheck={false} required /></>}
      <button disabled={!visible || busy}>Load control state</button>
    </form>
    {target.kind === 'tenant' && <p className="notice">Tenant control affects all environments of the authenticated tenant, including environments outside this console's current environment.</p>}
    {visible && message && <p className="notice" role="status">{message}</p>}
    {visible && busy && <p role="status">Dispatch control request in progress…</p>}
    {data && <article className="card"><h3>Authorized current control state</h3>{facts(data)}<p className="muted">Other scopes and eligibility checks can still prevent dispatch. Resuming this scope does not enable a disabled scope.</p><button disabled={busy} onClick={() => { setMessage(''); setConfirmation({ state: { ...data }, paused: !data.paused }); }}>Review {data.paused ? 'resume' : 'pause'}</button></article>}
    <dialog ref={dialog} aria-labelledby={id + '-confirm'} onCancel={() => setConfirmation(null)} onClose={() => setConfirmation(null)}>{visible && confirmation && <>
      <h2 id={id + '-confirm'}>Confirm dispatch {confirmation.paused ? 'pause' : 'resume'}</h2>
      {facts(confirmation.state)}<p>Desired paused state: <strong>{String(confirmation.paused)}</strong>. This confirmation applies only to this exact target, scope and revision.</p>
      {confirmation.state.kind === 'tenant' && <p className="notice">This changes dispatch control across ALL environments of this tenant.</p>}
      <p>Already authorized or in-flight requests may still execute. This change does not cancel provider effects, release uncertain holds or reset provider keys.</p>
      <div className="buttons"><button autoFocus onClick={() => setConfirmation(null)}>Cancel</button><button className="danger" disabled={busy} onClick={() => void mutate()}>Confirm {confirmation.paused ? 'pause' : 'resume'}</button></div>
    </>}</dialog>
  </section>;
}
