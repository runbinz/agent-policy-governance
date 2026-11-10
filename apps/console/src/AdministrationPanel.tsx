import { useEffect, useRef, useState } from 'react';
import { DispatchControlPanel } from './DispatchControlPanel';
import type { ControlTarget } from './api';
import { ApiError, getAdminEntities, getAdminGrants, setAdminEnabled, revokeAdminGrant, type ReviewerCredential, type AdminEntityKind, type AdminEntityPage, type AdminEntity, type AdminGrantPage, type AdminGrant, type AdminGrantKind } from './api';

const entities: AdminEntityKind[] = ['connections', 'workloads', 'reviewers'];
const grants: AdminGrantKind[] = ['workload', 'approval', 'reconciliation', 'policy_admin', 'evidence_export', 'operations', 'action_detail', 'tenant_dispatch', 'workload_dispatch', 'environment_admin'];
type Inventory = { type: 'entity'; page: AdminEntityPage } | { type: 'grant'; page: AdminGrantPage };
type Confirmation = { tenant: string; environment: string } & ({ type: 'entity'; kind: AdminEntityKind; row: AdminEntity; enabled: boolean } | { type: 'grant'; kind: AdminGrantKind; row: AdminGrant });
const grantKey = (row: AdminGrant) => [row.connection_id, row.workload_id, row.reviewer_id].join('/');

export function AdministrationPanel({ token, sessionSignal }: { token: ReviewerCredential; sessionSignal: AbortSignal }) {
  const [controlTarget, setControlTarget] = useState<ControlTarget | null>(null);
  const [filter, setFilter] = useState('entity:connections');
  const [inventory, setInventory] = useState<Inventory | null>(null);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  const [authority, setAuthority] = useState({ token, sessionSignal });
  const dialog = useRef<HTMLDialogElement>(null);
  const visible = authority.token === token && authority.sessionSignal === sessionSignal && !sessionSignal.aborted;
  function stop() { pending.current?.abort(); pending.current = null; setBusy(false); }
  function clear() { setControlTarget(null); stop(); setInventory(null); setConfirmation(null); setMessage(''); }
  useEffect(() => {
    setAuthority({ token, sessionSignal }); clear();
    const abort = () => clear();
    sessionSignal.addEventListener('abort', abort);
    return () => { pending.current?.abort(); sessionSignal.removeEventListener('abort', abort); };
    // Credential changes invalidate every captured scope and request.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionSignal]);
  useEffect(() => {
    if (visible && confirmation) dialog.current?.showModal(); else dialog.current?.close();
  }, [confirmation, visible]);
  function begin() {
    stop(); setConfirmation(null); setMessage(''); setBusy(true);
    const controller = new AbortController(); pending.current = controller;
    return AbortSignal.any([controller.signal, sessionSignal]);
  }
  async function load(signal: AbortSignal, after: string | null = null) {
    const [type, kind] = filter.split(':');
    const result: Inventory = type === 'entity'
      ? { type: 'entity', page: await getAdminEntities(token, kind as AdminEntityKind, after, signal) }
      : { type: 'grant', page: await getAdminGrants(token, kind as AdminGrantKind, after, signal) };
    if (signal.aborted) return;
    if (result.page.kind !== kind || (result.type === 'entity' && result.page.items.some(row => row.kind !== kind))) throw new Error('Inventory kind mismatch');
    if (after !== null && inventory && (inventory.page.tenant_id !== result.page.tenant_id || inventory.page.environment_id !== result.page.environment_id || inventory.type !== result.type || inventory.page.kind !== result.page.kind)) throw new Error('Inventory scope mismatch');
    if (after !== null && inventory?.type === 'entity' && result.type === 'entity') {
      const previous = inventory.page.items;
      result.page.items = [...previous, ...result.page.items.filter(row => !previous.some(old => old.id === row.id))];
    } else if (after !== null && inventory?.type === 'grant' && result.type === 'grant') {
      const previous = inventory.page.items;
      result.page.items = [...previous, ...result.page.items.filter(row => !previous.some(old => grantKey(old) === grantKey(row)))];
    }
    setInventory(result);
  }
  function fail(error: unknown, writing = false) {
    setInventory(null); setConfirmation(null);
    if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
      stop(); setMessage('Administration access is unavailable. Check your session and scope, then explicitly refresh.');
    } else setMessage(writing && (!(error instanceof ApiError) || error.status >= 500)
      ? 'Change outcome is unknown. Inventory was cleared. Explicitly refresh before deciding what to do next; no retry was sent.'
      : 'Request failed. Inventory was cleared. Explicitly refresh and review before trying again.');
  }
  async function refresh(after: string | null = null) {
    if (!visible) return;
    const signal = begin(); if (after === null) setInventory(null);
    try { await load(signal, after); }
    catch (error) { if (!signal.aborted) fail(error); }
    finally { if (!signal.aborted) setBusy(false); }
  }
  async function mutate() {
    if (!confirmation || !visible || busy) return;
    const captured = confirmation;
    const signal = begin(); setInventory(null);
    try {
      if (captured.type === 'entity') await setAdminEnabled(token, captured.kind, captured.row.id, captured.row.admin_revision, captured.enabled, signal);
      else await revokeAdminGrant(token, { kind: captured.kind, connection_id: captured.row.connection_id, workload_id: captured.row.workload_id, reviewer_id: captured.row.reviewer_id, expected_revision: captured.row.admin_revision }, signal);
      if (signal.aborted) return;
      await load(signal);
      if (!signal.aborted) setMessage('Change confirmed. Inventory refreshed; review current state before another change.');
    } catch (error) {
      if (signal.aborted) return;
      if (error instanceof ApiError && error.status === 409) {
        try {
          await load(signal);
          if (!signal.aborted) setMessage('Revision conflict. Confirmation discarded and inventory refreshed. Review the current target before another change.');
        } catch (refreshError) { if (!signal.aborted) fail(refreshError); }
      } else fail(error, true);
    } finally { if (!signal.aborted) setBusy(false); }
  }
  function review(value: Confirmation) { stop(); setConfirmation(value); setMessage(''); }
  const data = visible ? inventory : null;
  const capture = data ? { tenant: data.page.tenant_id, environment: data.page.environment_id } : null;
  return <section aria-labelledby="administration-title">
    <h2 id="administration-title">Environment administration</h2>
    {visible && controlTarget && <DispatchControlPanel key={controlTarget.kind + controlTarget.id} token={token} sessionSignal={sessionSignal} initialTarget={controlTarget} />}
    <p className="muted">Scoped inventory, enable/disable and grant revocation. Administration does not grant dispatch control.</p>
    <form className="operations-filter" onSubmit={event => { event.preventDefault(); void refresh(); }}>
      <label htmlFor="admin-inventory">Inventory</label><select id="admin-inventory" value={filter} onChange={event => { clear(); setFilter(event.target.value); }}>
        <optgroup label="Entities">{entities.map(kind => <option key={kind} value={'entity:' + kind}>{kind}</option>)}</optgroup>
        <optgroup label="Grants">{grants.map(kind => <option key={kind} value={'grant:' + kind}>{kind} grants</option>)}</optgroup>
      </select><button disabled={busy || !visible}>Refresh inventory</button>
    </form>
    {visible && message && <p className="notice" role="status">{message}</p>}
    {visible && busy && <p role="status">Administration request in progress…</p>}
    {data && capture && <>
      <article className="card"><h3>Authenticated scope</h3><dl className="facts"><div><dt>Tenant UUID</dt><dd>{capture.tenant}</dd></div><div><dt>Environment UUID</dt><dd>{capture.environment}</dd></div><div><dt>Inventory kind</dt><dd>{data.page.kind}</dd></div></dl>
        {data.type === 'entity' && <p>Tenant-wide pause: {data.page.tenant_paused ? 'paused' : 'not paused'}. Independently granted tenant dispatch control: {data.page.can_control_tenant ? 'yes' : 'no'} (separate authority).</p>}
        {data.type === 'entity' && data.page.can_control_tenant && <button type="button" onClick={() => setControlTarget({kind:'tenant',id:null})}>Open tenant-wide dispatch controls</button>}<p className="muted">Server authorization is checked for every change. Self-disable and self-revocation of environment administration are rejected by the server.</p>
      </article>
      <p role="status">{data.page.items.length} loaded rows. {data.page.next_after === null ? 'End of this inventory.' : 'More rows are available.'}</p>
      {data.type === 'entity' ? data.page.items.map(row => <article className="card" key={row.id}><h3>{row.kind}: {row.id}</h3><dl className="facts"><div><dt>Enabled</dt><dd>{String(row.enabled)}</dd></div><div><dt>Administration revision</dt><dd>{row.admin_revision}</dd></div>{row.kind !== 'reviewers' && <><div><dt>Paused</dt><dd>{String(row.paused)}</dd></div><div><dt>Independently granted dispatch control</dt><dd>{String(row.can_control)}</dd></div></>}{row.kind === 'connections' && <><div><dt>Configured mode</dt><dd>{row.mode}</dd></div><div><dt>Credential health</dt><dd>{row.credential_health} — no current credential verification observed</dd></div><div><dt>Last recorded payment verification</dt><dd>{row.last_payment_verified_at ?? 'None recorded'}</dd></div></>}</dl>{row.kind === 'connections' && <p className="muted">A past payment verification does not establish current credential health.</p>}<button disabled={busy} onClick={() => review({ ...capture, type: 'entity', kind: data.page.kind, row: { ...row }, enabled: !row.enabled })}>Review {row.enabled ? 'disable' : 'enable'}</button>{row.kind !== 'reviewers' && row.can_control && <button type="button" onClick={() => setControlTarget({kind:row.kind === 'connections' ? 'connection' : 'workload',id:row.id})}>Open dispatch controls</button>}</article>)
        : data.page.items.map(row => <article className="card" key={grantKey(row)}><h3>{data.page.kind} grant</h3><dl className="facts"><div><dt>Connection UUID</dt><dd>{row.connection_id ?? 'Not applicable'}</dd></div><div><dt>Workload UUID</dt><dd>{row.workload_id ?? 'Not applicable'}</dd></div><div><dt>Reviewer UUID</dt><dd>{row.reviewer_id ?? 'Not applicable'}</dd></div><div><dt>Enabled</dt><dd>{String(row.enabled)}</dd></div><div><dt>Administration revision</dt><dd>{row.admin_revision}</dd></div><div><dt>Configured permissions (effective only while enabled)</dt><dd>{row.permissions.join(', ') || 'None'}</dd></div></dl><button disabled={busy || !row.enabled} onClick={() => review({ ...capture, type: 'grant', kind: data.page.kind, row: { ...row, permissions: [...row.permissions] } })}>Review revocation</button></article>)}
      {data.page.next_after !== null && <button disabled={busy} onClick={() => void refresh(data.page.next_after)}>Load more inventory</button>}
    </>}
    <dialog ref={dialog} aria-labelledby="admin-confirm-title" onCancel={() => setConfirmation(null)} onClose={() => setConfirmation(null)}>{visible && confirmation && <>
      <h2 id="admin-confirm-title">Confirm {confirmation.type === 'grant' ? 'grant revocation' : confirmation.enabled ? 'enable' : 'disable'}</h2>
      <dl className="facts"><div><dt>Tenant UUID</dt><dd>{confirmation.tenant}</dd></div><div><dt>Environment UUID</dt><dd>{confirmation.environment}</dd></div><div><dt>Target kind</dt><dd>{confirmation.kind}</dd></div><div><dt>Expected revision</dt><dd>{confirmation.row.admin_revision}</dd></div>{confirmation.type === 'entity' ? <div><dt>Target UUID</dt><dd>{confirmation.row.id}</dd></div> : <><div><dt>Connection UUID</dt><dd>{confirmation.row.connection_id ?? 'Not applicable'}</dd></div><div><dt>Workload UUID</dt><dd>{confirmation.row.workload_id ?? 'Not applicable'}</dd></div><div><dt>Reviewer UUID</dt><dd>{confirmation.row.reviewer_id ?? 'Not applicable'}</dd></div><div><dt>Configured permissions</dt><dd>{confirmation.row.permissions.join(', ') || 'None'}</dd></div></>}</dl>
      <p>{confirmation.type === 'entity' && confirmation.enabled ? 'Enabling restores eligibility for existing configured grants; it does not add permissions.' : 'Disabling or revoking prevents newly authorized activity according to server ordering.'} This cannot undo an already possible provider effect and does not release uncertain holds. It does not pause scopes or create dispatch-control grants.</p>
      <div className="buttons"><button autoFocus onClick={() => setConfirmation(null)}>Cancel</button><button className="danger" disabled={busy} onClick={() => void mutate()}>Confirm change</button></div>
    </>}</dialog>
  </section>;
}
