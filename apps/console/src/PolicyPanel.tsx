import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiError, getPolicyPage, createPolicyDraft, simulatePolicy, publishPolicy, type ReviewerCredential, type PolicyPage, type ConsolePolicy, type PolicySimulation } from './api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const fields = ['version', 'auto_limit_minor', 'hard_limit_minor', 'approval_ttl_seconds'] as const;
const labels = ['Version', 'Automatic limit (minor units)', 'Hard limit (minor units)', 'Approval TTL (seconds)'];
type Form = Record<typeof fields[number], string>;
const initial: Form = { version: '1', auto_limit_minor: '1000', hard_limit_minor: '50000', approval_ttl_seconds: '3600' };
function parse(form: Form): ConsolePolicy | null {
  if (fields.some(key => !/^\d+$/.test(form[key]))) return null;
  const policy = Object.fromEntries(fields.map(key => [key, Number(form[key])])) as ConsolePolicy;
  if (fields.some(key => !Number.isSafeInteger(policy[key])) || policy.version < 1 || policy.auto_limit_minor < 0 || policy.auto_limit_minor > policy.hard_limit_minor || policy.hard_limit_minor > 50000 || policy.approval_ttl_seconds < 1 || policy.approval_ttl_seconds > 86400) return null;
  return policy;
}
function Values({ policy }: { policy: ConsolePolicy | null }) {
  return policy ? <dl className="facts">{fields.map((key, i) => <div key={key}><dt>{labels[i]}</dt><dd>{policy[key]}</dd></div>)}</dl> : <p>No active policy.</p>;
}
function Diff({ active, selected }: { active: ConsolePolicy | null; selected: ConsolePolicy }) {
  return <dl className="facts">{fields.map((key, i) => <div key={key}><dt>{labels[i]} {active?.[key] === selected[key] ? '(unchanged)' : '(changed)'}</dt><dd>{active?.[key] ?? 'None'} → {selected[key]}</dd></div>)}</dl>;
}

export function PolicyPanel({ token, sessionSignal }: { token: ReviewerCredential; sessionSignal: AbortSignal }) {
  const [connection, setConnection] = useState('');
  const [page, setPage] = useState<PolicyPage | null>(null);
  const [selected, setSelected] = useState<ConsolePolicy | null>(null);
  const [form, setForm] = useState<Form>(initial);
  const [fixtures, setFixtures] = useState('500, 1500, 50000');
  const [simulation, setSimulation] = useState<{ result: PolicySimulation; amounts: number[] } | null>(null);
  const [confirmation, setConfirmation] = useState<{ policy: ConsolePolicy; active: ConsolePolicy | null; expected: number } | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const pending = useRef<AbortController | null>(null);
  const dialog = useRef<HTMLDialogElement>(null);
  function stop() { pending.current?.abort(); pending.current = null; setBusy(false); }
  function invalidate() { stop(); setSelected(null); setSimulation(null); setConfirmation(null); }
  function clear() { invalidate(); setPage(null); setMessage(''); }
  useEffect(() => {
    clear();
    const abort = () => clear();
    sessionSignal.addEventListener('abort', abort);
    return () => { pending.current?.abort(); sessionSignal.removeEventListener('abort', abort); };
    // A new credential is a new authority scope.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [token, sessionSignal]);
  useEffect(() => {
    if (confirmation) dialog.current?.showModal();
    else dialog.current?.close();
  }, [confirmation]);
  function begin() {
    stop();
    const controller = new AbortController(); pending.current = controller; setBusy(true); setMessage('');
    return AbortSignal.any([controller.signal, sessionSignal]);
  }
  async function load(signal: AbortSignal, after: number | null = null) {
    const result = await getPolicyPage(token, connection.trim(), after, signal);
    if (signal.aborted) return;
    if (result.connection_id.toLowerCase() !== connection.trim().toLowerCase()) throw new Error('Scope mismatch');
    setPage(previous => after === null ? result : { ...result, versions: [...(previous?.versions ?? []), ...result.versions.filter(item => !previous?.versions.some(old => old.version === item.version))] });
  }
  function failure(error: unknown, publishing = false) {
    if (error instanceof ApiError && [401, 403, 404].includes(error.status)) {
      clear(); setMessage('Policy access is unavailable. Refresh after checking your session and connection access.');
    } else setMessage(publishing && (!(error instanceof ApiError) || error.status >= 500) ? 'Publication outcome is unknown. Refresh active policy before deciding what to do next. No retry was sent.' : error instanceof ApiError && error.status === 409 ? 'Policy conflict. Refresh and review the active policy before publication.' : 'Policy request failed. Refresh and review before trying again.');
  }
  async function refresh(event?: FormEvent, after: number | null = null) {
    event?.preventDefault(); invalidate();
    if (!UUID.test(connection.trim())) { setMessage('Enter a valid connection UUID.'); return; }
    if (sessionSignal.aborted) return;
    const signal = begin();
    try { await load(signal, after); } catch (error) { if (!signal.aborted) { setPage(null); failure(error); } }
    finally { if (!signal.aborted) setBusy(false); }
  }
  async function save(event: FormEvent) {
    event.preventDefault(); const policy = parse(form);
    if (!policy || !page?.can_edit || sessionSignal.aborted) return;
    invalidate(); const signal = begin();
    try {
      await createPolicyDraft(token, connection.trim(), policy, signal);
      if (signal.aborted) return;
      await load(signal); if (signal.aborted) return;
      setSelected(policy); setMessage('Immutable policy version saved. Review differences before publication.');
    } catch (error) { if (!signal.aborted) failure(error); }
    finally { if (!signal.aborted) setBusy(false); }
  }
  const amounts = fixtures.split(/[\s,]+/).filter(Boolean).map(Number);
  const validFixtures = amounts.length > 0 && amounts.length <= 25 && amounts.every(value => Number.isSafeInteger(value) && value >= 1 && value <= 50000);
  async function simulate() {
    if (!selected || !validFixtures || sessionSignal.aborted) return;
    setSimulation(null); setConfirmation(null); const signal = begin();
    try { const result = await simulatePolicy(token, connection.trim(), selected.version, amounts, signal); if (!signal.aborted) setSimulation({ result, amounts }); }
    catch (error) { if (!signal.aborted) failure(error); }
    finally { if (!signal.aborted) setBusy(false); }
  }
  async function publish() {
    if (!confirmation || !page?.can_publish || sessionSignal.aborted) return;
    const captured = confirmation; setConfirmation(null); const signal = begin();
    try {
      await publishPolicy(token, connection.trim(), captured.policy.version, captured.expected, signal);
      if (signal.aborted) return;
      setSimulation(null); setSelected(null); await load(signal);
      if (!signal.aborted) setMessage('Publication confirmed. Active policy refreshed. Pending monetary approvals may require reevaluation.');
    } catch (error) {
      if (signal.aborted) return;
      setSelected(null); setSimulation(null);
      if (error instanceof ApiError && error.status === 409) {
        try { await load(signal); } catch (refreshError) { if (!signal.aborted) { setPage(null); failure(refreshError); return; } }
      }
      if (!(error instanceof ApiError) || error.status >= 500) setPage(null);
      if (!signal.aborted) failure(error, true);
    } finally { if (!signal.aborted) setBusy(false); }
  }
  const valid = parse(form);
  return <section aria-labelledby="policy-title">
    <h2 id="policy-title">Policy administration</h2>
    <p className="muted">Immutable policy versions for a connection. Amounts use USD minor units (100 = USD 1.00). Budgets and monetary approvals are separate controls.</p>
    <form className="operations-filter" onSubmit={event => void refresh(event)}><label htmlFor="policy-connection">Connection UUID</label><input id="policy-connection" required value={connection} autoComplete="off" spellCheck={false} onChange={event => { clear(); setConnection(event.target.value); }} /><button disabled={busy || sessionSignal.aborted}>Refresh policies</button></form>
    {message && <p className="notice" role="status">{message}</p>}
    {busy && <p className="state" role="status">Policy request in progress…</p>}
    {page && <>
      <article className="card export-form"><h3>Current active policy</h3><Values policy={page.active_policy} /><p className="muted">Capabilities: {page.can_edit ? 'create drafts' : 'no draft creation'}; {page.can_publish ? 'publish saved versions' : 'no publication'}. Server authorization is checked on every request.</p></article>
      <div className="export-forms">
        <form className="card export-form" onSubmit={event => void save(event)}><h3>Create immutable version</h3>{fields.map((key, index) => <label key={key} htmlFor={'policy-' + key}>{labels[index]}<input id={'policy-' + key} type="number" required step="1" min={key === 'auto_limit_minor' || key === 'hard_limit_minor' ? 0 : 1} max={key === 'version' ? Number.MAX_SAFE_INTEGER : key === 'approval_ttl_seconds' ? 86400 : 50000} value={form[key]} disabled={!page.can_edit || busy} onChange={event => { invalidate(); setForm({ ...form, [key]: event.target.value }); }} /></label>)}<p className="muted">Use a positive safe integer version; 0 ≤ automatic ≤ hard ≤ 50000; TTL 1–86400 seconds. Saving never overwrites an existing version.</p>{!valid && <p role="alert">Enter whole numbers within these limits.</p>}<button disabled={busy || !page.can_edit || !valid}>Save new version</button></form>
        <article className="card export-form"><h3>Saved versions</h3><label htmlFor="policy-saved">Select saved version</label><select id="policy-saved" value={selected?.version ?? ''} disabled={busy} onChange={event => { invalidate(); const policy = page.versions.find(item => item.version === Number(event.target.value)); setSelected(policy ?? null); }}><option value="">Choose a version</option>{selected && !page.versions.some(item => item.version === selected.version) && <option value={selected.version}>{selected.version}</option>}{page.versions.map(item => <option key={item.version} value={item.version}>{item.version}</option>)}</select>{page.next_after !== null && <button disabled={busy} onClick={() => void refresh(undefined, page.next_after)}>Load more versions</button>}<p className="muted">Loaded {page.versions.length} versions. The active policy is shown independently above.</p>{selected && <><h3>Difference from active policy</h3><Diff active={page.active_policy} selected={selected} /><button disabled={busy || !page.can_publish} onClick={() => setConfirmation({ policy: { ...selected }, active: page.active_policy ? { ...page.active_policy } : null, expected: page.active_policy?.version ?? 0 })}>Review publication</button></>}</article>
      </div>
      <article className="card export-form"><h3>Static simulation</h3><p className="muted">Synthetic refund fixtures only; fabricated payment IDs policy_simulation_0, policy_simulation_1, etc. No payment verification, provider access, budget reservation or execution eligibility check occurs.</p><label htmlFor="policy-fixtures">Amounts in minor units (comma or space separated, 1–25 fixtures)</label><textarea id="policy-fixtures" disabled={busy} value={fixtures} onChange={event => { stop(); setSimulation(null); setConfirmation(null); setFixtures(event.target.value); }} />{!validFixtures && <p role="alert">Enter 1–25 whole amounts, each 1–50000.</p>}<button disabled={busy || !selected || !validFixtures || !(page.can_edit || page.can_publish)} onClick={() => void simulate()}>Simulate selected saved version</button>{simulation && <><p>Compared active version {simulation.result.active_version ?? 'none'} with saved version {simulation.result.draft_version}.</p><div className="operations-table-wrap"><table className="operations-table"><caption>Static policy outcomes and reasons; allow does not guarantee execution</caption><thead><tr><th>Fabricated payment ID</th><th>Amount</th><th>Active outcome / reason</th><th>Selected outcome / reason</th></tr></thead><tbody>{simulation.result.results.map((result, index) => <tr key={index}><td>policy_simulation_{index}</td><td>{simulation.amounts[index]}</td><td>{result.old.outcome}: {result.old.reason}</td><td>{result.new.outcome}: {result.new.reason}</td></tr>)}</tbody></table></div></>}</article>
    </>}
    <dialog ref={dialog} aria-labelledby="policy-confirm-title" onCancel={() => setConfirmation(null)} onClose={() => setConfirmation(null)}>{confirmation && <><h2 id="policy-confirm-title">Publish saved version {confirmation.policy.version}?</h2><p>Connection: {connection.trim()}</p><p>Expected active version: {confirmation.expected} {confirmation.expected === 0 && '(no active policy)'}</p><Diff active={confirmation.active} selected={confirmation.policy} /><p className="muted">Publication changes the active policy and can invalidate pending approvals. It does not approve or execute a refund. A concurrent publication will reject this expected version.</p><div className="buttons"><button autoFocus onClick={() => setConfirmation(null)}>Cancel</button><button className="danger" disabled={busy || !page?.can_publish} onClick={() => void publish()}>Confirm publication</button></div></>}</dialog>
  </section>;
}
