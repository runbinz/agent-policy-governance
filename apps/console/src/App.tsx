import type { ReviewerCredential, AuthConfig, BrowserCredential } from './api';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { ApiError, errorMessage, listApprovals, submitDecision, getAuthConfig, readBrowserSession, logoutBrowserSession, type Approval, type Decision } from './api';
import { OperationsPanel } from './OperationsPanel';
import { PolicyPanel } from './PolicyPanel';
import { AdministrationPanel } from './AdministrationPanel';
import { ExportPanel } from './ExportPanel';
import { ActionDetail } from './ActionDetail';
import { EMPTY_APPROVAL_FILTERS, filterApprovals, recordedAgeMinutes, validateApprovalFilters, type ApprovalFilters } from './approvalFilters';
import './style.css';

function money(item: Approval) {
  const { amount_minor, currency } = item.request.parameters;
  return new Intl.NumberFormat('en-US', { style: 'currency', currency, currencyDisplay: 'code' }).format(amount_minor / 100);
}

function expiry(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium', timeStyle: 'long',
  }).format(date);
}

function Facts({ item, now = Date.now() }: { item: Approval; now?: number }) {
  const age = recordedAgeMinutes(item.queued_at, now);
  return (
    <dl className="facts">
      <div><dt>Payment</dt><dd><code>{item.request.resource.payment_id}</code></dd></div>
      <div><dt>Connection</dt><dd><code>{item.connection_id}</code></dd></div>
      <div><dt>Queued</dt><dd>{item.queued_at ? <time dateTime={item.queued_at}>{expiry(item.queued_at)}</time> : 'Unknown (historical timestamp unavailable)'}</dd></div>
      <div><dt>Recorded queue age</dt><dd>{age === null ? 'Unknown' : `${age.toLocaleString()} whole minutes`}</dd></div>
      <div><dt>Expires</dt><dd><time dateTime={item.expires_at}>{expiry(item.expires_at)}</time></dd></div>
      <div><dt>Policy version</dt><dd>{item.policy_version}</dd></div>
      <div><dt>Action ID</dt><dd><code>{item.action_id}</code></dd></div>
    </dl>
  );
}

function Confirmation({ item, decision, busy, onCancel, onConfirm }: {
  item: Approval;
  decision: Decision;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const node = dialog.current;
    node?.showModal();
    return () => node?.close();
  }, []);
  const verb = decision === 'approve' ? 'Approve' : 'Reject';
  return (
    <dialog ref={dialog} aria-labelledby="confirm-title" onCancel={(event) => {
      event.preventDefault();
      if (!busy) onCancel();
    }}>
      <p className="eyebrow">Confirm decision</p>
      <h2 id="confirm-title">{verb} {money(item)} refund?</h2>
      <p className="muted">Review the exact payment and connection before recording this decision.</p>
      <Facts item={item} />
      <div className="buttons">
        <button type="button" autoFocus disabled={busy} onClick={onCancel}>Go back</button>
        <button type="button" className={decision === 'approve' ? 'primary' : 'danger'} disabled={busy} onClick={onConfirm}>
          {busy ? 'Saving decision…' : `Confirm ${decision === 'approve' ? 'approval' : 'rejection'}`}
        </button>
      </div>
    </dialog>
  );
}

function Queue({ token, sessionSignal, onOpenDetail }: { token: ReviewerCredential; sessionSignal: AbortSignal; onOpenDetail: (connectionId: string, actionId: string) => void }) {
  const [items, setItems] = useState<Approval[]>([]);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [filters, setFilters] = useState<ApprovalFilters>({ ...EMPTY_APPROVAL_FILTERS });
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [confirm, setConfirm] = useState<{ item: Approval; decision: Decision } | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const live = useRef(true);
  const decisionController = useRef<AbortController | null>(null);
  useEffect(() => { live.current = true; return () => { live.current = false; decisionController.current?.abort(); }; }, []);

  useEffect(() => {
    const controller = new AbortController();
    const abort = () => controller.abort();
    sessionSignal.addEventListener('abort', abort);
    if (sessionSignal.aborted) controller.abort();
    async function load() {
      try {
        const items = await listApprovals(token, controller.signal);
        if (!controller.signal.aborted) {
          setItems(items);
          setNow(Date.now());
          setError('');
        }
      } catch (error) {
        if (!controller.signal.aborted) {
          setItems([]);
          setError(errorMessage(error));
        }
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => { controller.abort(); sessionSignal.removeEventListener('abort', abort); };
  }, [token, refresh, sessionSignal]);

  function refreshQueue() {
    setLoading(true);
    setRefresh((current) => current + 1);
  }

  async function decide() {
    if (!confirm || sending || sessionSignal.aborted) return;
    setSending(true);
    setError('');
    setNotice('');
    try {
      const controller = new AbortController();
      decisionController.current = controller;
      await submitDecision(token, confirm.item, confirm.decision, AbortSignal.any([sessionSignal, controller.signal]));
      if (!live.current || sessionSignal.aborted) return;
      setNotice(confirm.decision === 'approve'
        ? 'Approval recorded. The worker still needs to process the refund.'
        : 'Rejection recorded.');
    } catch (error) {
      if (!live.current || sessionSignal.aborted) return;
      if (error instanceof ApiError && error.status === 409) {
        setNotice('This approval changed or expired. Review the refreshed queue before making another decision.');
      } else {
        setNotice(`${errorMessage(error)} The decision outcome could not be confirmed here.`);
      }
    } finally {
      if (live.current && !sessionSignal.aborted) {
        setConfirm(null);
        setSending(false);
        refreshQueue();
        requestAnimationFrame(() => heading.current?.focus());
      }
    }
  }

  const connections = [...new Set(items.map((item) => item.connection_id))].sort();
  const currencies: string[] = [...new Set(items.map((item) => item.request.parameters.currency))].sort();
  const filterError = validateApprovalFilters(filters);
  const shown = filterApprovals(items, filters, now);
  function changeFilter(key: keyof ApprovalFilters, value: string) {
    setFilters((previous) => ({ ...previous, [key]: value }));
  }
  return (
    <section aria-labelledby="queue-title">
      <div className="queue-toolbar">
        <h2 id="queue-title" ref={heading} tabIndex={-1}>Pending refunds <span className="count">{items.length}</span></h2>
        <div className="toolbar-controls">
          <button type="button" disabled={loading || sending} onClick={() => { setNotice(''); refreshQueue(); }}>Refresh queue</button>
        </div>
      </div>
      <fieldset className="approval-filters" aria-describedby="approval-filter-help approval-filter-error">
        <legend>Filter authorized approvals</legend>
        <label>Connection<select value={filters.connection} onChange={(event) => changeFilter('connection', event.target.value)}>
          <option value="">All connections</option>
          {filters.connection && !connections.includes(filters.connection) && <option value={filters.connection}>{filters.connection} (no current approvals)</option>}
          {connections.map((id) => <option key={id} value={id}>{id}</option>)}
        </select></label>
        <label>Currency<select value={filters.currency} onChange={(event) => changeFilter('currency', event.target.value)}>
          <option value="">All currencies</option>
          {filters.currency && !currencies.includes(filters.currency) && <option value={filters.currency}>{filters.currency}</option>}
          {currencies.map((currency) => <option key={currency} value={currency}>{currency}</option>)}
        </select></label>
        <label>Minimum amount (integer minor units)<input inputMode="numeric" value={filters.minimum} onChange={(event) => changeFilter('minimum', event.target.value)} /></label>
        <label>Maximum amount (integer minor units)<input inputMode="numeric" value={filters.maximum} onChange={(event) => changeFilter('maximum', event.target.value)} /></label>
        <label>Minimum recorded age (whole minutes)<input inputMode="numeric" value={filters.ageMinutes} onChange={(event) => changeFilter('ageMinutes', event.target.value)} /></label>
        <button type="button" onClick={() => setFilters({ ...EMPTY_APPROVAL_FILTERS })}>Reset filters</button>
      </fieldset>
      <p id="approval-filter-help" className="muted">Amount bounds are inclusive and require a currency. Age uses this approval generation’s recorded queue timestamp and updates automatically. Unknown ages are excluded only when an age filter is active.</p>
      <p id="approval-filter-error" className={filterError ? 'notice error' : undefined} role="alert">{filterError}</p>
      {!loading && !error && !filterError && <p role="status">Showing {shown.length} of {items.length} authorized approvals.</p>}
      {notice && <p className="notice" role="status">{notice}</p>}
      {error && <p className="notice error" role="alert">{error}</p>}
      {loading ? <p className="state" role="status">Loading pending refunds…</p>
        : filterError ? <p className="state">Correct the filters to view matching approvals.</p>
        : !error && shown.length === 0 ? <p className="state" role="status">{items.length === 0 ? 'No refunds are waiting for your review.' : 'No approvals match these filters. Adjust or reset the filters.'}</p>
        : <ul className="approval-list">
          {shown.map((item) => (
            <li className="card" key={`${item.action_id}:${item.generation}`}>
              <div className="card-header"><div><p className="eyebrow">Refund request</p><h3>{money(item)}</h3></div><span className="badge">Pending approval</span></div>
              <Facts item={item} now={now} />
              <div className="buttons">
                <button type="button" onClick={() => onOpenDetail(item.connection_id, item.action_id)}>View action detail</button>
                <button type="button" onClick={() => setConfirm({ item, decision: 'reject' })}>Review rejection</button>
                <button type="button" className="primary" onClick={() => setConfirm({ item, decision: 'approve' })}>Review approval</button>
              </div>
            </li>
          ))}
        </ul>}
      {confirm && <Confirmation item={confirm.item} decision={confirm.decision} busy={sending} onCancel={() => setConfirm(null)} onConfirm={() => void decide()} />}
    </section>
  );
}

export default function App() {
  const [draft, setDraft] = useState('');
  const [token, setToken] = useState<ReviewerCredential>('');
  const [tab, setTab] = useState<'approvals' | 'evidence' | 'operations' | 'policies' | 'administration'>('approvals');
  const [selectedDetail, setSelectedDetail] = useState<{ connectionId: string; actionId: string; origin: 'approvals' | 'evidence' } | null>(null);
  const [epoch, setEpoch] = useState(0);
  const [config, setConfig] = useState<AuthConfig | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [authError, setAuthError] = useState('');
  const [authNotice, setAuthNotice] = useState('');
  const [authRefresh, setAuthRefresh] = useState(0);
  const [logoutPending, setLogoutPending] = useState<BrowserCredential | null>(null);
  const [loggingOut, setLoggingOut] = useState(false);
  const session = useRef(new AbortController());
  useEffect(() => () => session.current.abort(), []);

  function replaceCredential(value: ReviewerCredential) {
    session.current.abort();
    session.current = new AbortController();
    setEpoch((value) => value + 1);
    setTab('approvals');
    setSelectedDetail(null);
    setToken(value);
  }

  useEffect(() => {
    const controller = new AbortController();
    setAuthLoading(true);
    setAuthError('');
    async function load() {
      try {
        const next = await getAuthConfig(controller.signal);
        if (controller.signal.aborted) return;
        setConfig(next);
        if (next.managed_login) {
          const credential = await readBrowserSession(controller.signal);
          if (!controller.signal.aborted && credential) replaceCredential(credential);
        }
      } catch {
        if (!controller.signal.aborted) setAuthError('Reviewer sign-in could not be loaded. Check the service and retry.');
      } finally {
        if (!controller.signal.aborted) setAuthLoading(false);
      }
    }
    void load();
    return () => controller.abort();
  }, [authRefresh]);

  useEffect(() => {
    if (typeof token === 'string') return;
    const timer = window.setTimeout(() => {
      session.current.abort();
      setToken('');
      setAuthNotice('Your session expired. Sign in again.');
    }, Math.max(0, token.expiresAt * 1000 - Date.now()));
    return () => window.clearTimeout(timer);
  }, [token]);

  function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!config?.development_tokens || !draft.trim()) return;
    replaceCredential(draft.trim());
    setDraft('');
    setAuthError('');
    setAuthNotice('');
  }

  async function signOut() {
    if (loggingOut) return;
    const old = logoutPending ?? token;
    session.current.abort();
    setToken('');
    setAuthError('');
    if (typeof old === 'string') { setAuthNotice('Reviewer token cleared.'); return; }
    setLoggingOut(true);
    try {
      await logoutBrowserSession(old);
      setLogoutPending(null);
      setAuthNotice('Signed out of reviewer tools.');
    } catch {
      setLogoutPending(old);
      setAuthError('Sign-out could not be confirmed. Retry before leaving a shared browser.');
    } finally { setLoggingOut(false); }
  }

  return <>
    <header className="topbar"><div className="container topbar-inner">
      <div className="brand"><span aria-hidden="true">DG</span> Data Governance</div>
      <span className="environment">{config?.managed_login ? 'Managed sign-in' : config?.development_tokens ? 'Local development' : 'Reviewer console'}</span>
    </div></header>
    <main className="container">
      <div className="intro">
        <div><p className="eyebrow">Reviewer console</p><h1>Refund governance</h1><p className="muted">Review pending refunds, operational health, and scoped evidence.</p></div>
        {(token || logoutPending) && <button type="button" disabled={loggingOut} onClick={() => void signOut()}>
          {loggingOut ? 'Signing out…' : logoutPending ? 'Retry sign out' : typeof token === 'string' ? 'Clear reviewer token' : 'Sign out'}
        </button>}
      </div>
      {authError && <div className="notice error" role="alert"><p>{authError}</p>
        {!logoutPending && <button type="button" onClick={() => setAuthRefresh((n) => n + 1)} disabled={authLoading}>Retry sign-in check</button>}
      </div>}
      {authNotice && <p className="notice" role="status">{authNotice}</p>}
      {token ? <>
        <nav className="console-tabs" aria-label="Reviewer tools">
          <button type="button" aria-current={tab === 'approvals' ? 'page' : undefined} onClick={() => { setSelectedDetail(null); setTab('approvals'); }}>Approvals</button>
          <button type="button" aria-current={tab === 'evidence' ? 'page' : undefined} onClick={() => { setSelectedDetail(null); setTab('evidence'); }}>Evidence</button>
          <button type="button" aria-current={tab === 'operations' ? 'page' : undefined} onClick={() => { setSelectedDetail(null); setTab('operations'); }}>Operations</button>
          <button type="button" aria-current={tab === 'policies' ? 'page' : undefined} onClick={() => { setSelectedDetail(null); setTab('policies'); }}>Policies</button>
          <button type="button" aria-current={tab === 'administration' ? 'page' : undefined} onClick={() => { setSelectedDetail(null); setTab('administration'); }}>Administration</button>
        </nav>
        {selectedDetail ? <ActionDetail key={`${epoch}:${selectedDetail.connectionId}:${selectedDetail.actionId}`} token={token} sessionSignal={session.current.signal} connectionId={selectedDetail.connectionId} actionId={selectedDetail.actionId} onBack={() => { setTab(selectedDetail.origin); setSelectedDetail(null); }} onQueue={() => { setSelectedDetail(null); setTab('approvals'); }} /> : tab === 'approvals' ? <Queue key={epoch} token={token} sessionSignal={session.current.signal} onOpenDetail={(connectionId, actionId) => setSelectedDetail({ connectionId, actionId, origin: 'approvals' })} /> : tab === 'administration' ? <AdministrationPanel key={epoch} token={token} sessionSignal={session.current.signal} /> : tab === 'policies' ? <PolicyPanel key={epoch} token={token} sessionSignal={session.current.signal} /> : tab === 'operations' ? <OperationsPanel key={epoch} token={token} sessionSignal={session.current.signal} /> : <ExportPanel key={epoch} token={token} sessionSignal={session.current.signal} onOpenDetail={(connectionId, actionId) => setSelectedDetail({ connectionId, actionId, origin: 'evidence' })} />}
      </> : authLoading ? <p className="state" role="status">Checking reviewer sign-in…</p>
        : config?.managed_login ? <section className="card sign-in" aria-labelledby="login-title">
          <h2 id="login-title">Sign in to reviewer tools</h2>
          <p>Your identity provider verifies your account. Access still requires assigned project roles.</p>
          <form action="/auth/login" method="post"><button type="submit" className="primary" disabled={loggingOut || !!logoutPending}>Sign in with identity provider</button></form>
        </section> : config?.development_tokens ? <section className="card sign-in" aria-labelledby="token-title">
          <h2 id="token-title">Open reviewer tools</h2>
          <form onSubmit={signIn} autoComplete="off">
            <label htmlFor="token">Development reviewer bearer token</label>
            <input id="token" type="password" autoComplete="off" spellCheck={false} value={draft} onChange={(event) => setDraft(event.target.value)} required aria-describedby="token-help" />
            <p id="token-help" className="muted">The token stays in this page’s memory and clears on reload.</p>
            <button className="primary" type="submit" disabled={!draft.trim()}>Open reviewer tools</button>
          </form>
        </section> : !authError && <p className="state">Reviewer sign-in is not configured. Contact your project administrator.</p>}
    </main>
  </>;
}
