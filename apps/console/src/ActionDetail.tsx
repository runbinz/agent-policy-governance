import { useEffect, useState, type ReactNode } from 'react';
import { ApiError, getActionDetail, getActionHistory, type ActionDetail as Detail, type ActionHistoryPage, type HistoryKind, type ReviewerCredential } from './api';

const KINDS: HistoryKind[] = ['audit', 'policy', 'approval', 'budget', 'attempt'];
function timestamp(value: string | null) {
  if (!value || !Number.isFinite(Date.parse(value))) return 'Unknown (historical timestamp unavailable)';
  return new Date(value).toLocaleString();
}
function amount(value: number, currency: string) { return `${value.toLocaleString()} ${currency} minor units`; }
function Fact({ name, children }: { name: string; children: ReactNode }) {
  return <div><dt>{name}</dt><dd>{children}</dd></div>;
}
function ApprovalFacts({ item }: { item: NonNullable<Detail['approval']> }) {
  return <dl className="facts">
    <Fact name="Generation">{item.generation}</Fact><Fact name="Policy version">{item.policy_version}</Fact>
    <Fact name="Action digest"><code>{item.action_digest}</code></Fact>
    {item.payment_attestation_id && <Fact name="Linked payment attestation"><code>{item.payment_attestation_id}</code></Fact>}
    <Fact name="Queued">{timestamp(item.queued_at)}</Fact><Fact name="Expires">{timestamp(item.expires_at)}</Fact>
    <Fact name="Decision">{item.decision ?? 'No decision recorded'}</Fact>
    <Fact name="Deciding reviewer"><code>{item.reviewer_id ?? 'No reviewer recorded'}</code></Fact>
    <Fact name="Decided">{item.decision ? timestamp(item.decided_at) : "Not decided"}</Fact>
  </dl>;
}
function PaymentFacts({ evidence }: { evidence: Detail['authoritative_payment'] }) {
  const payment = evidence.availability === 'verified_payment' ? evidence.payment : null;
  if (payment) return <>
    <dl className="facts">
      <Fact name="Attestation"><code>{payment.attestation_id}</code></Fact>
      <Fact name="Evidence source">{payment.source === 'approval' ? 'Approval generation' : 'Dispatch authorization'}</Fact>
      <Fact name="Approval generation">{payment.approval_generation ?? 'No approval generation'}</Fact>
      <Fact name="Schema version">{payment.schema_version}</Fact>
      <Fact name="Payment"><code>{payment.payment_id}</code></Fact>
      <Fact name="Connection"><code>{payment.connection_id}</code></Fact>
      <Fact name="Requested refund">{amount(payment.requested_minor, payment.currency)}</Fact>
      <Fact name="Charge amount">{amount(payment.charge_amount_minor, payment.currency)}</Fact>
      <Fact name="Captured amount">{amount(payment.captured_minor, payment.currency)}</Fact>
      <Fact name="Refunded amount">{amount(payment.refunded_minor, payment.currency)}</Fact>
      <Fact name="Remaining refundable amount at observation">{amount(payment.remaining_minor, payment.currency)}</Fact>
      <Fact name="Payment status">{payment.status}</Fact>
      <Fact name="Paid">{payment.paid ? 'Yes' : 'No'}</Fact>
      <Fact name="Captured">{payment.captured ? 'Yes' : 'No'}</Fact>
      <Fact name="Disputed">{payment.disputed ? 'Yes' : 'No'}</Fact>
      <Fact name="Payment method">{payment.method}</Fact>
      <Fact name="Direct charge">{payment.direct_charge ? 'Yes' : 'No'}</Fact>
      <Fact name="Eligible at observation">{payment.eligible_at_observation ? 'Yes' : 'No'}</Fact>
      <Fact name="Observed">{timestamp(payment.observed_at)}</Fact>
      <Fact name="Recorded fresh-until">{timestamp(payment.fresh_until)}</Fact>
      <Fact name="Freshness at response">{payment.freshness === 'fresh' ? 'Fresh at response' : 'Stale at response'}</Fact>
    </dl>
    <p className="muted">Retained historical payment facts, not a live balance or a claim of eligibility now. Freshness is assessed at response time. A stale observation alone does not prevent review; dispatch requires fresh matching facts and current authorization checks.</p>
  </>;
  const context = evidence.availability === 'verified_context' ? evidence.context : null;
  return <>{context ? <dl className="facts">
    <Fact name="Payment"><code>{context.payment_id}</code></Fact>
    <Fact name="Connection"><code>{context.connection_id}</code></Fact>
    <Fact name="Verified refund amount">{amount(context.amount_minor, context.currency)}</Fact>
    <Fact name="Observed">{timestamp(context.observed_at)}</Fact>
    <Fact name="Recorded fresh-until">{timestamp(context.fresh_until)}</Fact>
  </dl> : <p>Unavailable. No validated payment attestation is retained for this action.</p>}
    <p className="muted">{context ? 'Only legacy verified refund context is retained. ' : ''}Full payment facts, including captured and refunded amounts and recorded eligibility, are unavailable. This is not a live payment balance.</p>
  </>;
}
function HistoryRecord({ item }: { item: ActionHistoryPage['items'][number] }) {
  switch (item.kind) {
    case 'approval': return <ApprovalFacts item={item} />;
    case 'policy': return <dl className="facts"><Fact name="Audit sequence">{item.audit_sequence}</Fact><Fact name="Policy version">{item.policy_version ?? 'Unavailable'}</Fact><Fact name="Outcome">{item.outcome}</Fact><Fact name="Reason code">{item.reason_code}</Fact><Fact name="Evaluated">{timestamp(item.evaluated_at)}</Fact></dl>;
    case 'audit': return <dl className="facts"><Fact name="Sequence">{item.sequence}</Fact><Fact name="Event">{item.event_type}</Fact><Fact name="Recorded">{timestamp(item.recorded_at)}</Fact></dl>;
    case 'budget': return <dl className="facts"><Fact name="Sequence">{item.sequence}</Fact><Fact name="Event">{item.event_kind}</Fact><Fact name="Recorded">{timestamp(item.recorded_at)}</Fact></dl>;
    case 'attempt': return <dl className="facts"><Fact name="Generation">{item.generation}</Fact><Fact name="Send marker recorded">{timestamp(item.recorded_at)}</Fact></dl>;
  }
}
export function ActionDetail({ token, sessionSignal, connectionId, actionId, onBack, onQueue }: {
  token: ReviewerCredential; sessionSignal: AbortSignal; connectionId: string; actionId: string; onBack: () => void; onQueue: () => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [history, setHistory] = useState<ActionHistoryPage | null>(null);
  const [kind, setKind] = useState<HistoryKind>('audit');
  const [cursors, setCursors] = useState<Array<string | null>>([null]);
  const [page, setPage] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    // One bounded request pair at a time, with API timeouts; recheck access every 30 seconds.
    const timer = window.setInterval(() => setRefresh((value) => value + 1), 30000);
    return () => window.clearInterval(timer);
  }, []);
  const cursor = cursors[page];
  useEffect(() => {
    const controller = new AbortController();
    const clear = () => { setDetail(null); setHistory(null); };
    const abort = () => { controller.abort(); clear(); setLoading(false); };
    sessionSignal.addEventListener('abort', abort);
    clear(); setError(''); setLoading(true);
    if (sessionSignal.aborted) abort();
    const active = () => !controller.signal.aborted && !sessionSignal.aborted;
    async function load() {
      try {
        const [next, records] = await Promise.all([
          getActionDetail(token, connectionId, actionId, controller.signal),
          getActionHistory(token, connectionId, actionId, kind, cursor, controller.signal),
        ]);
        if (!active()) return;
        if (next.id !== actionId || next.connection_id !== connectionId || next.schema_version !== 1
          || records.items.length > 50 || records.items.some((item) => item.kind !== kind)) throw new Error('Invalid detail');
        setDetail(next); setHistory(records);
      } catch (failure) {
        if (!active()) return;
        clear();
        setError(failure instanceof ApiError && [401, 403, 404].includes(failure.status)
          ? 'This action is unavailable with your current access. Access or searchable retention may have changed. Detail requires a separate connection grant; approval and evidence access alone do not provide it.'
          : 'Action detail could not be refreshed. Previously loaded detail has been cleared. Retry to check current access.');
        // Cancel the other request even when only one member of the pair failed.
        controller.abort();
        setLoading(false);
      } finally { if (active()) setLoading(false); }
    }
    if (active()) void load();
    return () => { controller.abort(); sessionSignal.removeEventListener('abort', abort); };
  }, [token, sessionSignal, connectionId, actionId, kind, cursor, refresh]);
  return <section className="action-detail" aria-labelledby="detail-title">
    <div className="queue-toolbar"><h2 id="detail-title">Action detail</h2><div className="buttons"><button onClick={onBack} type="button">Back to results</button><button type="button" onClick={onQueue}>Open approval queue</button><button type="button" disabled={loading} onClick={() => setRefresh((value) => value + 1)}>Refresh detail</button></div></div>
    <p className="muted">Read-only recorded evidence. Access and retention are rechecked every 30 seconds. Decisions require a fresh approval queue item and explicit confirmation there.</p>
    {loading && <p role="status">Loading current action access and recorded detail…</p>}
    {error && <p role="alert" className="notice error">{error}</p>}
    {detail && history && <>
      <div className="detail-grid">
        <section className="card"><h3>Exact immutable request</h3><dl className="facts">
          <Fact name="Action"><code>{detail.id}</code></Fact><Fact name="Connection"><code>{detail.connection_id}</code></Fact><Fact name="Workload"><code>{detail.workload_id}</code></Fact><Fact name="Status">{detail.status}</Fact><Fact name="Type">{detail.immutable_request.type}</Fact><Fact name="Payment"><code>{detail.immutable_request.resource.payment_id}</code></Fact><Fact name="Requested amount">{amount(detail.immutable_request.parameters.amount_minor, detail.immutable_request.parameters.currency)}</Fact><Fact name="Created">{timestamp(detail.created_at)}</Fact><Fact name="Terminal">{["denied", "rejected", "expired", "cancelled", "failed_confirmed", "succeeded"].includes(detail.status) ? timestamp(detail.terminal_at) : "Not terminal"}</Fact><Fact name="Response observed">{timestamp(detail.observed_at)} (response time, not an event)</Fact>
        </dl></section>
        <section className="card"><h3>Recorded policy</h3>{detail.policy.latest ? <dl className="facts"><Fact name="Audit sequence">{detail.policy.latest.audit_sequence}</Fact><Fact name="Version">{detail.policy.latest.policy_version ?? 'Unavailable'}</Fact><Fact name="Outcome">{detail.policy.latest.outcome}</Fact><Fact name="Reason code">{detail.policy.latest.reason_code}</Fact></dl> : <p>No policy decision recorded.</p>}<p className="muted">This is the latest recorded decision, not today’s policy binding.</p></section>
        <section className="card"><h3>Latest approval</h3>{detail.approval ? <ApprovalFacts item={detail.approval} /> : <p>No approval recorded.</p>}<p>Current decision eligibility: {detail.decision_eligibility.can_decide ? 'Eligible at observation time' : 'Not eligible'} · {detail.decision_eligibility.reason_code}</p><p className="muted">Advisory only. Open the approval queue to review any currently authorized decision.</p></section>
        <section className="card"><h3>Retained payment facts</h3><PaymentFacts evidence={detail.authoritative_payment} /></section>
        <section className="card"><h3>Action budget exposure</h3>{detail.budget ? <><dl className="facts"><Fact name="State">{detail.budget.state}</Fact><Fact name="Recorded amount">{amount(detail.budget.amount_minor, detail.budget.currency)}</Fact><Fact name="UTC budget day">{detail.budget.utc_day}</Fact><Fact name="Reserved">{timestamp(detail.budget.reserved_at)}</Fact><Fact name="Settled or released">{timestamp(detail.budget.settled_or_released_at)}</Fact></dl><p>{detail.budget.state === 'held' ? 'Held exposure remains reserved, including unresolved and manual-review actions.' : detail.budget.state === 'settled' ? 'Settled exposure is committed.' : 'Released exposure contributes zero.'}</p></> : <p>No reservation recorded. This does not establish available budget.</p>}</section>
        <section className="card"><h3>Execution and outcome</h3>{detail.execution ? <dl className="facts"><Fact name="Execution state">{detail.execution.state}</Fact><Fact name="First send marker">{timestamp(detail.execution.first_send_at)}</Fact><Fact name="Retry until">{timestamp(detail.execution.retry_until)}</Fact><Fact name="State changed">{timestamp(detail.execution.state_changed_at)}</Fact><Fact name="Abandoned">{timestamp(detail.execution.abandoned_at)}</Fact></dl> : <p>No external execution record.</p>}<p>Outcome: {detail.provider_outcome.status} · Source: {detail.provider_outcome.source}</p><p className="muted">Local fixture outcomes are test evidence. A send marker does not prove an HTTP call or provider receipt; unresolved states do not confirm success or non-execution.</p></section>
      </div>
      <section className="card detail-history" aria-labelledby="history-title"><h3 id="history-title">Recorded history</h3><label>History kind <select value={kind} onChange={(event) => { setHistory(null); setDetail(null); setPage(0); setCursors([null]); setKind(event.target.value as HistoryKind); }}>{KINDS.map((value) => <option key={value} value={value}>{value}</option>)}</select></label><p className="muted">Page {page + 1}, at most 50 records. Each kind follows its own ascending sequence or generation; these pages do not form a combined chronological timeline. Unknown timestamps stay unknown.</p>{kind === 'attempt' && <p>Attempts are durable send markers, not proof of provider receipt.</p>}
        {history.items.length ? <ol className="detail-records">{history.items.map((item, index) => <li key={index}><HistoryRecord item={item} /></li>)}</ol> : <p>No records of this kind.</p>}
        <div className="buttons"><button type="button" disabled={page === 0} onClick={() => setPage((value) => value - 1)}>Previous history page</button><button type="button" disabled={!history.next_cursor} onClick={() => { if (history.next_cursor) { setCursors([...cursors.slice(0, page + 1), history.next_cursor]); setPage((value) => value + 1); } }}>Next history page</button><button type="button" disabled={page === 0} onClick={() => { setPage(0); setCursors([null]); }}>First history page</button></div>
      </section>
    </>}
  </section>;
}
