import type { ReviewerCredential } from './api';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { evidenceErrorMessage, searchEvidence, type EvidenceItem, type EvidenceQuery } from './api';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_SELECTION = 1000;
const STATUSES = ['received', 'pending_approval', 'ready', 'dispatching', 'succeeded', 'failed_confirmed', 'denied', 'rejected', 'expired', 'cancelled'] as const satisfies readonly NonNullable<EvidenceQuery['status']>[];
interface Filters {
  connection: string;
  status: string;
  workload: string;
  action: string;
  min: string;
  max: string;
  limit: string;
}
const INITIAL: Filters = { connection: '', status: '', workload: '', action: '', min: '', max: '', limit: '50' };

export function EvidenceSearch({ token, sessionSignal, disabled, onUseSelection, onOpenDetail }: {
  token: ReviewerCredential;
  sessionSignal: AbortSignal;
  disabled: boolean;
  onOpenDetail: (connectionId: string, actionId: string) => void;
  onUseSelection: (connectionId: string, actionIds: string[]) => void;
}) {
  const [filters, setFilters] = useState<Filters>(INITIAL);
  const [query, setQuery] = useState<EvidenceQuery | null>(null);
  const [items, setItems] = useState<EvidenceItem[]>([]);
  const [selected, setSelected] = useState<Set<string>>(() => new Set());
  const [cursors, setCursors] = useState<Array<string | undefined>>([undefined]);
  const [pageIndex, setPageIndex] = useState(0);
  const [next, setNext] = useState<string | null>(null);
  const [searched, setSearched] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const current = useRef<AbortController | null>(null);
  const generation = useRef(0);
  const live = useRef(false);
  const resultsTitle = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    live.current = true;
    setItems([]);
    setSelected(new Set());
    setQuery(null);
    setSearched(false);
    setLoading(false);
    setError('');
    setNotice('');
    const abort = () => { generation.current += 1; current.current?.abort(); };
    sessionSignal.addEventListener('abort', abort);
    return () => {
      live.current = false;
      abort();
      sessionSignal.removeEventListener('abort', abort);
    };
  }, [token, sessionSignal]);

  function change(field: keyof Filters, value: string) {
    generation.current += 1;
    current.current?.abort();
    current.current = null;
    setFilters((previous) => ({ ...previous, [field]: value }));
    setItems([]);
    setSelected(new Set());
    setQuery(null);
    setCursors([undefined]);
    setPageIndex(0);
    setNext(null);
    setSearched(false);
    setLoading(false);
    setError('');
    setNotice('');
  }

  function validatedQuery(): EvidenceQuery | null {
    const connection = filters.connection.trim().toLowerCase();
    const workload = filters.workload.trim().toLowerCase();
    const action = filters.action.trim().toLowerCase();
    if (!UUID.test(connection) || (workload && !UUID.test(workload)) || (action && !UUID.test(action))) {
      setError('Enter a connection UUID and valid optional workload and action UUIDs.');
      return null;
    }
    const integer = (value: string) => /^\d+$/.test(value) && Number.isSafeInteger(Number(value));
    if ((filters.min && (!integer(filters.min) || Number(filters.min) > 50000)) || (filters.max && (!integer(filters.max) || Number(filters.max) > 50000))
      || (filters.min && filters.max && Number(filters.min) > Number(filters.max))
      || !integer(filters.limit) || Number(filters.limit) < 1 || Number(filters.limit) > 100) {
      setError('Use whole minor-unit amounts from 0 to 50,000, minimum no greater than maximum, and a page size from 1 to 100.');
      return null;
    }
    return {
      connection_id: connection,
      ...(filters.status && { status: STATUSES.find((status) => status === filters.status) }),
      ...(workload && { workload_id: workload }),
      ...(action && { action_id: action }),
      ...(filters.min && { min_amount_minor: Number(filters.min) }),
      ...(filters.max && { max_amount_minor: Number(filters.max) }),
      limit: Number(filters.limit),
    };
  }

  async function loadPage(applied: EvidenceQuery, after: string | undefined, index: number, history: Array<string | undefined>) {
    if (sessionSignal.aborted) return;
    current.current?.abort();
    const controller = new AbortController();
    current.current = controller;
    const sequence = ++generation.current;
    const abort = () => controller.abort();
    sessionSignal.addEventListener('abort', abort);
    const active = () => live.current && !sessionSignal.aborted && !controller.signal.aborted
      && generation.current === sequence;
    setLoading(true);
    setItems([]);
    setError('');
    setNotice('');
    setNext(null);
    try {
      const page = await searchEvidence(token, { ...applied, ...(after && { after }) }, controller.signal);
      if (!active()) return;
      if (page.items.length > 100 || page.items.some((item) => item.connection_id.toLowerCase() !== applied.connection_id
        || !UUID.test(item.id)) || new Set(page.items.map((item) => item.id)).size !== page.items.length
        || (page.next_after !== null && !UUID.test(page.next_after))) {
        throw new Error('Search unavailable');
      }
      setItems(page.items);
      setNext(page.next_after);
      setQuery(applied);
      setPageIndex(index);
      setCursors(history);
      setSearched(true);
      requestAnimationFrame(() => { if (active()) resultsTitle.current?.focus(); });
    } catch (error) {
      if (active()) {
        setError(evidenceErrorMessage(error));
        setSearched(false);
        setSelected(new Set());
        setQuery(null);
      }
    } finally {
      sessionSignal.removeEventListener('abort', abort);
      if (active()) setLoading(false);
      if (current.current === controller) current.current = null;
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (disabled || loading || sessionSignal.aborted) return;
    const applied = validatedQuery();
    if (!applied) return;
    setSelected(new Set());
    void loadPage(applied, undefined, 0, [undefined]);
  }

  function toggle(id: string) {
    if (disabled || loading || sessionSignal.aborted) return;
    setNotice('');
    setSelected((previous) => {
      const changed = new Set(previous);
      if (changed.has(id)) changed.delete(id);
      else if (changed.size < MAX_SELECTION) changed.add(id);
      return changed;
    });
  }

  function useSelection() {
    if (!query || disabled || loading || !selected.size || sessionSignal.aborted) return;
    onUseSelection(query.connection_id, [...selected]);
    setNotice('Selected action IDs were copied to the export form. Review that form before requesting the export.');
  }

  return <section className="card evidence-search" aria-labelledby="search-title">
    <h3 id="search-title">Find actions for an export</h3>
    <p className="muted">Search redacted evidence with an explicit connection evidence grant. Select up to 1,000 unique actions across pages from one connection. Changing any filter clears the results and selection.</p>
    <form onSubmit={submit} className="search-form">
      <div className="search-filters">
        <label htmlFor="search-connection">Connection UUID
          <input id="search-connection" value={filters.connection} onChange={(event) => change('connection', event.target.value)} required autoComplete="off" spellCheck={false} disabled={disabled} />
        </label>
        <label htmlFor="search-status">Status
          <select id="search-status" value={filters.status} onChange={(event) => change('status', event.target.value)} disabled={disabled}>
            <option value="">Any status</option>
            {STATUSES.map((status) => <option key={status} value={status}>{status}</option>)}
          </select>
        </label>
        <label htmlFor="search-workload">Workload UUID (optional)
          <input id="search-workload" value={filters.workload} onChange={(event) => change('workload', event.target.value)} autoComplete="off" spellCheck={false} disabled={disabled} />
        </label>
        <label htmlFor="search-action">Action UUID (optional)
          <input id="search-action" value={filters.action} onChange={(event) => change('action', event.target.value)} autoComplete="off" spellCheck={false} disabled={disabled} />
        </label>
        <label htmlFor="search-min">Minimum amount (minor units)
          <input id="search-min" inputMode="numeric" value={filters.min} onChange={(event) => change('min', event.target.value)} disabled={disabled} />
        </label>
        <label htmlFor="search-max">Maximum amount (minor units)
          <input id="search-max" inputMode="numeric" value={filters.max} onChange={(event) => change('max', event.target.value)} disabled={disabled} />
        </label>
        <label htmlFor="search-limit">Actions per page (1–100)
          <input id="search-limit" inputMode="numeric" value={filters.limit} onChange={(event) => change('limit', event.target.value)} required disabled={disabled} />
        </label>
      </div>
      <button type="submit" disabled={disabled || loading}>{loading ? 'Searching…' : 'Search evidence'}</button>
    </form>
    {error && <p className="notice error" role="alert">{error}</p>}
    {notice && <p className="notice" role="status">{notice}</p>}
    <div className="search-selection">
      <p role="status">{selected.size.toLocaleString()} of 1,000 selected</p>
      <div className="buttons">
        <button type="button" disabled={disabled || loading || !selected.size} onClick={() => { setSelected(new Set()); setNotice('Selection cleared.'); }}>Clear selection</button>
        <button type="button" className="primary" disabled={disabled || loading || !selected.size} onClick={useSelection}>Use selected actions</button>
      </div>
    </div>
    {loading && <p className="state" role="status">Loading redacted evidence…</p>}
    {searched && !loading && <div className="search-results">
      <h4 ref={resultsTitle} tabIndex={-1}>Search results · page {pageIndex + 1}</h4>
      <p className="muted">Pages use action UUID cursors. They do not represent chronological order.</p>
      {!items.length ? <p className="state" role="status">No actions match these filters.</p> :
        <div className="table-scroll" role="region" aria-label="Evidence search results" tabIndex={0}>
          <table>
            <caption className="sr-only">Redacted actions. Amounts are exact integer minor units in the displayed currency.</caption>
            <thead><tr><th scope="col">Select</th><th scope="col">Action / workload</th><th scope="col">Amount</th><th scope="col">Status / reason</th><th scope="col">Policy / budget</th></tr></thead>
            <tbody>{items.map((item) => <tr key={item.id}>
              <td><input type="checkbox" aria-label={`Select action ${item.id}`} checked={selected.has(item.id)}
                disabled={disabled || (!selected.has(item.id) && selected.size >= MAX_SELECTION)} onChange={() => toggle(item.id)} /></td>
              <td><code>{item.id}</code><button type="button" disabled={disabled || loading} onClick={() => onOpenDetail(item.connection_id, item.id)}>View action detail</button><span className="evidence-secondary">Workload <code>{item.workload_id}</code></span></td>
              <td className="evidence-amount">{item.amount_minor.toLocaleString()} <span>{item.currency} minor units</span></td>
              <td>{item.status}<span className="evidence-secondary">{item.reason ?? 'No reason recorded'}</span></td>
              <td>Version {item.policy_version ?? '—'}<span className="evidence-secondary">{item.budget_state ?? 'No budget record'}{item.budget_amount_minor !== null ? ` · ${item.budget_amount_minor.toLocaleString()} minor units` : ''}</span></td>
            </tr>)}</tbody>
          </table>
        </div>}
      <div className="buttons search-pagination">
        <button type="button" disabled={disabled || pageIndex === 0 || !query} onClick={() => {
          if (query) void loadPage(query, cursors[pageIndex - 1], pageIndex - 1, cursors);
        }}>Previous page</button>
        <button type="button" disabled={disabled || !next || !query} onClick={() => {
          if (query && next) void loadPage(query, next, pageIndex + 1, [...cursors.slice(0, pageIndex + 1), next]);
        }}>Next page</button>
      </div>
    </div>}
  </section>;
}
