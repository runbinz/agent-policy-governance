import type { paths } from './api.generated';

const approvalPath = '/v1/approvals' satisfies keyof paths;
const decisionPath = '/v1/approvals/{id}/decision' satisfies keyof paths;

type ApprovalQueue = paths[typeof approvalPath]['get']['responses'][200]['content']['application/json'];
type DecisionOperation = paths[typeof decisionPath]['post'];
type DecisionInput = DecisionOperation['requestBody']['content']['application/json'];
type DecisionResult = DecisionOperation['responses'][200]['content']['application/json'];

export type Approval = ApprovalQueue[number];
export type Decision = DecisionInput['decision'];
export type BrowserCredential = { csrfToken: string; expiresAt: number };
export type ReviewerCredential = string | BrowserCredential;

export class ApiError extends Error {
  constructor(readonly status: number) {
    super(`Request failed (${status})`);
  }
}

async function call(path: string, token: ReviewerCredential, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.delete('Authorization');
  if (typeof token === 'string') headers.set('Authorization', `Bearer ${token}`);
  else {
    if (Date.now() >= token.expiresAt * 1000) throw new ApiError(401);
    if (!['GET', 'HEAD'].includes((init.method ?? 'GET').toUpperCase())) headers.set('X-CSRF-Token', token.csrfToken);
  }
  headers.set('Accept', 'application/json');
  const response = await fetch(path, {
    ...init, headers, cache: 'no-store', credentials: typeof token === 'string' ? 'omit' : 'same-origin', redirect: 'error',
  });
  if (!response.ok) throw new ApiError(response.status);
  return response;
}

export async function listApprovals(token: ReviewerCredential, signal?: AbortSignal): Promise<ApprovalQueue> {
  const response = await call(approvalPath, token, { signal });
  return response.json();
}

export async function submitDecision(token: ReviewerCredential, item: Approval, decision: Decision, signal?: AbortSignal): Promise<DecisionResult> {
  const body: DecisionInput = { generation: item.generation, action_digest: item.action_digest, decision };
  const response = await call(decisionPath.replace('{id}', encodeURIComponent(item.action_id)), token, {
    method: 'POST',
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(15000)]) : AbortSignal.timeout(15000),
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  return response.json();
}

export function errorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Your reviewer sign-in was not accepted. Sign in again.';
    if (error.status === 403 || error.status === 404) return 'You cannot access this approval, or it is no longer available.';
  }
  return 'The approval service could not complete the request. Check that the local API is running and refresh.';
}

const exportPath = '/v1/exports' satisfies keyof paths;
const exportInfoPath = '/v1/exports/{id}' satisfies keyof paths;
const exportDownloadPath = '/v1/exports/{id}/download' satisfies keyof paths;
export type EvidenceExport = paths[typeof exportInfoPath]['get']['responses'][200]['content']['application/json'];
export type ExportInput = paths[typeof exportPath]['post']['requestBody']['content']['application/json'];

export async function requestExport(token: ReviewerCredential, input: ExportInput, signal: AbortSignal): Promise<EvidenceExport> {
  const response = await call(exportPath, token, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input), signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
  });
  return response.json();
}

export async function getExport(token: ReviewerCredential, id: string, signal: AbortSignal): Promise<EvidenceExport> {
  const response = await call(exportInfoPath.replace('{id}', encodeURIComponent(id)), token, { signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
  return response.json();
}

export async function downloadExport(token: ReviewerCredential, id: string, signal: AbortSignal): Promise<Blob> {
  const response = await call(exportDownloadPath.replace('{id}', encodeURIComponent(id)), token, { signal: AbortSignal.any([signal, AbortSignal.timeout(45000)]) });
  const limit = 20 * 1024 * 1024;
  if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'application/json'
    || Number(response.headers.get('content-length')) > limit || !response.body) {
    await response.body?.cancel().catch(() => {});
    throw new Error('Export unavailable');
  }
  const reader = response.body.getReader();
  const chunks: ArrayBuffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit || signal.aborted) throw new Error('Export unavailable');
      chunks.push(value.slice().buffer);
    }
    if (signal.aborted) throw new Error('Export unavailable');
    return new Blob(chunks, { type: 'application/json' });
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

export function exportErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Your reviewer sign-in is no longer accepted. Sign in again.';
    if (error.status === 403 || error.status === 404) return 'This export is unavailable, expired, or outside your current access.';
    if (error.status === 409) return 'The export is not ready. Check its status again.';
    if (error.status === 400 || error.status === 413) return 'Check the connection and action IDs, then try again.';
  }
  return 'The export service could not complete this request. Check the service and try again.';
}

const evidencePath = '/v1/evidence' satisfies keyof paths;
type EvidenceOperation = paths[typeof evidencePath]['get'];
export type EvidenceQuery = NonNullable<EvidenceOperation['parameters']['query']>;
export type EvidencePage = EvidenceOperation['responses'][200]['content']['application/json'];
export type EvidenceItem = EvidencePage['items'][number];

export async function searchEvidence(token: ReviewerCredential, query: EvidenceQuery, signal: AbortSignal): Promise<EvidencePage> {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== '') parameters.set(key, String(value));
  }
  const response = await call(`${evidencePath}?${parameters}`, token, {
    signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
  });
  return response.json();
}

export function evidenceErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Your reviewer sign-in is no longer accepted. Sign in again.';
    if (error.status === 403 || error.status === 404) return 'Evidence search is unavailable for this connection with your current access.';
    if (error.status === 400) return 'Check the search filters and try again.';
  }
  return 'Evidence search could not complete this request. Check the service and try again.';
}

export type AuthConfig = paths['/auth/config']['get']['responses'][200]['content']['application/json'];
type SessionInfo = paths['/auth/session']['get']['responses'][200]['content']['application/json'];

export async function getAuthConfig(signal: AbortSignal): Promise<AuthConfig> {
  const response = await fetch('/auth/config', { cache: 'no-store', credentials: 'omit', redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
  if (!response.ok) throw new ApiError(response.status);
  const config: AuthConfig = await response.json();
  if (typeof config.managed_login !== 'boolean' || typeof config.development_tokens !== 'boolean'
    || (config.managed_login && config.development_tokens)) throw new Error('Invalid sign-in configuration');
  return config;
}

export async function readBrowserSession(signal: AbortSignal): Promise<BrowserCredential | null> {
  const response = await fetch('/auth/session', { cache: 'no-store', credentials: 'same-origin', redirect: 'error', signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
  if (response.status === 401) return null;
  if (!response.ok) throw new ApiError(response.status);
  const session: SessionInfo = await response.json();
  if (session.authenticated !== true || !/^[A-Za-z0-9_-]{43}$/.test(session.csrf_token)
    || !Number.isSafeInteger(session.expires_at) || session.expires_at * 1000 <= Date.now()) return null;
  return { csrfToken: session.csrf_token, expiresAt: session.expires_at };
}

export async function logoutBrowserSession(credential: BrowserCredential): Promise<void> {
  const response = await fetch('/auth/logout', { method: 'POST', cache: 'no-store', credentials: 'same-origin', redirect: 'error',
    headers: { 'X-CSRF-Token': credential.csrfToken }, signal: AbortSignal.timeout(15000) });
  if (response.status === 401 && await readBrowserSession(new AbortController().signal) === null) return;
  if (!response.ok) throw new ApiError(response.status);
}

const operationsPath = '/v1/operations' satisfies keyof paths;
export type OperationsSnapshot = paths[typeof operationsPath]['get']['responses'][200]['content']['application/json'];
export async function getOperations(token: ReviewerCredential, connectionId: string, signal: AbortSignal): Promise<OperationsSnapshot> {
  const response = await call(`${operationsPath}?${new URLSearchParams({ connection_id: connectionId })}`, token, {
    signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]),
  });
  return response.json();
}
export function operationsErrorMessage(error: unknown) {
  if (error instanceof ApiError) {
    if (error.status === 401) return 'Your reviewer sign-in is no longer accepted. Sign in again.';
    if (error.status === 403 || error.status === 404) return 'Operations are unavailable for this connection with your current access.';
    if (error.status === 400) return 'Enter a valid connection UUID and refresh.';
  }
  return 'The operations snapshot could not be loaded. Check the service and refresh.';
}

const detailPath = '/v1/reviewer/actions/{id}' satisfies keyof paths;
const detailHistoryPath = '/v1/reviewer/actions/{id}/history' satisfies keyof paths;
export type ActionDetail = paths[typeof detailPath]['get']['responses'][200]['content']['application/json'];
export type ActionHistoryPage = paths[typeof detailHistoryPath]['get']['responses'][200]['content']['application/json'];
export type HistoryKind = paths[typeof detailHistoryPath]['get']['parameters']['query']['kind'];

export async function getActionDetail(token: ReviewerCredential, connectionId: string, actionId: string, signal: AbortSignal): Promise<ActionDetail> {
  const query = new URLSearchParams({ connection_id: connectionId });
  const response = await call(detailPath.replace('{id}', encodeURIComponent(actionId)) + '?' + query, token,
    { signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
  return response.json();
}
export async function getActionHistory(token: ReviewerCredential, connectionId: string, actionId: string, kind: HistoryKind, after: string | null, signal: AbortSignal): Promise<ActionHistoryPage> {
  const query = new URLSearchParams({ connection_id: connectionId, kind, limit: '50' });
  if (after !== null) query.set('after', after);
  const response = await call(detailHistoryPath.replace('{id}', encodeURIComponent(actionId)) + '?' + query, token,
    { signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
  return response.json();
}

const policyPagePath = '/v1/policies' satisfies keyof paths;
export type PolicyPage = paths[typeof policyPagePath]['get']['responses'][200]['content']['application/json'];
export type ConsolePolicy = PolicyPage['versions'][number];
export type PolicySimulation = paths['/v1/policies/{version}/simulate']['post']['responses'][200]['content']['application/json'];
export async function getPolicyPage(token: ReviewerCredential, connection: string, after: number | null, signal: AbortSignal): Promise<PolicyPage> {
  const query = new URLSearchParams({connection_id:connection,limit:'50'});
  if (after !== null) query.set('after',String(after));
  return (await call(policyPagePath+'?'+query,token,{signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function createPolicyDraft(token: ReviewerCredential, connection: string, policy: ConsolePolicy, signal: AbortSignal): Promise<void> {
  await call('/v1/policies/drafts',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({connection_id:connection,...policy}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])});
}
export async function simulatePolicy(token: ReviewerCredential, connection: string, version: number, amounts: number[], signal: AbortSignal): Promise<PolicySimulation> {
  const requests=amounts.map((amount_minor,index)=>({type:'refund.create',connection_id:connection,resource:{payment_id:'policy_simulation_'+index},parameters:{amount_minor,currency:'USD'}}));
  return (await call('/v1/policies/'+encodeURIComponent(version)+'/simulate',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({connection_id:connection,requests}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function publishPolicy(token: ReviewerCredential, connection: string, version: number, expectedVersion: number, signal: AbortSignal): Promise<void> {
  await call('/v1/policies/'+encodeURIComponent(version)+'/publish',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({connection_id:connection,expected_version:expectedVersion}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])});
}

export type AdminEntityPage = paths['/v1/admin/entities']['get']['responses'][200]['content']['application/json'];
export type AdminEntity = AdminEntityPage['items'][number];
export type AdminEntityKind = AdminEntityPage['kind'];
export type AdminGrantPage = paths['/v1/admin/grants']['get']['responses'][200]['content']['application/json'];
export type AdminGrant = AdminGrantPage['items'][number];
export type AdminGrantKind = AdminGrantPage['kind'];
export type AdminRevokeInput = paths['/v1/admin/grants/revoke']['post']['requestBody']['content']['application/json'];
type AdminRevisionResult = paths['/v1/admin/grants/revoke']['post']['responses'][200]['content']['application/json'];
export async function getAdminEntities(token: ReviewerCredential, kind: AdminEntityKind, after: string | null, signal: AbortSignal): Promise<AdminEntityPage> {
  const query=new URLSearchParams({kind,limit:'50'});if(after!==null)query.set('after',after);
  return (await call('/v1/admin/entities?'+query,token,{signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function getAdminGrants(token: ReviewerCredential, kind: AdminGrantKind, after: string | null, signal: AbortSignal): Promise<AdminGrantPage> {
  const query=new URLSearchParams({kind,limit:'50'});if(after!==null)query.set('after',after);
  return (await call('/v1/admin/grants?'+query,token,{signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function setAdminEnabled(token: ReviewerCredential, kind: AdminEntityKind, id: string, expectedRevision: number, enabled: boolean, signal: AbortSignal): Promise<AdminRevisionResult> {
  return (await call('/v1/admin/entities/'+encodeURIComponent(kind)+'/'+encodeURIComponent(id)+'/enabled',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({expected_revision:expectedRevision,enabled}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function revokeAdminGrant(token: ReviewerCredential, input: AdminRevokeInput, signal: AbortSignal): Promise<AdminRevisionResult> {
  return (await call('/v1/admin/grants/revoke',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(input),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}

export type ControlState = paths['/v1/controls/state']['get']['responses'][200]['content']['application/json'];
export type ControlKind = ControlState['kind'];
export type ControlTarget = {kind: ControlKind; id: string | null};
export async function getControlState(token: ReviewerCredential, kind: ControlKind, id: string | null, signal: AbortSignal): Promise<ControlState> {
  const query=new URLSearchParams({kind});if(id!==null)query.set('id',id);
  return (await call('/v1/controls/state?'+query,token,{signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}
export async function setDispatchControl(token: ReviewerCredential, state: ControlState, paused: boolean, signal: AbortSignal): Promise<ControlState> {
  const scope=state.kind==='tenant'?{tenant:true}:state.kind==='connection'?{connection_id:state.target_id}:{workload_id:state.target_id};
  return (await call(paused?'/v1/controls/pause':'/v1/controls/resume',token,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({...scope,expected_revision:state.revision}),signal:AbortSignal.any([signal,AbortSignal.timeout(15000)])})).json();
}

export type RecoveryPage = paths['/v1/operations/items']['get']['responses'][200]['content']['application/json'];
export type RecoveryKind = RecoveryPage['kind'];
export type RecoveryItem = RecoveryPage['items'][number];
export type ReconciliationState = paths['/v1/actions/{id}/reconcile']['get']['responses'][200]['content']['application/json'];
export async function getRecoveryItems(token: ReviewerCredential, connectionId: string, kind: RecoveryKind, after: string | null, signal: AbortSignal): Promise<RecoveryPage> {
  const query = new URLSearchParams({ connection_id: connectionId, kind, limit: '50' });
  if (after !== null) query.set('after', after);
  return (await call(`/v1/operations/items?${query}`, token, { signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) })).json();
}
export async function getReconciliationState(token: ReviewerCredential, actionId: string, signal: AbortSignal): Promise<ReconciliationState> {
  return (await call(`/v1/actions/${encodeURIComponent(actionId)}/reconcile`, token, { signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) })).json();
}
export async function requestReconciliation(token: ReviewerCredential, actionId: string, signal: AbortSignal): Promise<void> {
  await call(`/v1/actions/${encodeURIComponent(actionId)}/reconcile`, token, { method: 'POST', signal: AbortSignal.any([signal, AbortSignal.timeout(15000)]) });
}
