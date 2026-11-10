import type { Approval } from './api';

export interface ApprovalFilters {
  connection: string;
  currency: string;
  minimum: string;
  maximum: string;
  ageMinutes: string;
}
export const EMPTY_APPROVAL_FILTERS: ApprovalFilters = { connection: '', currency: '', minimum: '', maximum: '', ageMinutes: '' };

export function validateApprovalFilters(filters: ApprovalFilters): string {
  for (const [label, value] of [['Minimum amount', filters.minimum], ['Maximum amount', filters.maximum], ['Minimum age', filters.ageMinutes]]) {
    if (value !== '' && (!/^\d+$/.test(value) || !Number.isSafeInteger(Number(value)))) {
      return `${label} must be a nonnegative safe whole integer.`;
    }
  }
  if ((filters.minimum !== '' || filters.maximum !== '') && !filters.currency) return 'Choose a currency before filtering amounts.';
  if (filters.minimum !== '' && filters.maximum !== '' && Number(filters.minimum) > Number(filters.maximum)) return 'Minimum amount must not exceed maximum amount.';
  return '';
}

export function recordedAgeMinutes(queuedAt: string | null, now: number): number | null {
  if (queuedAt === null) return null;
  const timestamp = Date.parse(queuedAt);
  if (!Number.isFinite(timestamp) || timestamp > now) return null;
  return Math.floor((now - timestamp) / 60000);
}

export function filterApprovals(items: Approval[], filters: ApprovalFilters, now: number): Approval[] {
  if (validateApprovalFilters(filters)) return [];
  return items.filter((item) => {
    const { currency, amount_minor } = item.request.parameters;
    const age = recordedAgeMinutes(item.queued_at, now);
    return (!filters.connection || filters.connection === item.connection_id)
      && (!filters.currency || filters.currency === currency)
      && (filters.minimum === '' || amount_minor >= Number(filters.minimum))
      && (filters.maximum === '' || amount_minor <= Number(filters.maximum))
      && (filters.ageMinutes === '' || (age !== null && age >= Number(filters.ageMinutes)));
  });
}
