'use client';

import useSWR from 'swr';
import { apiRequest } from '@/lib/api';
import { useTenantId } from '@/components/layout/TenantProvider';

type ReceiptStatus = {
  configured: boolean;
  events_received?: number;
  last_received_at?: string | null;
  source_epochs?: number;
};

export function WindowsSecurityStatus() {
  const tenantId = useTenantId();
  const { data, error, isLoading } = useSWR(
    tenantId ? ['windows-security:status', tenantId] : null,
    () => apiRequest<ReceiptStatus>('/windows-security/status'),
    { refreshInterval: 30_000, revalidateOnFocus: false },
  );
  return (
    <section aria-label="Windows Security staging" className="rounded-lg border border-border p-4 space-y-2">
      <h2 className="font-semibold">Windows Security staging</h2>
      {error ? <p role="status">Receipt status unavailable. Event volume is unknown.</p>
        : isLoading || !tenantId ? <p>Loading receipt status…</p>
        : !data?.configured ? <p>Staging collection is not configured for this tenant.</p>
        : <>
          <p>{data.events_received} metadata records durably received; {data.source_epochs} source epochs.</p>
          <p>Last receipt: {data.last_received_at ? new Date(data.last_received_at).toLocaleString() : 'No events received'}</p>
          <p className="text-sm text-muted-foreground">Isolated staging receipts. Detection and triage are not connected.</p>
        </>}
    </section>
  );
}
