import { render, screen } from '@testing-library/react';
import { SWRConfig } from 'swr';
import { beforeEach, expect, it, vi } from 'vitest';
import { apiRequest } from '@/lib/api';
import { WindowsSecurityStatus } from './WindowsSecurityStatus';

vi.mock('@/lib/api', () => ({ apiRequest: vi.fn() }));
const tenant = vi.hoisted(() => ({ id: 'tenant-one' as string | null }));
vi.mock('@/components/layout/TenantProvider', () => ({ useTenantId: () => tenant.id }));

beforeEach(() => {
  vi.mocked(apiRequest).mockReset();
  tenant.id = 'tenant-one';
});

function mount() {
  return render(
    <SWRConfig value={{ provider: () => new Map(), shouldRetryOnError: false }}>
      <WindowsSecurityStatus />
    </SWRConfig>,
  );
}

it('shows loading without a fabricated count', () => {
  vi.mocked(apiRequest).mockReturnValue(new Promise(() => {}));
  mount();
  expect(screen.getByText(/Loading receipt status/)).toBeInTheDocument();
  expect(screen.queryByText(/0 metadata records/)).not.toBeInTheDocument();
});

it('shows an honest failure instead of stale receipt counts', async () => {
  vi.mocked(apiRequest).mockRejectedValue(new Error('offline'));
  mount();
  expect(await screen.findByRole('status')).toHaveTextContent('Event volume is unknown');
  expect(screen.queryByText(/durably received/)).not.toBeInTheDocument();
});

it('shows tenant configuration absence', async () => {
  vi.mocked(apiRequest).mockResolvedValue({ configured: false });
  mount();
  expect(await screen.findByText(/not configured for this tenant/)).toBeInTheDocument();
  expect(apiRequest).toHaveBeenCalledWith('/windows-security/status');
});

it('shows actual receipt counts and an explicit empty timestamp', async () => {
  vi.mocked(apiRequest).mockResolvedValue({ configured: true, events_received: 0, source_epochs: 0, last_received_at: null });
  mount();
  expect(await screen.findByText(/0 metadata records durably received/)).toBeInTheDocument();
  expect(screen.getByText(/No events received/)).toBeInTheDocument();
  expect(screen.getByText(/Detection and triage are not connected/)).toBeInTheDocument();
});

it('does not query until tenant identity is resolved', () => {
  tenant.id = null;
  mount();
  expect(apiRequest).not.toHaveBeenCalled();
  expect(screen.getByText(/Loading receipt status/)).toBeInTheDocument();
});

it('renders a synthetic twelve-receipt response without claiming detections', async () => {
  vi.mocked(apiRequest).mockResolvedValue({
    configured: true, events_received: 12, source_epochs: 1,
    last_received_at: '2026-11-13T17:25:18+00:00',
  });
  mount();
  expect(await screen.findByText(/12 metadata records durably received; 1 source epochs/)).toBeInTheDocument();
  expect(screen.getByText(/Last receipt:/)).not.toHaveTextContent('No events received');
  expect(screen.getByText(/Detection and triage are not connected/)).toBeInTheDocument();
});

it('does not reuse receipt counts when the active tenant changes', async () => {
  vi.mocked(apiRequest).mockResolvedValue({ configured: true, events_received: 7, source_epochs: 1, last_received_at: null });
  const view = mount();
  expect(await screen.findByText(/7 metadata records/)).toBeInTheDocument();
  tenant.id = 'tenant-two';
  vi.mocked(apiRequest).mockReturnValue(new Promise(() => {}));
  // Keep the same SWR provider/cache while changing the tenant key.
  view.rerender(<WindowsSecurityStatus />);
  expect(screen.queryByText(/7 metadata records/)).not.toBeInTheDocument();
});
