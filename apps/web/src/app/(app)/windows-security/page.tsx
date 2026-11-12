'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, windowsSecurityApi } from '@/lib/api';

type EventRow = {
  event_time: string;
  severity: string;
  hostname: string;
  event_code: number;
  provider: string;
  record_id: number;
};

const EXPECTED_COLUMNS = ['event_time', 'severity', 'hostname', 'event_code', 'provider', 'record_id'];

function parseEvents(result: Awaited<ReturnType<typeof windowsSecurityApi.events>>): EventRow[] {
  if (!EXPECTED_COLUMNS.every((column) => result.columns.includes(column))) {
    throw new Error('Windows Security API returned unexpected columns.');
  }
  return result.rows.map((row) => {
    const get = (name: string) => row[result.columns.indexOf(name)];
    return {
      event_time: String(get('event_time') ?? ''),
      severity: String(get('severity') ?? ''),
      hostname: String(get('hostname') ?? ''),
      event_code: Number(get('event_code')),
      provider: String(get('provider') ?? ''),
      record_id: Number(get('record_id')),
    };
  });
}

function formatUtcTimestamp(value: string): string {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return '—';
  return new Date(timestamp).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

export default function WindowsSecurityPage() {
  const [events, setEvents] = useState<EventRow[]>([]);
  const refreshInFlight = useRef(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  const refresh = useCallback(async (silent = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    if (!silent) setLoading(true);
    setError(null);
    try {
      const response = await windowsSecurityApi.events();
      setEvents(parseEvents(response));
      setLastUpdated(new Date().toLocaleTimeString());
    } catch (err) {
      const message = err instanceof ApiError && err.status === 403
        ? 'Your account needs the lake:query permission to view Windows Security events.'
        : err instanceof ApiError && err.status === 401
          ? 'Please sign in to view Windows Security events.'
          : 'Could not load Windows Security events. Try refreshing.';
      setError(message);
    } finally {
      refreshInFlight.current = false;
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') void refresh(true);
    }, 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  return (
    <main className="space-y-6 p-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold text-fg-primary">Windows Security Events</h1>
          <p className="mt-1 text-sm text-fg-secondary">
            Tenant-scoped Windows Security metadata. Events are not automatically alerts.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span role="status" className="text-xs text-fg-secondary">
            Auto-refresh every 5 seconds{lastUpdated ? ` · Last checked ${lastUpdated}` : ''}
          </span>
        <button type="button" onClick={() => void refresh()} disabled={loading}
          className="rounded-lg border border-border-default px-4 py-2 text-sm text-fg-primary disabled:opacity-50">
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        </div>
      </div>

      {error ? (
        <div role="alert" className="rounded-lg border border-red-500/40 p-4 text-sm text-fg-primary">
          {error}
        </div>
      ) : loading ? (
        <p role="status" className="text-sm text-fg-secondary">Loading Windows Security events…</p>
      ) : events.length === 0 ? (
        <div className="rounded-lg border border-border-default p-8 text-center text-fg-secondary">
          No Windows Security events found for the active tenant.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border-default">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-border-default text-fg-secondary">
              <tr>
                <th scope="col" className="p-3">Time (UTC)</th>
                <th scope="col" className="p-3">Event ID</th>
                <th scope="col" className="p-3">Hostname</th>
                <th scope="col" className="p-3">Severity</th>
                <th scope="col" className="p-3">Provider</th>
                <th scope="col" className="p-3">Record ID</th>
              </tr>
            </thead>
            <tbody>
              {events.map((event, index) => (
                <tr key={`${event.hostname}-${event.record_id}-${index}`} className="border-b border-border-default last:border-0">
                  <td className="whitespace-nowrap p-3">{formatUtcTimestamp(event.event_time)}</td>
                  <td className="p-3">{event.event_code}</td>
                  <td className="p-3">{event.hostname}</td>
                  <td className="p-3 capitalize">{event.severity}</td>
                  <td className="p-3">{event.provider}</td>
                  <td className="p-3">{event.record_id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </main>
  );
}
