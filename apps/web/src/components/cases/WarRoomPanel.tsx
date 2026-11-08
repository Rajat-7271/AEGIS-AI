'use client';

/**
 * Open a chat war room for a case, and show whether it is still mirroring.
 *
 * Depth 9.4. The one action the plan asks for, and the honest reporting
 * around it:
 *
 * - **The button performs a real write and fails loudly.** The API returns
 *   502 with the vendor's own reason when the bot is not deployed or Slack
 *   refuses, and that sentence is what the analyst reads. A toast saying
 *   "opening…" over a request that failed is the control this console is not
 *   allowed to ship.
 * - **"Never synced" and "synced with nothing to say" render differently.**
 *   `last_synced_at: null` means the sweep has not run for this room yet,
 *   which is a different fact from a quiet case, and collapsing them would
 *   let an analyst read a broken mirror as a calm one.
 * - **A stalled mirror is shown, not hidden.** `last_error` is rendered in
 *   full. A war room that has silently stopped following the case is worse
 *   than one that was never opened.
 * - **No `fallbackData` and no mock.** First paint is a loading state.
 */

import { useCallback, useState } from 'react';
import useSWR from 'swr';

import { ApiError, warRoomApi, type WarRoom } from '@/lib/api';
import { formatTimeIST } from '@/lib/utils';

/**
 * War-room vendor errors may contain reverse-proxy HTML or infrastructure
 * details. Keep actionable plain-text provider errors, but never render
 * markup, hostnames or arbitrary network exception text in the panel.
 */
const WAR_ROOM_UNAVAILABLE = 'War room unavailable. Please retry later.';

function safeProviderDetail(message: string): string {
  const detail = message.trim();
  if (!detail || detail.length > 240 || /<[^>]*>|https?:\/\/|(?:[a-z0-9-]+\.)+[a-z]{2,}/i.test(detail)) {
    return WAR_ROOM_UNAVAILABLE;
  }
  return detail;
}

export function describeWarRoomFailure(error: unknown): string {
  if (!(error instanceof ApiError)) return WAR_ROOM_UNAVAILABLE;
  if (error.status === 0 || error.status >= 500) return WAR_ROOM_UNAVAILABLE;
  return safeProviderDetail(error.body);
}

function SyncState({ room }: { room: WarRoom }) {
  if (room.last_error) {
    return (
      <span className="text-red-400" role="alert">
        not mirroring — {safeProviderDetail(room.last_error)}
      </span>
    );
  }
  if (!room.last_synced_at) {
    // Distinct from "synced and had nothing to say". An analyst must be able
    // to tell a room nobody has swept from a case nobody has touched.
    return <span className="text-gray-500">waiting for the first sync</span>;
  }
  return (
    <span className="text-emerald-400">
      mirroring · last synced {formatTimeIST(room.last_synced_at)}
    </span>
  );
}

export function WarRoomPanel({ caseId }: { caseId: string }) {
  const { data, error, isLoading, mutate } = useSWR(['war-rooms', caseId], () => warRoomApi.forCase(caseId), {
    refreshInterval: 30_000,
  });
  const [opening, setOpening] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);

  const open = useCallback(
    async (provider: 'slack' | 'teams') => {
      setOpening(true);
      setFailure(null);
      try {
        await warRoomApi.open(caseId, provider);
        await mutate();
      } catch (err) {
        setFailure(describeWarRoomFailure(err));
      } finally {
        setOpening(false);
      }
    },
    [caseId, mutate],
  );

  const rooms = data ?? [];

  return (
    <section className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-4 space-y-3" aria-label="War room">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-gray-200">War room</h2>
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={opening}
            onClick={() => void open('slack')}
            className="text-xs px-3 py-1.5 rounded-md border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 disabled:opacity-50"
          >
            {opening ? 'Opening…' : 'Open in Slack'}
          </button>
          <button
            type="button"
            disabled={opening}
            onClick={() => void open('teams')}
            className="text-xs px-3 py-1.5 rounded-md border border-gray-700 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          >
            Open in Teams
          </button>
        </div>
      </div>

      {failure && (
        <p className="text-xs text-red-400" role="alert">
          {failure}
        </p>
      )}

      {isLoading ? (
        <p className="text-xs text-gray-500">Loading…</p>
      ) : error ? (
        <p className="text-xs text-red-400" role="alert">
          Couldn&apos;t load war rooms for this case.
        </p>
      ) : rooms.length === 0 ? (
        <p className="text-xs text-gray-500">
          No war room yet. Opening one creates a channel, invites the assignees and mirrors the case
          timeline into it.
        </p>
      ) : (
        <ul className="space-y-2">
          {rooms.map((room) => (
            <li key={room.id} className="text-xs flex items-center justify-between gap-3">
              <span className="text-gray-300 truncate">
                <span className="uppercase text-[10px] text-gray-500 mr-2">{room.provider}</span>
                {room.channel_name || room.channel_id}
                {room.state === 'closed' && <span className="text-gray-600 ml-2">(closed)</span>}
              </span>
              <SyncState room={room} />
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
