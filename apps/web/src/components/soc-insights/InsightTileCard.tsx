/**
 * Single KPI tile on the SOC Insights dashboard (T3.1).
 *
 * Presentational component taking the typed payload from the aggregator
 * endpoint and rendering value + delta + sparkline. Features restrained
 * domain-specific icons, subtle accent styling, and graceful "awaiting data"
 * indicators when sample_count is 0 without awkward line breaks.
 */
'use client';

import type { ReactNode } from 'react';
import {
  Clock,
  ShieldCheck,
  Filter,
  Bell,
  FolderKanban,
  DollarSign,
  Zap,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
} from 'lucide-react';

import type { InsightTile } from '@/lib/api';

interface InsightTileCardProps {
  tile: InsightTile;
  sparkline: ReactNode;
  isSelected?: boolean;
  onSelect?: () => void;
}

interface TileMeta {
  icon: typeof Clock;
  accent: {
    text: string;
    bg: string;
    border: string;
    sparklineColor: string;
  };
  subtitle: string;
}

const TILE_META: Record<string, TileMeta> = {
  mtta: {
    icon: Clock,
    accent: {
      text: 'text-amber-400',
      bg: 'bg-amber-500/10',
      border: 'border-amber-500/20',
      sparklineColor: '#f59e0b',
    },
    subtitle: 'Target < 15m',
  },
  mttr: {
    icon: ShieldCheck,
    accent: {
      text: 'text-blue-400',
      bg: 'bg-blue-500/10',
      border: 'border-blue-500/20',
      sparklineColor: '#3b82f6',
    },
    subtitle: 'Target < 4h',
  },
  fp_rate: {
    icon: Filter,
    accent: {
      text: 'text-purple-400',
      bg: 'bg-purple-500/10',
      border: 'border-purple-500/20',
      sparklineColor: '#a855f7',
    },
    subtitle: 'Suppression efficiency',
  },
  alerts_per_day: {
    icon: Bell,
    accent: {
      text: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
      border: 'border-cyan-500/20',
      sparklineColor: '#06b6d4',
    },
    subtitle: 'Ingest volume',
  },
  cases_per_day: {
    icon: FolderKanban,
    accent: {
      text: 'text-rose-400',
      bg: 'bg-rose-500/10',
      border: 'border-rose-500/20',
      sparklineColor: '#f43f5e',
    },
    subtitle: 'Escalated incidents',
  },
  agent_cost_per_investigation: {
    icon: DollarSign,
    accent: {
      text: 'text-emerald-400',
      bg: 'bg-emerald-500/10',
      border: 'border-emerald-500/20',
      sparklineColor: '#10b981',
    },
    subtitle: 'LLM triage inference',
  },
  analyst_hours_saved: {
    icon: Zap,
    accent: {
      text: 'text-sky-400',
      bg: 'bg-sky-500/10',
      border: 'border-sky-500/20',
      sparklineColor: '#0ea5e9',
    },
    subtitle: 'Autonomous velocity',
  },
};

const DEFAULT_META: TileMeta = {
  icon: Clock,
  accent: {
    text: 'text-zinc-400',
    bg: 'bg-zinc-500/10',
    border: 'border-zinc-500/20',
    sparklineColor: '#71717a',
  },
  subtitle: 'Metric',
};

export function InsightTileCard({
  tile,
  sparkline,
  isSelected = false,
  onSelect,
}: InsightTileCardProps) {
  const meta = TILE_META[tile.key] || DEFAULT_META;
  const Icon = meta.icon;
  const direction = deltaDirection(tile);
  const deltaLabel = formatDelta(tile.delta_pct);
  const isMeasured = tile.sample_count !== 0;

  const deltaTitle =
    tile.delta_pct === null
      ? 'No data for the previous window — delta undefined.'
      : `Compared to the previous window: ${deltaLabel}.`;

  const accessibleValue = isMeasured ? formatValue(tile) : 'not measured';

  return (
    <div
      onClick={onSelect}
      className={`group relative flex flex-col justify-between rounded-xl border p-4 transition-all duration-200 ${
        isSelected
          ? 'border-primary/60 bg-card/90 shadow-lg shadow-primary/5 ring-1 ring-primary/40'
          : 'border-border/80 bg-card/60 hover:border-border hover:bg-card/90'
      } ${onSelect ? 'cursor-pointer' : ''}`}
      aria-label={`${tile.label}: ${accessibleValue}, ${deltaTitle}`}
    >
      {/* Top row: Icon + Label on left, Delta pill on right */}
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${meta.accent.bg} ${meta.accent.border}`}
          >
            <Icon className={`h-3.5 w-3.5 ${meta.accent.text}`} />
          </div>
          <span className="truncate text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            {tile.label}
          </span>
        </div>

        <div>
          {tile.delta_pct === null ? (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-muted/50 px-2 py-0.5 text-[11px] font-medium text-muted-foreground/80"
              title={deltaTitle}
            >
              <Minus className="h-2.5 w-2.5 opacity-60" />
              <span>—</span>
            </span>
          ) : direction === 'up' ? (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-emerald-500/10 px-2 py-0.5 text-xs font-medium text-emerald-600 dark:text-emerald-400"
              title={deltaTitle}
            >
              <ArrowUpRight className="h-3 w-3" />
              <span>{deltaLabel}</span>
            </span>
          ) : direction === 'down' ? (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-rose-500/10 px-2 py-0.5 text-xs font-medium text-rose-600 dark:text-rose-400"
              title={deltaTitle}
            >
              <ArrowDownRight className="h-3 w-3" />
              <span>{deltaLabel}</span>
            </span>
          ) : (
            <span
              className="inline-flex items-center gap-0.5 rounded-full bg-muted/50 px-2 py-0.5 text-xs font-medium text-muted-foreground"
              title={deltaTitle}
            >
              <span>{deltaLabel}</span>
            </span>
          )}
        </div>
      </div>

      {/* Middle: Prominent Value / Empty State */}
      <div className="my-3 flex items-baseline justify-between gap-2">
        {isMeasured ? (
          <div className="flex items-baseline gap-1.5">
            <span className="text-2xl font-bold tracking-tight text-foreground tabular-nums sm:text-3xl">
              {formatValue(tile)}
            </span>
          </div>
        ) : (
          <div className="flex items-center gap-2">
            <span className="text-2xl font-semibold tracking-tight text-muted-foreground/50 tabular-nums sm:text-3xl">
              —
            </span>
            <span className="rounded-md bg-muted/60 px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
              Awaiting data
            </span>
          </div>
        )}
      </div>

      {/* Bottom row: Subtitle / Samples left, Sparkline right */}
      <div className="flex items-end justify-between gap-2 border-t border-border/40 pt-2.5">
        <div className="min-w-0">
          <p className="truncate text-[11px] text-muted-foreground/70">
            {isMeasured && tile.sample_count !== undefined
              ? `${tile.sample_count} sample${tile.sample_count === 1 ? '' : 's'}`
              : meta.subtitle}
          </p>
        </div>
        <div className="shrink-0">{sparkline}</div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatValue(tile: InsightTile): string {
  if (tile.sample_count === 0) return 'not measured';

  switch (tile.unit) {
    case 'hours':
      return `${tile.value.toFixed(1)}h`;
    case 'hours_saved':
      return `${Math.round(tile.value)}h`;
    case 'pct':
      return `${(tile.value * 100).toFixed(1)}%`;
    case 'usd':
      return tile.value < 1
        ? `$${tile.value.toFixed(3)}`
        : `$${tile.value.toFixed(2)}`;
    case 'count':
    default:
      return Number.isInteger(tile.value)
        ? tile.value.toString()
        : tile.value.toFixed(1);
  }
}

function formatDelta(delta: number | null): string {
  if (delta === null) return '—';
  const sign = delta > 0 ? '+' : '';
  return `${sign}${delta.toFixed(1)}%`;
}

/**
 * Classify the delta into a UX direction.
 * For "more = worse" metrics (MTTA, MTTR, FP rate, cost, alerts/day),
 * an increase is marked as 'down' (red), and a drop is 'up' (green).
 * For 'analyst_hours_saved', higher is better.
 */
function deltaDirection(tile: InsightTile): 'up' | 'down' | 'flat' {
  if (tile.delta_pct === null || tile.delta_pct === 0) return 'flat';
  const positive = tile.delta_pct > 0;
  const goodWhenUp = tile.key === 'analyst_hours_saved';
  return positive === goodWhenUp ? 'up' : 'down';
}
