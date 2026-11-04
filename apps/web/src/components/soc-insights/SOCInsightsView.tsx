/**
 * SOC Insights dashboard view (T3.1).
 *
 * Owns data-fetching, layout, and operational analysis for AEGIS AI.
 * Displays 7 core KPI tiles, an interactive 24-bucket operational trend
 * inspection panel, and autonomous efficiency & SLA benchmark telemetry.
 */
'use client';

import { useEffect, useId, useMemo, useState } from 'react';
import { useTimeWindow } from '@/components/layout/TimeWindowProvider';
import useSWR from 'swr';
import {
  Activity,
  ArrowUpRight,
  BarChart3,
  CheckCircle2,
  Clock,
  Gauge,
  HelpCircle,
  Radio,
  RefreshCw,
  ShieldCheck,
  TrendingUp,
  Zap,
} from 'lucide-react';

import { useRealtimeChannel } from '@/lib/realtime';
import {
  type InsightTile,
  type InsightsWindow,
  type SOCInsightsResponse,
  insightsApi,
} from '@/lib/api';

import { InsightTileCard } from './InsightTileCard';
import { Sparkline } from './Sparkline';
import { formatTimeIST } from '@/lib/utils';

const WINDOW_OPTIONS: InsightsWindow[] = ['24h', '7d', '30d'];

interface RealtimePoke {
  type: string;
  reason?: string;
  timestamp?: string;
}

export function SOCInsightsView() {
  const { window: globalWindow, setWindow: setGlobalWindow } = useTimeWindow();
  const clamped = globalWindow === '1h';
  const window: InsightsWindow = clamped ? '24h' : globalWindow;
  const setWindow = setGlobalWindow;

  const [selectedKey, setSelectedKey] = useState<string>('alerts_per_day');

  const { data, error, isLoading, mutate, isValidating } = useSWR<SOCInsightsResponse>(
    ['insights:soc', window],
    () => insightsApi.getSOC(window),
    {
      revalidateOnFocus: true,
      revalidateIfStale: true,
      dedupingInterval: 0,
    },
  );

  const { last } = useRealtimeChannel<RealtimePoke>('insights');

  useEffect(() => {
    if (last?.type === 'insights_updated' || last?.type === 'case.updated') {
      mutate(undefined, { revalidate: true });
    }
  }, [last, mutate]);

  const selectedTile = useMemo(() => {
    if (!data?.tiles) return null;
    return data.tiles.find((t) => t.key === selectedKey) || data.tiles[0];
  }, [data?.tiles, selectedKey]);

  return (
    <div className="space-y-6 p-6">
      <Header
        window={window}
        clamped={clamped}
        onWindowChange={setWindow}
        generatedAt={data?.generated_at}
        manualMinutes={data?.manual_investigation_minutes}
        isValidating={isValidating}
        onRefresh={() => mutate()}
      />

      {error ? (
        <ErrorState
          message={error instanceof Error ? error.message : String(error)}
          onRetry={() => mutate()}
        />
      ) : isLoading || !data ? (
        <LoadingSkeleton />
      ) : (
        <>
          {/* 7 KPI Tiles Grid */}
          <TileGrid
            tiles={data.tiles}
            selectedKey={selectedTile?.key}
            onSelectTile={(key) => setSelectedKey(key)}
          />

          {/* Interactive Operational Trend Analysis */}
          {selectedTile && (
            <TrendAnalysisPanel
              tile={selectedTile}
              window={window}
              allTiles={data.tiles}
              onSelectMetric={(key) => setSelectedKey(key)}
            />
          )}

          {/* Autonomous Performance & SLA Analysis Grid */}
          <OperationalAnalysisGrid
            tiles={data.tiles}
            manualMinutes={data.manual_investigation_minutes}
          />
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Header Component
// ---------------------------------------------------------------------------

interface HeaderProps {
  window: InsightsWindow;
  clamped: boolean;
  onWindowChange: (w: InsightsWindow) => void;
  generatedAt: string | undefined;
  manualMinutes: number | undefined;
  isValidating: boolean;
  onRefresh: () => void;
}

function Header({
  window,
  clamped,
  onWindowChange,
  generatedAt,
  manualMinutes,
  isValidating,
  onRefresh,
}: HeaderProps) {
  const stamp = useMemo(() => {
    if (!generatedAt) return null;
    try {
      return formatTimeIST(generatedAt);
    } catch {
      return generatedAt;
    }
  }, [generatedAt]);

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-border/70 bg-card/40 p-5 backdrop-blur-sm lg:flex-row lg:items-center lg:justify-between">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            SOC Insights
          </h1>
          <div className="flex items-center gap-1.5 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-2.5 py-0.5 text-[11px] font-medium text-emerald-600 dark:text-emerald-400">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
            </span>
            Live Telemetry
          </div>
        </div>

        <p className="mt-1.5 max-w-2xl text-xs text-muted-foreground sm:text-sm">
          Real-time operational metrics, SLA compliance, and autonomous triage velocity
          for AEGIS AI. Deltas compare against the previous window.
          Calculated at {manualMinutes ?? 45}m manual effort saved per closed case.
        </p>

        {clamped && (
          <p className="mt-1.5 text-xs text-amber-500">
            These tiles have no 1-hour window, so they are showing 24 hours.
          </p>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        {stamp && (
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground" aria-live="polite">
            <Clock className="h-3.5 w-3.5 text-muted-foreground/70" />
            <span>Updated {stamp}</span>
          </div>
        )}

        <button
          type="button"
          onClick={onRefresh}
          disabled={isValidating}
          title="Refresh metrics"
          className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border bg-card/80 text-muted-foreground transition hover:border-border hover:text-foreground disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isValidating ? 'animate-spin' : ''}`} />
        </button>

        <WindowSelector value={window} onChange={onWindowChange} />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Window Selector
// ---------------------------------------------------------------------------

interface WindowSelectorProps {
  value: InsightsWindow;
  onChange: (w: InsightsWindow) => void;
}

function WindowSelector({ value, onChange }: WindowSelectorProps) {
  return (
    <div
      role="radiogroup"
      aria-label="Window"
      className="inline-flex rounded-lg border border-border bg-card/80 p-0.5 text-xs shadow-sm"
    >
      {WINDOW_OPTIONS.map((option) => {
        const active = option === value;
        return (
          <button
            key={option}
            type="button"
            role="radio"
            aria-checked={active}
            onClick={() => onChange(option)}
            className={
              active
                ? 'rounded-md bg-primary px-3 py-1 font-semibold text-primary-foreground shadow-sm transition'
                : 'rounded-md px-3 py-1 font-medium text-muted-foreground transition hover:text-foreground'
            }
          >
            {option}
          </button>
        );
      })}
    </div>
  );
}

// ---------------------------------------------------------------------------
// 7 Tile Grid Container
// ---------------------------------------------------------------------------

interface TileGridProps {
  tiles: InsightTile[];
  selectedKey?: string;
  onSelectTile?: (key: string) => void;
}

function TileGrid({ tiles, selectedKey, onSelectTile }: TileGridProps) {
  return (
    <div
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
      data-testid="soc-insights-tiles"
    >
      {tiles.map((tile) => (
        <InsightTileCard
          key={tile.key}
          tile={tile}
          isSelected={tile.key === selectedKey}
          onSelect={onSelectTile ? () => onSelectTile(tile.key) : undefined}
          sparkline={<Sparkline points={tile.sparkline.points} />}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Trend Analysis Panel (Expanded 24-Bucket Visualization)
// ---------------------------------------------------------------------------

const METRIC_TABS: Record<string, string> = {
  alerts_per_day: 'Alert Ingest',
  cases_per_day: 'Escalated Cases',
  mtta: 'MTTA Velocity',
  mttr: 'MTTR Resolution',
  fp_rate: 'False Positives',
  agent_cost_per_investigation: 'Triage Cost',
  analyst_hours_saved: 'Hours Saved',
};

interface TrendAnalysisPanelProps {
  tile: InsightTile;
  window: InsightsWindow;
  allTiles: InsightTile[];
  onSelectMetric: (key: string) => void;
}

function TrendAnalysisPanel({
  tile,
  window,
  allTiles,
  onSelectMetric,
}: TrendAnalysisPanelProps) {
  const points = tile.sparkline.points || [];
  const hasData = points.some((p) => p > 0);
  const chartGradId = useId();

  const maxVal = points.length > 0 ? Math.max(...points) : 0;
  const minVal = points.length > 0 ? Math.min(...points) : 0;
  const avgVal =
    points.length > 0
      ? points.reduce((acc, p) => acc + p, 0) / points.length
      : 0;
  const latestVal = points.length > 0 ? points[points.length - 1] : 0;

  // Labeled time intervals based on active window
  const timeLabels = useMemo(() => {
    switch (window) {
      case '30d':
        return ['-30d', '-22d', '-15d', '-7d', 'Now'];
      case '7d':
        return ['-7d', '-5d', '-3d', '-1d', 'Now'];
      case '24h':
      default:
        return ['-24h', '-18h', '-12h', '-6h', 'Now'];
    }
  }, [window]);

  // SVG Area path calculation for the 400x120 SVG chart
  const { pathD, areaD } = useMemo(() => {
    if (!points || points.length < 2) {
      return { pathD: 'M 0 60 L 400 60', areaD: 'M 0 60 L 400 60 L 400 120 L 0 120 Z' };
    }
    const range = maxVal - minVal || 1;
    const stepX = 400 / (points.length - 1);
    const coords = points.map((val, idx) => {
      const x = idx * stepX;
      const y = 110 - ((val - minVal) / range) * 90;
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    });
    const pD = 'M ' + coords.join(' L ');
    const aD = `${pD} L 400 120 L 0 120 Z`;
    return { pathD: pD, areaD: aD };
  }, [points, maxVal, minVal]);

  return (
    <div className="rounded-xl border border-border/80 bg-card/60 p-5 shadow-sm backdrop-blur-sm">
      {/* Panel Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-border/50 pb-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            <h2 className="text-base font-semibold text-foreground">
              Trend Telemetry Analysis
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-muted-foreground">
            24-bucket operational timeline across the {window} inspection window.
          </p>
        </div>

        {/* Metric Selector Pills */}
        <div className="flex flex-wrap items-center gap-1.5">
          {allTiles.map((t) => {
            const active = t.key === tile.key;
            const tabLabel = METRIC_TABS[t.key] || `${t.label} Trend`;
            return (
              <button
                key={t.key}
                type="button"
                onClick={() => onSelectMetric(t.key)}
                className={`rounded-lg px-2.5 py-1 text-xs font-medium transition ${
                  active
                    ? 'bg-primary/15 text-primary ring-1 ring-primary/30 font-semibold'
                    : 'bg-muted/40 text-muted-foreground hover:bg-muted/70 hover:text-foreground'
                }`}
              >
                {tabLabel}
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Content Area */}
      <div className="mt-5 grid gap-6 lg:grid-cols-4">
        {/* Left: 24-bucket chart (span 3) */}
        <div className="lg:col-span-3">
          {hasData ? (
            <div className="relative rounded-lg border border-border/40 bg-card/40 p-4">
              {/* Y Axis Guide indicators */}
              <div className="flex justify-between text-[11px] font-mono text-muted-foreground/60 mb-2">
                <span>Peak: {formatMetricValue(maxVal, tile.unit)}</span>
                <span>Avg: {formatMetricValue(avgVal, tile.unit)}</span>
                <span>Baseline: {formatMetricValue(minVal, tile.unit)}</span>
              </div>

              {/* Responsive SVG Chart */}
              <svg
                viewBox="0 0 400 120"
                className="w-full h-36 overflow-visible"
                preserveAspectRatio="none"
              >
                <defs>
                  <linearGradient id={chartGradId} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.25" />
                    <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
                  </linearGradient>
                </defs>

                {/* Horizontal reference lines */}
                <line x1="0" y1="20" x2="400" y2="20" stroke="currentColor" strokeOpacity="0.07" strokeDasharray="3 3" />
                <line x1="0" y1="65" x2="400" y2="65" stroke="currentColor" strokeOpacity="0.07" strokeDasharray="3 3" />
                <line x1="0" y1="110" x2="400" y2="110" stroke="currentColor" strokeOpacity="0.12" />

                {/* Area fill */}
                <path d={areaD} fill={`url(#${chartGradId})`} />

                {/* Polyline curve */}
                <path
                  d={pathD}
                  fill="none"
                  stroke="#3b82f6"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              </svg>

              {/* Time X-Axis */}
              <div className="mt-3 flex justify-between border-t border-border/30 pt-2 text-[11px] font-medium text-muted-foreground/70">
                {timeLabels.map((lbl, idx) => (
                  <span key={idx}>{lbl}</span>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex h-44 flex-col items-center justify-center rounded-lg border border-dashed border-border/60 bg-muted/10 p-6 text-center">
              <BarChart3 className="h-8 w-8 text-muted-foreground/40 mb-2" />
              <p className="text-sm font-medium text-muted-foreground">
                No activity recorded for {tile.label} in this time window
              </p>
              <p className="mt-1 max-w-sm text-xs text-muted-foreground/70">
                Historical buckets will populate automatically as telemetry streams through the ingest pipeline.
              </p>
            </div>
          )}
        </div>

        {/* Right: Metric Summary Highlights */}
        <div className="flex flex-col justify-between gap-3 rounded-lg border border-border/40 bg-card/40 p-4">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              {tile.label} Summary
            </span>
            <div className="mt-3 space-y-3">
              <div>
                <p className="text-[11px] text-muted-foreground">Peak Bucket Volume</p>
                <p className="text-lg font-bold tabular-nums text-foreground">
                  {formatMetricValue(maxVal, tile.unit)}
                </p>
              </div>

              <div>
                <p className="text-[11px] text-muted-foreground">Window Average</p>
                <p className="text-lg font-bold tabular-nums text-foreground">
                  {formatMetricValue(avgVal, tile.unit)}
                </p>
              </div>

              <div>
                <p className="text-[11px] text-muted-foreground">Latest Value</p>
                <p className="text-lg font-bold tabular-nums text-foreground">
                  {formatMetricValue(latestVal, tile.unit)}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded border border-border/50 bg-muted/30 p-2.5 text-[11px] text-muted-foreground">
            <span className="font-semibold text-foreground">Sampling Rate:</span> 24 hourly buckets aggregated per window.
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Operational SLA & Autonomous Leverage Analysis Grid
// ---------------------------------------------------------------------------

interface OperationalAnalysisGridProps {
  tiles: InsightTile[];
  manualMinutes?: number;
}

function OperationalAnalysisGrid({
  tiles,
  manualMinutes = 45,
}: OperationalAnalysisGridProps) {
  const tileMap = useMemo(() => {
    const map = new Map<string, InsightTile>();
    for (const t of tiles) {
      map.set(t.key, t);
    }
    return map;
  }, [tiles]);

  const mtta = tileMap.get('mtta');
  const mttr = tileMap.get('mttr');
  const fpRate = tileMap.get('fp_rate');
  const alerts = tileMap.get('alerts_per_day');
  const cases = tileMap.get('cases_per_day');
  const hoursSaved = tileMap.get('analyst_hours_saved');
  const agentCost = tileMap.get('agent_cost_per_investigation');

  const mttaWithinSla = mtta && mtta.sample_count !== 0 && mtta.value <= 0.25; // 15 mins = 0.25h
  const mttrWithinSla = mttr && mttr.sample_count !== 0 && mttr.value <= 4.0; // 4 hours
  const fpRateTarget = fpRate && fpRate.sample_count !== 0 && fpRate.value <= 0.15; // 15%

  const escalationRatio =
    alerts && cases && alerts.value > 0
      ? ((cases.value / alerts.value) * 100).toFixed(1)
      : null;

  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* Card 1: SLA Compliance & Target Velocity */}
      <div className="rounded-xl border border-border/80 bg-card/60 p-5 shadow-sm backdrop-blur-sm">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-blue-500/20 bg-blue-500/10 text-blue-400">
            <ShieldCheck className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground">
              SLA Compliance & Target Velocity
            </h3>
            <p className="text-xs text-muted-foreground">
              SOC performance benchmarked against operational target thresholds.
            </p>
          </div>
        </div>

        <div className="mt-4 space-y-3">
          {/* MTTA Target */}
          <div className="flex items-center justify-between rounded-lg border border-border/40 bg-card/40 p-3">
            <div>
              <p className="text-xs font-medium text-foreground">MTTA SLA Target</p>
              <p className="text-[11px] text-muted-foreground">Target acknowledgment under 15 minutes</p>
            </div>
            <div className="text-right">
              <span
                className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${
                  mtta?.sample_count === 0
                    ? 'bg-muted text-muted-foreground'
                    : mttaWithinSla
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                      : 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
                }`}
              >
                {mtta?.sample_count === 0
                  ? 'Awaiting data'
                  : mttaWithinSla
                    ? 'Within SLA (<15m)'
                    : `${mtta?.value.toFixed(1)}h (Exceeds 15m)`}
              </span>
            </div>
          </div>

          {/* MTTR Target */}
          <div className="flex items-center justify-between rounded-lg border border-border/40 bg-card/40 p-3">
            <div>
              <p className="text-xs font-medium text-foreground">MTTR SLA Target</p>
              <p className="text-[11px] text-muted-foreground">Target resolution under 4 hours</p>
            </div>
            <div className="text-right">
              <span
                className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${
                  mttr?.sample_count === 0
                    ? 'bg-muted text-muted-foreground'
                    : mttrWithinSla
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                      : 'bg-rose-500/15 text-rose-600 dark:text-rose-400'
                }`}
              >
                {mttr?.sample_count === 0
                  ? 'Awaiting data'
                  : mttrWithinSla
                    ? 'Within SLA (<4h)'
                    : `${mttr?.value.toFixed(1)}h (Exceeds 4h)`}
              </span>
            </div>
          </div>

          {/* Suppression Ratio */}
          <div className="flex items-center justify-between rounded-lg border border-border/40 bg-card/40 p-3">
            <div>
              <p className="text-xs font-medium text-foreground">Noise Suppression Target</p>
              <p className="text-[11px] text-muted-foreground">False-positive suppression rate benchmark</p>
            </div>
            <div className="text-right">
              <span
                className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-semibold ${
                  fpRate?.sample_count === 0
                    ? 'bg-muted text-muted-foreground'
                    : fpRateTarget
                      ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400'
                      : 'bg-amber-500/15 text-amber-600 dark:text-amber-400'
                }`}
              >
                {!fpRate || fpRate.sample_count === 0
                  ? 'Awaiting data'
                  : fpRateTarget
                    ? `${(fpRate.value * 100).toFixed(1)}% (Clean)`
                    : `${(fpRate.value * 100).toFixed(1)}%`}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Card 2: Autonomous Efficiency & Capacity Preservation */}
      <div className="rounded-xl border border-border/80 bg-card/60 p-5 shadow-sm backdrop-blur-sm">
        <div className="flex items-center gap-2.5">
          <div className="flex h-7 w-7 items-center justify-center rounded-lg border border-sky-500/20 bg-sky-500/10 text-sky-400">
            <Zap className="h-4 w-4" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-foreground">
              Autonomous Efficiency & Capacity
            </h3>
            <p className="text-xs text-muted-foreground">
              Analyst work hours and budget saved via automated triage.
            </p>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-3">
          {/* Capacity Saved */}
          <div className="rounded-lg border border-border/40 bg-card/40 p-3">
            <p className="text-[11px] text-muted-foreground">Hours Saved</p>
            <p className="mt-1 text-2xl font-bold tabular-nums text-sky-500 dark:text-sky-400">
              {hoursSaved?.sample_count !== 0 && hoursSaved?.value !== undefined
                ? `${Math.round(hoursSaved.value)}h`
                : '—'}
            </p>
            <p className="mt-1 text-[10px] text-muted-foreground/70">
              Based on {manualMinutes}m manual investigation / case.
            </p>
          </div>

          {/* Agent Cost */}
          <div className="rounded-lg border border-border/40 bg-card/40 p-3">
            <p className="text-[11px] text-muted-foreground">LLM Cost / Case</p>
            <p className="mt-1 text-2xl font-bold tabular-nums text-emerald-500 dark:text-emerald-400">
              {agentCost?.sample_count !== 0 && agentCost?.value !== undefined
                ? `$${agentCost.value < 1 ? agentCost.value.toFixed(3) : agentCost.value.toFixed(2)}`
                : '—'}
            </p>
            <p className="mt-1 text-[10px] text-muted-foreground/70">
              Machine triage vs $65/h human baseline.
            </p>
          </div>
        </div>

        {/* Ingest to Escalation Funnel Rate */}
        <div className="mt-3 rounded-lg border border-border/40 bg-card/40 p-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-medium text-foreground">Alert → Case Escalation Ratio</span>
            <span className="font-bold tabular-nums text-foreground">
              {escalationRatio !== null ? `${escalationRatio}%` : '—'}
            </span>
          </div>
          <p className="mt-1 text-[11px] text-muted-foreground">
            {escalationRatio !== null
              ? `Only ${escalationRatio}% of ingested alerts require case escalation.`
              : 'Requires alert and case telemetry in the selected window.'}
          </p>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Loading & Error States
// ---------------------------------------------------------------------------

function LoadingSkeleton() {
  return (
    <div
      className="space-y-6"
      aria-busy="true"
      aria-label="Loading SOC insights"
    >
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 7 }).map((_, i) => (
          <div
            key={i}
            className="h-32 animate-pulse rounded-xl border border-border bg-card/60"
          />
        ))}
      </div>
      <div className="h-56 animate-pulse rounded-xl border border-border bg-card/40" />
    </div>
  );
}

interface ErrorStateProps {
  message: string;
  onRetry: () => void;
}

function ErrorState({ message, onRetry }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className="rounded-xl border border-destructive/30 bg-destructive/5 p-6 text-sm"
    >
      <div className="flex items-center gap-2 text-destructive">
        <Gauge className="h-5 w-5" />
        <p className="font-semibold">
          SOC Insights are temporarily unavailable.
        </p>
      </div>
      <p className="mt-2 text-xs text-muted-foreground">{message}</p>
      <button
        type="button"
        onClick={onRetry}
        className="mt-4 rounded-lg border border-border bg-background px-4 py-1.5 text-xs font-semibold text-foreground hover:bg-muted"
      >
        Retry
      </button>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Value Formatting Helper
// ---------------------------------------------------------------------------

function formatMetricValue(val: number, unit: string): string {
  switch (unit) {
    case 'hours':
      return `${val.toFixed(1)}h`;
    case 'hours_saved':
      return `${Math.round(val)}h`;
    case 'pct':
      return `${(val * 100).toFixed(1)}%`;
    case 'usd':
      return val < 1 ? `$${val.toFixed(3)}` : `$${val.toFixed(2)}`;
    case 'count':
    default:
      return Number.isInteger(val) ? val.toString() : val.toFixed(1);
  }
}
