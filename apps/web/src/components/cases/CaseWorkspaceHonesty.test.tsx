/**
 * Data-honesty gate for the case workspace.
 *
 * Three separate ways this screen published invented incident state, all of
 * them reachable on any deployment whose backend was merely unreachable:
 *
 *   1. `const useFallback = !!error` — no demo gate at all. A failed case load
 *      rendered `buildDemoCase(caseId)`, which takes its id from the route
 *      param, so the fabrication presented *as the case the analyst opened*:
 *      a title, an assignee, four linked alert ids, three ATT&CK techniques
 *      and a five-event timeline including "Auto-investigation completed".
 *
 *   2. A failed `casesApi.investigate` was caught and turned into
 *      `status: 'completed'` with invented recon IOCs, a forensic root cause
 *      at 0.88 confidence drawn as a progress bar, three containment actions
 *      and a four-entry agent audit log. The structured panels carried no
 *      caveat — only a transient toast, which is gone by the time anyone
 *      reads the verdict.
 *
 *   3. `updateStatus` mutated the SWR cache optimistically and, on failure,
 *      toasted "writes disabled" without rolling back — so the workspace
 *      showed a status the database did not have.
 *
 * These assert the negative (no fabricated string reaches the DOM) plus the
 * positive half that stops the fix becoming "render nothing": the demo build
 * is still populated, and a real case still renders.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { __setDemoModeForTests } from '@/lib/demoMode';
import type { Case } from '@/lib/api';

const swrData = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
const swrMutate = vi.hoisted(() => vi.fn());

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    const k = typeof key === 'string' ? key : JSON.stringify(key);
    return {
      data: swrData.get(k),
      error: swrErrors.get(k),
      isLoading: false,
      mutate: swrMutate,
    };
  },
}));

const casesApi = vi.hoisted(() => ({
  get: vi.fn(),
  update: vi.fn(),
  investigate: vi.fn(),
  listInvestigations: vi.fn(),
  getInvestigation: vi.fn(),
  addComment: vi.fn(),
  addTask: vi.fn(),
  updateTask: vi.fn(),
  openAutoSummaryHtml: vi.fn(),
  downloadReportPdf: vi.fn(),
  getAttackChain: vi.fn(),
  getTimeline: vi.fn(),
  reopen: vi.fn(),
}));
const apiFetch = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  apiFetch,
  casesApi,
  graphApi: { getCaseAttackPath: vi.fn() },
  realtimeApi: { ticket: vi.fn().mockRejectedValue(new Error('no ticket')) },
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

vi.mock('next/navigation', () => ({
  __esModule: true,
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/cases/INC-2026-0042',
  useSearchParams: () => new URLSearchParams(),
}));

// Both are exercised by their own suites and each opens its own requests.
vi.mock('./InvestigationLedger', () => ({
  __esModule: true,
  InvestigationLedger: () => null,
}));

vi.mock('@/components/copilot/ContextualActions', () => ({
  __esModule: true,
  ContextualActions: () => null,
}));

import { CaseWorkspace } from './CaseWorkspace';

/** The route param. `buildDemoCase` copied it, so the invention wore this id. */
const CASE_ID = 'INC-2026-0042';

const SWR_KEY = JSON.stringify(['case', CASE_ID]);

/** Every string `buildDemoCase()` would put on screen. */
const FABRICATED_CASE_STRINGS = [
  'Suspected lateral movement from finance subnet',
  'WIN-FIN-DB01',
  'BACKUP-SRV-12',
  'sasha.lin',
  'alert-9012',
  'alert-9024',
  'T1021.002',
  'Auto-investigation completed',
  'Rotate svc_backup credentials',
  'lateral-movement',
];

/** Every string the investigate `catch` block would put on screen. */
const FABRICATED_INVESTIGATION_STRINGS = [
  '192.168.1.105',
  'c2.evil-corp.io',
  'Compromised svc_backup service account used for lateral movement.',
  '88% confidence',
  'Isolate WIN-FIN-DB01',
  'Block C2 domain at perimeter',
  'ReconAgent',
  'ForensicAgent',
];

function expectNoFabrication(names: string[]) {
  for (const name of names) {
    expect(
      document.body.textContent ?? '',
      `"${name}" is fabricated case data and must not render outside demo mode`,
    ).not.toContain(name);
  }
}

/** A real case, as the API would return it. */
function realCase(overrides: Partial<Case> = {}): Case {
  return {
    id: CASE_ID,
    title: 'Unusual sign-in from an unrecognised ASN',
    description: 'One failed conditional-access challenge followed by a success.',
    status: 'new',
    severity: 'medium',
    alertIds: [],
    alertCount: 0,
    tags: [],
    mitre: [],
    createdBy: 'system',
    createdAt: '2026-05-06T09:00:00Z',
    updatedAt: '2026-05-06T09:05:00Z',
    timeline: [],
    tasks: [],
    ...overrides,
  } as Case;
}

beforeEach(() => {
  swrData.clear();
  swrErrors.clear();
  swrMutate.mockClear();
  for (const fn of Object.values(casesApi)) fn.mockReset();
  // Methods whose callers chain (.then/.catch) need a resolved default;
  // mockReset() alone would make them return undefined and explode.
  casesApi.getTimeline.mockResolvedValue({ events: [] });
  casesApi.listInvestigations.mockResolvedValue({ runs: [] });
  casesApi.getInvestigation.mockResolvedValue({ status: 'running' });
  apiFetch.mockResolvedValue({ ok: false, text: vi.fn().mockResolvedValue('') });
  casesApi.getAttackChain.mockResolvedValue({ nodes: [], edges: [] });
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('a failed case load does not invent the case', () => {
  it('renders an error naming the failure, not a fabricated incident', () => {
    swrErrors.set(SWR_KEY, new Error('503 Service Unavailable'));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expectNoFabrication(FABRICATED_CASE_STRINGS);
    expect(screen.getByText(/Couldn't load case/i)).toBeTruthy();
    expect(screen.getByText(/503 Service Unavailable/i)).toBeTruthy();
  });

  it('offers a retry that re-issues the request', async () => {
    swrErrors.set(SWR_KEY, new Error('network down'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /retry/i }));

    expect(swrMutate).toHaveBeenCalled();
  });

  it('still shows the seeded case in the hosted demo', () => {
    // The gate must not have become "never show sample data anywhere".
    __setDemoModeForTests(true);
    swrErrors.set(SWR_KEY, new Error('no backend in the demo'));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expect(screen.getByText('Suspected lateral movement from finance subnet')).toBeTruthy();
  });
});

describe('a failed investigation is not reported as a completed one', () => {
  it('surfaces the failure instead of inventing IOCs and a root cause', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('agents service unreachable'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });
    expectNoFabrication(FABRICATED_INVESTIGATION_STRINGS);
    expect(screen.getByText(/agents service unreachable/i)).toBeTruthy();
  });

  it('does not claim the investigation completed', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('502 Bad Gateway'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });
    expect(screen.queryByText(/Investigation complete/i)).toBeNull();
    expect(screen.queryByText(/View full report/i)).toBeNull();
  });

  it('writes no report for an investigation that never ran', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockRejectedValue(new Error('down'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));
    await waitFor(() => {
      expect(screen.getByText(/Investigation failed/i)).toBeTruthy();
    });

    await userEvent.click(screen.getByRole('button', { name: /^report$/i }));

    expect(screen.getByText(/No report yet/i)).toBeTruthy();
    expect(screen.queryByText(/Incident Report — /i)).toBeNull();
  });

  it('shows the starting state while the launch request is pending', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockReturnValue(new Promise(() => {}));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    expect(await screen.findByText('Starting investigation…')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Investigating…' })).toBeDisabled();
  });

  it('launches through the case-scoped API and shows the running state', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockResolvedValue({ run_id: 'run-123', case_id: CASE_ID, status: 'running' });

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    await waitFor(() => {
      expect(casesApi.investigate).toHaveBeenCalledWith(
        CASE_ID,
        'One failed conditional-access challenge followed by a success.',
      );
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Investigation: running' }));
    expect(await screen.findByText('Investigation in progress…')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Investigation: running' })).toBeInTheDocument();
  });

  it('rejects a launch response associated with a different case', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.investigate.mockResolvedValue({
      run_id: 'run-wrong-case',
      case_id: 'another-case-id',
      status: 'running',
    });

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.click(screen.getByRole('button', { name: /investigate with agent/i }));

    expect(await screen.findByText(/not associated with this case/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'View investigation report' })).toBeNull();
  });

  it('restores an active case run after refresh and resumes status polling', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.listInvestigations.mockResolvedValue({
      runs: [{ run_id: 'run-active', case_id: CASE_ID, status: 'running' }],
    });
    casesApi.getInvestigation.mockResolvedValue({ run_id: 'run-active', case_id: CASE_ID, status: 'running' });

    render(<CaseWorkspace caseId={CASE_ID} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Investigation: running' }));
    expect(await screen.findByText('Investigation in progress…')).toBeInTheDocument();
    expect(casesApi.getInvestigation).toHaveBeenCalledWith(CASE_ID, 'run-active');
    expect(screen.getByRole('button', { name: 'Investigating…' })).toBeDisabled();
  });

  it('loads and opens the case-scoped report when a run is already complete', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.listInvestigations.mockResolvedValue({
      runs: [{ run_id: 'run-done', case_id: CASE_ID, status: 'completed' }],
    });
    casesApi.getInvestigation.mockResolvedValue({ run_id: 'run-done', case_id: CASE_ID, status: 'completed' });
    apiFetch.mockResolvedValue({ ok: true, text: vi.fn().mockResolvedValue('# Investigation findings') });

    render(<CaseWorkspace caseId={CASE_ID} />);
    const reportLink = await screen.findByRole('button', { name: 'View investigation report' });
    await waitFor(() => expect(apiFetch).toHaveBeenCalledWith(
      `/api/v1/cases/${CASE_ID}/investigations/run-done/report.md`,
    ));
    await userEvent.click(reportLink);

    expect(await screen.findByText('# Investigation findings')).toBeInTheDocument();
  });

  it('restores a failed run with its recorded failure reason', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.listInvestigations.mockResolvedValue({
      runs: [{ run_id: 'run-failed', case_id: CASE_ID, status: 'failed' }],
    });
    casesApi.getInvestigation.mockResolvedValue({
      run_id: 'run-failed',
      case_id: CASE_ID,
      status: 'failed',
      error: 'Agent execution failed',
    });

    render(<CaseWorkspace caseId={CASE_ID} />);

    await userEvent.click(await screen.findByRole('button', { name: 'Investigation: failed' }));
    expect(await screen.findByText('Investigation failed')).toBeInTheDocument();
    expect(screen.getByText('Agent execution failed')).toBeInTheDocument();
  });
});

describe('a rejected status write does not stick in the UI', () => {
  it('rolls the optimistic mutation back when the API refuses it', async () => {
    swrData.set(SWR_KEY, realCase({ status: 'new' }));
    casesApi.update.mockRejectedValue(new Error('403 Forbidden'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Change case status' }), 'triaged');

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalled();
    });

    // The last mutate call has to restore the status the server still holds.
    await waitFor(() => {
      const restored = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
      expect(restored?.status, 'the rejected write must be rolled back').toBe('new');
    });
  });

  it('keeps the write when the API accepts it', async () => {
    swrData.set(SWR_KEY, realCase({ status: 'new' }));
    casesApi.update.mockResolvedValue(realCase({ status: 'resolved' }));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Change case status' }), 'triaged');

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalled();
    });
    const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
    expect(last?.status).toBe('triaged');
  });

  it('offers only valid forward transitions for an open case', () => {
    swrData.set(SWR_KEY, realCase({ status: 'new' }));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expect(screen.getByRole('option', { name: 'Triaged' })).toBeInTheDocument();
    expect(screen.queryByRole('option', { name: 'Closed' })).toBeNull();
  });

  it('reopens a closed case to the selected supported status', async () => {
    swrData.set(SWR_KEY, realCase({ status: 'closed' }));
    casesApi.reopen.mockResolvedValue(realCase({ status: 'investigating' }));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Change case status' }), 'investigating');

    await waitFor(() => {
      expect(casesApi.reopen).toHaveBeenCalledWith(CASE_ID, {
        reason: 'Reopened to Investigating from analyst console',
        status: 'investigating',
      });
    });
  });
});

describe('case severity and analyst assignment updates', () => {
  it('saves a severity change through the case API', async () => {
    swrData.set(SWR_KEY, realCase({ severity: 'medium' }));
    casesApi.update.mockResolvedValue(realCase({ severity: 'critical' }));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Change case severity' }), 'critical');

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalledWith(CASE_ID, { severity: 'critical' });
    });
    const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
    expect(last?.severity).toBe('critical');
  });

  it('rolls severity back when the case API rejects the update', async () => {
    swrData.set(SWR_KEY, realCase({ severity: 'medium' }));
    casesApi.update.mockRejectedValue(new Error('403 Forbidden'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Change case severity' }), 'critical');

    await waitFor(() => expect(casesApi.update).toHaveBeenCalledWith(CASE_ID, { severity: 'critical' }));
    await waitFor(() => {
      const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
      expect(last?.severity).toBe('medium');
    });
  });

  it('reassigns a case and rolls back cached assignment when rejected', async () => {
    const user = userEvent.setup();
    swrData.set(SWR_KEY, realCase({ assignee: 'first@example.test' }));
    casesApi.update.mockRejectedValue(new Error('403 Forbidden'));

    render(<CaseWorkspace caseId={CASE_ID} />);
    const assignee = screen.getByRole('textbox', { name: 'Assign analyst' });
    expect(assignee).toHaveValue('first@example.test');
    await user.clear(assignee);
    await user.type(assignee, 'second@example.test');
    await user.click(screen.getByRole('button', { name: 'Assign' }));

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalledWith(CASE_ID, { assignee: 'second@example.test' });
    });
    const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
    expect(last?.assignee).toBe('first@example.test');
  });

  it('saves an analyst assignment after a successful update', async () => {
    const user = userEvent.setup();
    swrData.set(SWR_KEY, realCase());
    casesApi.update.mockResolvedValue(realCase({ assignee: 'analyst@example.test' }));

    render(<CaseWorkspace caseId={CASE_ID} />);
    const assignee = screen.getByRole('textbox', { name: 'Assign analyst' });
    await user.type(assignee, 'analyst@example.test');
    await user.click(screen.getByRole('button', { name: 'Assign' }));

    await waitFor(() => {
      expect(casesApi.update).toHaveBeenCalledWith(CASE_ID, { assignee: 'analyst@example.test' });
    });
    const last = swrMutate.mock.calls.at(-1)?.[0] as Case | undefined;
    expect(last?.assignee).toBe('analyst@example.test');
  });
});

describe('case activity history', () => {
  it('renders events in chronological order with their recorded actor and timestamp', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.getTimeline.mockResolvedValue({
      events: [
        {
          id: 'created',
          type: 'created',
          timestamp: '2026-05-06T09:00:00Z',
          title: 'Case opened',
          actor: 'creator@example.test',
        },
        {
          id: 'changed',
          type: 'case_update',
          timestamp: '2026-05-06T09:05:00Z',
          title: 'Case updated',
          description: 'Severity: medium → high',
          actor: 'analyst@example.test',
        },
      ],
    });

    render(<CaseWorkspace caseId={CASE_ID} />);

    const created = await screen.findByText('Case opened');
    const changed = screen.getByText('Case updated');
    expect(created.compareDocumentPosition(changed) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('by creator@example.test')).toBeInTheDocument();
    expect(screen.getByText('by analyst@example.test')).toBeInTheDocument();
    expect(screen.getByText('Severity: medium → high')).toBeInTheDocument();
  });

  it('shows an honest empty state when the case has no recorded activity', () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.getTimeline.mockResolvedValue({ events: [] });

    render(<CaseWorkspace caseId={CASE_ID} />);

    expect(screen.getByText('Quiet so far')).toBeInTheDocument();
  });

  it('reports a timeline request failure instead of presenting it as an empty history', async () => {
    swrData.set(SWR_KEY, realCase());
    casesApi.getTimeline.mockRejectedValue(new Error('timeline unavailable'));

    render(<CaseWorkspace caseId={CASE_ID} />);

    expect(await screen.findByText('Activity unavailable')).toBeInTheDocument();
    expect(screen.getByText('The activity history could not be loaded.')).toBeInTheDocument();
  });
});
