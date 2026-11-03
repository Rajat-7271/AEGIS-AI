import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const { createCase, mutate, push, toastSuccess, toastError } = vi.hoisted(() => ({
  createCase: vi.fn(),
  mutate: vi.fn(),
  push: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({ data: { cases: [], total: 0 }, error: undefined, isLoading: false, mutate }),
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, casesApi: { ...actual.casesApi, create: createCase } };
});

vi.mock('react-hot-toast', () => ({
  default: Object.assign(vi.fn(), { success: toastSuccess, error: toastError }),
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

vi.mock('next/navigation', () => ({ useRouter: () => ({ push }) }));

vi.mock('@/components/saved-views/SavedViewsBar', () => ({
  __esModule: true,
  SavedViewsBar: () => null,
}));

vi.mock('./AnalystWorkload', () => ({ AnalystWorkload: () => null }));

import { CasesView } from './CasesView';

beforeEach(() => {
  createCase.mockResolvedValue({ id: 'case-123', title: 'Manual investigation' });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('manual case creation', () => {
  it('creates a case through the API and refreshes the tenant case list', async () => {
    const user = userEvent.setup();
    render(<CasesView />);

    await user.click(screen.getByRole('button', { name: 'New Case' }));
    expect(screen.getByRole('dialog', { name: 'Create case' })).toBeInTheDocument();

    await user.type(screen.getByLabelText('Case title'), 'Manual investigation');
    await user.type(screen.getByLabelText(/Description/), 'Review suspicious cloud activity.');
    await user.selectOptions(screen.getByLabelText('Severity'), 'high');
    await user.type(screen.getByLabelText(/Assignee/), 'analyst@example.test');
    await user.click(screen.getByRole('button', { name: 'Create case' }));

    await waitFor(() => expect(createCase).toHaveBeenCalledOnce());
    expect(createCase).toHaveBeenCalledWith({
      title: 'Manual investigation',
      description: 'Review suspicious cloud activity.',
      severity: 'high',
      assignee: 'analyst@example.test',
    });
    expect(toastSuccess).toHaveBeenCalledWith('Case created');
    expect(mutate).toHaveBeenCalledOnce();
    expect(push).toHaveBeenCalledWith('/cases/case-123');
    expect(screen.queryByRole('dialog')).toBeNull();
  });

  it('requires a three-character title and keeps the dialog open on API failure', async () => {
    const user = userEvent.setup();
    createCase.mockRejectedValueOnce(new Error('request failed'));
    render(<CasesView />);

    await user.click(screen.getByRole('button', { name: 'New Case' }));
    const title = screen.getByLabelText('Case title');
    await user.type(title, 'ab');
    expect(screen.getByRole('button', { name: 'Create case' })).toBeDisabled();
    expect(createCase).not.toHaveBeenCalled();

    await user.type(title, 'c');
    await user.click(screen.getByRole('button', { name: 'Create case' }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Could not create the case. Please try again.'));
    expect(screen.getByRole('dialog', { name: 'Create case' })).toBeInTheDocument();
    expect(mutate).not.toHaveBeenCalled();
  });
});
