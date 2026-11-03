import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { Connector } from '@/lib/api';

const { catalog, update, toastSuccess, toastError } = vi.hoisted(() => ({
  catalog: vi.fn(),
  update: vi.fn(),
  toastSuccess: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  connectorsApi: { catalog, update },
}));

vi.mock('react-hot-toast', () => ({
  default: Object.assign(vi.fn(), { success: toastSuccess, error: toastError }),
}));

import { EditConnectorModal } from './EditConnectorModal';
import { ConnectorInstanceList } from './ConnectorInstanceList';

const connector: Connector = {
  id: 'connector-1',
  name: 'Production SIEM',
  type: 'splunk',
  status: 'active',
  enabled: true,
  config: { endpoint: 'https://old.example', poll_interval: 60, legacy_option: 'preserve-me' },
};

const catalogResponse = {
  connectors: [
    {
      connector_id: 'splunk',
      connector_name: 'Splunk',
      category: 'siem',
      description: 'Splunk Enterprise',
      fields: [
        { name: 'endpoint', type: 'string', label: 'Endpoint', required: true },
        { name: 'poll_interval', type: 'number', label: 'Poll interval', default: 30 },
        { name: 'verify_tls', type: 'boolean', label: 'Verify TLS' },
        { name: 'api_token', type: 'secret', label: 'API token', required: true },
      ],
    },
  ],
};

beforeEach(() => {
  catalog.mockResolvedValue(catalogResponse);
  update.mockResolvedValue({ ...connector, name: 'Production SIEM (East)' });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('EditConnectorModal', () => {
  it('exposes the configure action and passes the selected connector to its owner', async () => {
    const onConfigure = vi.fn();
    render(
      <ConnectorInstanceList
        connectors={[connector]}
        onTest={vi.fn()}
        onAdd={vi.fn()}
        onConfigure={onConfigure}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'Configure Production SIEM' }));

    expect(onConfigure).toHaveBeenCalledWith(connector);
  });

  it('updates ordinary settings while preserving unknown config and vault-held credentials', async () => {
    const user = userEvent.setup();
    const onUpdated = vi.fn();
    const onClose = vi.fn();
    render(<EditConnectorModal connector={connector} onUpdated={onUpdated} onClose={onClose} />);

    const endpoint = await screen.findByRole('textbox', { name: 'Endpoint' });
    expect(endpoint).toHaveValue('https://old.example');
    const apiToken = screen.getByLabelText(/API token/);
    expect(apiToken).toHaveAttribute('type', 'password');
    expect(apiToken).toHaveValue('');
    expect(screen.getByText(/existing credentials are never shown/i)).toBeTruthy();

    await user.clear(endpoint);
    await user.type(endpoint, 'https://new.example');
    await user.clear(screen.getByLabelText('Instance name'));
    await user.type(screen.getByLabelText('Instance name'), 'Production SIEM (East)');
    await user.click(screen.getByLabelText('Connector enabled'));
    await user.click(screen.getByRole('button', { name: 'Save settings' }));

    await waitFor(() => expect(update).toHaveBeenCalledTimes(1));
    expect(update).toHaveBeenCalledWith('connector-1', {
      name: 'Production SIEM (East)',
      is_enabled: false,
      connector_config: {
        endpoint: 'https://new.example',
        poll_interval: 60,
        verify_tls: false,
        legacy_option: 'preserve-me',
      },
    });
    expect(update.mock.calls[0][1]).not.toHaveProperty('auth_config');
    expect(onUpdated).toHaveBeenCalledWith({ ...connector, name: 'Production SIEM (East)' });
    expect(onClose).toHaveBeenCalledOnce();
  });

  it('submits only nonblank catalog-defined credential replacements', async () => {
    const user = userEvent.setup();
    render(<EditConnectorModal connector={connector} onClose={vi.fn()} />);

    await screen.findByRole('textbox', { name: 'Endpoint' });
    await user.type(screen.getByLabelText(/API token/), 'new-api-token');
    await user.click(screen.getByRole('button', { name: 'Save settings' }));

    await waitFor(() => expect(update).toHaveBeenCalledOnce());
    expect(update.mock.calls[0][1].auth_config).toEqual({ api_token: 'new-api-token' });
    expect(JSON.stringify(update.mock.calls[0][1])).not.toContain('old-token');
  });

  it('keeps the form open and reports an update failure', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    update.mockRejectedValueOnce(new Error('Permission denied'));
    render(<EditConnectorModal connector={connector} onClose={onClose} />);

    await screen.findByRole('textbox', { name: 'Endpoint' });
    await user.click(screen.getByRole('button', { name: 'Save settings' }));

    await waitFor(() => expect(toastError).toHaveBeenCalledWith('Permission denied'));
    expect(onClose).not.toHaveBeenCalled();
    expect(screen.getByRole('dialog')).toBeTruthy();
  });
});
