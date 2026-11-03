'use client';

import { useEffect, useState, type FormEvent } from 'react';
import toast from 'react-hot-toast';
import {
  connectorsApi,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorSchemaField,
  type UpdateConnectorPayload,
} from '@/lib/api';

type FormValue = string | number | boolean;

function initialValue(field: ConnectorSchemaField): FormValue {
  if (field.default !== undefined && field.default !== null) {
    return field.default as FormValue;
  }
  if (field.type === 'boolean') return false;
  if (field.type === 'number') return 0;
  return '';
}

function valueFromConfig(field: ConnectorSchemaField, config: Record<string, unknown>): FormValue {
  const value = config[field.name];
  if (value === undefined || value === null) return initialValue(field);
  if (field.type === 'boolean') return Boolean(value);
  if (field.type === 'number') {
    const parsed = typeof value === 'number' ? value : Number(value);
    return Number.isFinite(parsed) ? parsed : initialValue(field);
  }
  return String(value);
}

function SchemaField({
  field,
  value,
  onChange,
}: {
  field: ConnectorSchemaField;
  value: FormValue;
  onChange: (next: FormValue) => void;
}) {
  const inputClass =
    'w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500/30';

  let control;
  switch (field.type) {
    case 'boolean':
      control = (
        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(event) => onChange(event.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500"
          />
          {field.placeholder ?? 'Enabled'}
        </label>
      );
      break;
    case 'select':
      control = (
        <select
          aria-label={field.label}
          className={inputClass}
          value={String(value)}
          required={field.required}
          onChange={(event) => onChange(event.target.value)}
        >
          {!field.required && <option value="">— none —</option>}
          {(field.options ?? []).map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </select>
      );
      break;
    case 'textarea':
      control = (
        <textarea
          aria-label={field.label}
          className={inputClass}
          rows={4}
          value={String(value)}
          placeholder={field.placeholder}
          required={field.required}
          onChange={(event) => onChange(event.target.value)}
        />
      );
      break;
    case 'number':
      control = (
        <input
          aria-label={field.label}
          className={inputClass}
          type="number"
          value={String(value)}
          placeholder={field.placeholder}
          required={field.required}
          onChange={(event) => onChange(event.target.value === '' ? 0 : Number(event.target.value))}
        />
      );
      break;
    default:
      control = (
        <input
          aria-label={field.label}
          className={inputClass}
          type="text"
          value={String(value)}
          placeholder={field.placeholder}
          required={field.required}
          onChange={(event) => onChange(event.target.value)}
        />
      );
  }

  return (
    <div className="space-y-1.5">
      <label className="block text-xs font-medium text-gray-300">{field.label}</label>
      {control}
      {field.help_text && <p className="text-xs text-gray-500">{field.help_text}</p>}
    </div>
  );
}

interface EditConnectorModalProps {
  connector: Connector | null;
  onClose: () => void;
  onUpdated?: (connector: Connector) => void;
}

export function EditConnectorModal({ connector, onClose, onUpdated }: EditConnectorModalProps) {
  if (!connector) return null;
  return (
    <EditConnectorForm
      key={connector.id}
      connector={connector}
      onClose={onClose}
      onUpdated={onUpdated}
    />
  );
}

function EditConnectorForm({
  connector,
  onClose,
  onUpdated,
}: Omit<EditConnectorModalProps, 'connector'> & { connector: Connector }) {
  const [catalog, setCatalog] = useState<ConnectorCatalogEntry[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [name, setName] = useState(connector.name);
  const [enabled, setEnabled] = useState(connector.enabled ?? true);
  const [values, setValues] = useState<Record<string, FormValue>>({});
  const [credentialValues, setCredentialValues] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    let cancelled = false;

    connectorsApi
      .catalog()
      .then((result) => {
        if (cancelled) return;
        setCatalog(result.connectors);
        const entry = result.connectors.find((item) => item.connector_id === connector.type);
        if (!entry) {
          setCatalogError(`Settings for ${connector.type} are not available in this build.`);
          return;
        }
        const config = connector.config ?? {};
        setValues(
          Object.fromEntries(
            entry.fields
              .filter((field) => field.type !== 'secret')
              .map((field) => [field.name, valueFromConfig(field, config)]),
          ),
        );
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setCatalogError(error instanceof Error ? error.message : 'Failed to load connector settings.');
      });

    return () => {
      cancelled = true;
    };
  }, [connector]);

  const entry = catalog?.find((item) => item.connector_id === connector.type) ?? null;
  const fields = entry?.fields.filter((field) => field.type !== 'secret') ?? [];
  const secretFields = entry?.fields.filter((field) => field.type === 'secret') ?? [];

  const save = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!connector || !name.trim()) return;

    setSaving(true);
    try {
      // Preserve schema fields the current build does not know about. The API
      // replaces connector_config as one object, so dropping these would lose
      // settings written by a newer connector version.
      const connectorConfig: Record<string, unknown> = { ...(connector.config ?? {}) };
      for (const field of fields) connectorConfig[field.name] = values[field.name];

      const payload: UpdateConnectorPayload = {
        name: name.trim(),
        is_enabled: enabled,
        connector_config: connectorConfig,
      };
      const replacements = Object.fromEntries(
        secretFields
          .filter((field) => (credentialValues[field.name] ?? '').trim().length > 0)
          .map((field) => [field.name, credentialValues[field.name]]),
      );
      if (Object.keys(replacements).length > 0) payload.auth_config = replacements;

      // Only newly typed values leave the browser. Blank inputs are omitted;
      // the API merges partial replacements with its vault-held credentials.
      const updated = await connectorsApi.update(connector.id, payload);
      toast.success(`Updated ${updated.name}`);
      onUpdated?.(updated);
      onClose();
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to update connector.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="edit-connector-title"
        className="max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-6 shadow-2xl"
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 id="edit-connector-title" className="text-lg font-semibold text-gray-100">
              Configure {connector.name}
            </h2>
            <p className="mt-1 text-xs text-gray-500">{connector.type}</p>
          </div>
          <button
            type="button"
            aria-label="Close connector settings"
            onClick={onClose}
            className="rounded px-2 py-1 text-gray-400 hover:bg-gray-800 hover:text-white"
          >
            ×
          </button>
        </div>

        {catalogError && (
          <p role="alert" className="mb-4 rounded-lg border border-red-800/60 bg-red-950/30 p-3 text-sm text-red-300">
            {catalogError}
          </p>
        )}

        {!catalog && !catalogError ? (
          <p role="status" className="py-8 text-center text-sm text-gray-400">
            Loading connector settings…
          </p>
        ) : (
          <form onSubmit={save} className="space-y-5">
            <div className="space-y-1.5">
              <label htmlFor="connector-name" className="block text-xs font-medium text-gray-300">
                Instance name
              </label>
              <input
                id="connector-name"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
                value={name}
                required
                maxLength={255}
                onChange={(event) => setName(event.target.value)}
              />
            </div>

            <label className="flex items-center gap-2 text-sm text-gray-300">
              <input
                type="checkbox"
                checked={enabled}
                onChange={(event) => setEnabled(event.target.checked)}
                className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500"
              />
              Connector enabled
            </label>

            {secretFields.length > 0 && (
              <section aria-labelledby="connector-credentials-title" className="space-y-4 rounded-lg border border-gray-800 bg-gray-950/40 p-4">
                <div>
                  <h3 id="connector-credentials-title" className="text-sm font-medium text-gray-200">
                    Replace credentials
                  </h3>
                  <p className="mt-1 text-xs text-gray-400">
                    Existing credentials are never shown. Leave a field blank to keep its saved value.
                  </p>
                </div>
                {secretFields.map((field) => (
                  <div key={field.name} className="space-y-1.5">
                    <label htmlFor={`connector-secret-${field.name}`} className="block text-xs font-medium text-gray-300">
                      {field.label}
                      {field.required && <span className="ml-1 text-gray-500">(required for new connectors)</span>}
                    </label>
                    <input
                      id={`connector-secret-${field.name}`}
                      type="password"
                      autoComplete="new-password"
                      value={credentialValues[field.name] ?? ''}
                      placeholder="Enter a replacement value"
                      onChange={(event) =>
                        setCredentialValues((current) => ({ ...current, [field.name]: event.target.value }))
                      }
                      className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm font-mono text-gray-100 focus:border-blue-500 focus:outline-none focus:ring-1 focus:ring-blue-500/30"
                    />
                    {field.help_text && <p className="text-xs text-gray-500">{field.help_text}</p>}
                  </div>
                ))}
              </section>
            )}

            {fields.map((field) => (
              <SchemaField
                key={field.name}
                field={field}
                value={values[field.name] ?? initialValue(field)}
                onChange={(value) => setValues((current) => ({ ...current, [field.name]: value }))}
              />
            ))}

            <div className="flex justify-end gap-2 border-t border-gray-800 pt-4">
              <button
                type="button"
                onClick={onClose}
                className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving || !entry || !!catalogError || !name.trim()}
                className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {saving ? 'Saving…' : 'Save settings'}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
}
