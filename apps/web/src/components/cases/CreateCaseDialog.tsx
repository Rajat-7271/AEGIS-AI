'use client';

import { useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import toast from 'react-hot-toast';
import { casesApi, type CaseSeverity } from '@/lib/api';

const SEVERITIES: CaseSeverity[] = ['critical', 'high', 'medium', 'low'];

interface CreateCaseDialogProps {
  onClose: () => void;
  onCreated: () => void;
}

export function CreateCaseDialog({ onClose, onCreated }: CreateCaseDialogProps) {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<CaseSeverity>('medium');
  const [assignee, setAssignee] = useState('');
  const [saving, setSaving] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const trimmedTitle = title.trim();
    if (trimmedTitle.length < 3 || saving) return;

    setSaving(true);
    try {
      const created = await casesApi.create({
        title: trimmedTitle,
        description: description.trim() || undefined,
        severity,
        assignee: assignee.trim() || undefined,
      });
      toast.success('Case created');
      onCreated();
      onClose();
      router.push(`/cases/${encodeURIComponent(created.caseNumber ?? created.id)}`);
    } catch {
      toast.error('Could not create the case. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4">
      <section
        role="dialog"
        aria-modal="true"
        aria-labelledby="create-case-title"
        className="w-full max-w-xl rounded-xl border border-gray-800 bg-gray-900 p-6 shadow-2xl"
      >
        <div className="mb-5 flex items-start justify-between gap-4">
          <div>
            <h2 id="create-case-title" className="text-lg font-semibold text-gray-100">
              Create case
            </h2>
            <p className="mt-1 text-xs text-gray-500">Start a case to organize investigation work and evidence.</p>
          </div>
          <button
            type="button"
            aria-label="Close create case dialog"
            onClick={onClose}
            disabled={saving}
            className="rounded px-2 py-1 text-gray-400 hover:bg-gray-800 hover:text-white disabled:opacity-50"
          >
            ×
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="new-case-title" className="block text-xs font-medium text-gray-300">
              Case title
            </label>
            <input
              id="new-case-title"
              autoFocus
              required
              minLength={3}
              maxLength={255}
              value={title}
              onChange={(event) => setTitle(event.target.value)}
              placeholder="Describe the incident"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
            />
            <p className="text-xs text-gray-500">Use at least 3 characters.</p>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="new-case-description" className="block text-xs font-medium text-gray-300">
              Description <span className="font-normal text-gray-500">(optional)</span>
            </label>
            <textarea
              id="new-case-description"
              rows={4}
              value={description}
              onChange={(event) => setDescription(event.target.value)}
              placeholder="Add context, scope, or initial observations"
              className="w-full resize-y rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
            />
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="space-y-1.5">
              <label htmlFor="new-case-severity" className="block text-xs font-medium text-gray-300">
                Severity
              </label>
              <select
                id="new-case-severity"
                value={severity}
                onChange={(event) => setSeverity(event.target.value as CaseSeverity)}
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
              >
                {SEVERITIES.map((value) => (
                  <option key={value} value={value}>
                    {value.charAt(0).toUpperCase() + value.slice(1)}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="new-case-assignee" className="block text-xs font-medium text-gray-300">
                Assignee <span className="font-normal text-gray-500">(optional)</span>
              </label>
              <input
                id="new-case-assignee"
                value={assignee}
                onChange={(event) => setAssignee(event.target.value)}
                placeholder="name@organization.com"
                className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-blue-500 focus:outline-none"
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 border-t border-gray-800 pt-4">
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || title.trim().length < 3}
              className="rounded-lg bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {saving ? 'Creating…' : 'Create case'}
            </button>
          </div>
        </form>
      </section>
    </div>
  );
}
