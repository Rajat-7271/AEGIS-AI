'use client';

import { Suspense, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { authApi } from '@/lib/api';

function VerifyEmailContent() {
  const params = useSearchParams();
  const [token, setToken] = useState('');
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState('');

  useEffect(() => {
    const value = params.get('token') ?? '';
    setToken(value);
    // Remove the bearer token from browser history immediately.
    if (value) window.history.replaceState(null, '', '/settings/verify-email');
  }, [params]);

  const confirm = async () => {
    if (!token || pending) return;
    setPending(true);
    try {
      await authApi.confirmEmailChange(token);
      setToken('');
      setResult('Your login email was updated. Sign in again with the new address.');
    } catch (error) {
      setResult(error instanceof Error ? error.message : 'Verification failed or expired.');
    } finally {
      setPending(false);
    }
  };

  return (
    <main className="mx-auto flex min-h-screen max-w-lg flex-col justify-center gap-5 px-6 text-gray-100">
      <h1 className="text-2xl font-semibold">Verify new login email</h1>
      <p className="text-sm text-gray-400">You must be signed in to the account that requested this change. Confirmation signs out existing sessions.</p>
      {result && <p role="status" className="text-sm">{result}</p>}
      {!result && (
        <button type="button" onClick={confirm} disabled={!token || pending} className="rounded-lg bg-blue-600 px-4 py-3 text-sm font-medium disabled:opacity-50">
          {pending ? 'Verifying…' : 'Confirm email change'}
        </button>
      )}
      {!token && !result && <p className="text-sm text-amber-300">This link is missing its verification token. Request a new link from Settings.</p>}
      <Link href={result.startsWith('Your login email was updated') ? '/login' : '/settings'} className="text-sm text-blue-400">
        {result.startsWith('Your login email was updated') ? 'Sign in' : 'Back to Settings'}
      </Link>
    </main>
  );
}

export default function VerifyEmailPage() {
  return <Suspense fallback={<main className="p-6">Loading verification…</main>}><VerifyEmailContent /></Suspense>;
}
