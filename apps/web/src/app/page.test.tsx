import { describe, expect, it, vi } from 'vitest';
import { redirect } from 'next/navigation';
import RootPage from './page';
import nextConfig from '../../next.config.js';

vi.mock('next/navigation', () => ({
  redirect: vi.fn(),
}));

describe('RootPage', () => {
  it('redirects visiting root (/) directly to /dashboard', () => {
    RootPage();
    expect(redirect).toHaveBeenCalledWith('/dashboard');
  });
});

describe('next.config.js redirects', () => {
  it('declares redirect from / to /dashboard', async () => {
    const redirects = await nextConfig.redirects();
    const rootRedirect = redirects.find((r: { source: string }) => r.source === '/');
    expect(rootRedirect).toBeDefined();
    expect(rootRedirect).toEqual({
      source: '/',
      destination: '/dashboard',
      permanent: false,
    });
  });

  it('declares alias redirect from /welcome to /landing', async () => {
    const redirects = await nextConfig.redirects();
    const welcomeRedirect = redirects.find((r: { source: string }) => r.source === '/welcome');
    expect(welcomeRedirect).toBeDefined();
    expect(welcomeRedirect).toEqual({
      source: '/welcome',
      destination: '/landing',
      permanent: false,
    });
  });

  it('preserves existing /signup redirect to /dashboard', async () => {
    const redirects = await nextConfig.redirects();
    const signupRedirect = redirects.find((r: { source: string }) => r.source === '/signup');
    expect(signupRedirect).toBeDefined();
    expect(signupRedirect).toEqual({
      source: '/signup',
      destination: '/dashboard',
      permanent: true,
    });
  });
});
