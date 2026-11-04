import { describe, expect, it, vi } from 'vitest';
import { redirect } from 'next/navigation';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import RootPage from './page';
import nextConfig from '../../next.config.js';

const require = createRequire(import.meta.url);

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

describe('build and proxy environment configuration', () => {
  it('allows API_URL through Turborepo build environment in turbo.json', () => {
    const turboPath = path.resolve(process.cwd(), '../../turbo.json');
    const turboConfig = JSON.parse(fs.readFileSync(turboPath, 'utf8'));

    const inGlobalEnv = turboConfig.globalEnv?.includes('API_URL');
    const inBuildEnv = turboConfig.tasks?.build?.env?.includes('API_URL');

    expect(
      inGlobalEnv || inBuildEnv,
      'turbo.json must allow API_URL in globalEnv or tasks.build.env so Turborepo does not strip it during build',
    ).toBe(true);
  });

  it('rewrites /api/v1/* and /auth/* to process.env.API_URL when set', async () => {
    const prevApiUrl = process.env.API_URL;
    try {
      process.env.API_URL = 'https://aisoc.rajat.blitz.cloud';
      const configFile = path.resolve(process.cwd(), 'next.config.js');
      delete require.cache[configFile];
      const dynamicConfig = require(configFile);
      const rewrites = await dynamicConfig.rewrites();

      const apiRewrite = rewrites.find((r: { source: string }) => r.source === '/api/v1/:path*');
      expect(apiRewrite).toBeDefined();
      expect(apiRewrite.destination).toBe('https://aisoc.rajat.blitz.cloud/api/v1/:path*');

      const authRewrite = rewrites.find((r: { source: string }) => r.source === '/auth/:path*');
      expect(authRewrite).toBeDefined();
      expect(authRewrite.destination).toBe('https://aisoc.rajat.blitz.cloud/auth/:path*');
    } finally {
      if (prevApiUrl === undefined) {
        delete process.env.API_URL;
      } else {
        process.env.API_URL = prevApiUrl;
      }
    }
  });

  it('falls back to http://localhost:8000 when API_URL is unset', async () => {
    const prevApiUrl = process.env.API_URL;
    try {
      delete process.env.API_URL;
      const configFile = path.resolve(process.cwd(), 'next.config.js');
      delete require.cache[configFile];
      const dynamicConfig = require(configFile);
      const rewrites = await dynamicConfig.rewrites();

      const apiRewrite = rewrites.find((r: { source: string }) => r.source === '/api/v1/:path*');
      expect(apiRewrite).toBeDefined();
      expect(apiRewrite.destination).toBe('http://localhost:8000/api/v1/:path*');
    } finally {
      if (prevApiUrl === undefined) {
        delete process.env.API_URL;
      } else {
        process.env.API_URL = prevApiUrl;
      }
    }
  });
});
