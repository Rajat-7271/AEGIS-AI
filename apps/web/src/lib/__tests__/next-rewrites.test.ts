import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('Windows Security API proxy routing', () => {
  it('forwards Windows Security paths to the configured core API origin', () => {
    const apiUrl = 'https://api.example.invalid';
    const configPath = resolve(process.cwd(), 'next.config.js');
    const script = `
      const config = require(process.argv[1]);
      Promise.resolve(config.rewrites()).then((rules) => {
        const route = rules.find((r) => r.source === '/api/v1/:path*');
        process.stdout.write(JSON.stringify(route || null));
      }).catch((error) => { console.error(error); process.exitCode = 1; });
    `;
    const output = execFileSync(process.execPath, ['-e', script, configPath], {
      encoding: 'utf8',
      env: { ...process.env, API_URL: apiUrl },
    });
    expect(JSON.parse(output)).toEqual({
      source: '/api/v1/:path*',
      destination: `${apiUrl}/api/v1/:path*`,
    });
  });
});
