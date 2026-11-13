const { test } = require('node:test');
const assert = require('node:assert/strict');
const { configureStaging } = require('./staging-routing.cjs');
const fresh = () => ({ AISOC_STAGING_ONLY: '1', AISOC_STAGING_API_URL: 'https://isolated-staging.invalid', AISOC_STAGING_API_HOST: 'isolated-staging.invalid' });
test('explicit staging origin and unavailable sibling services', () => {
  const env = fresh(); configureStaging(env);
  assert.equal(env.API_URL, 'https://isolated-staging.invalid');
  assert.equal(env.AGENTS_URL, 'http://127.0.0.1:1');
});
test('missing, mismatched, credentialed and production origins fail closed', () => {
  for (const change of [
    { AISOC_STAGING_API_URL: '' }, { AISOC_STAGING_API_HOST: 'shared.invalid' },
    { AISOC_STAGING_API_URL: 'https://user:secret@isolated-staging.invalid' },
    { VERCEL_ENV: 'production' }, { API_URL: 'https://shared.invalid' },
    { NEXT_PUBLIC_API_URL: 'https://shared.invalid' }, { AGENTS_URL: 'https://shared.invalid' },
    { INTERNAL_API_URL: 'https://shared.invalid' }, { NEXT_PUBLIC_PURPLE_TEAM_API: 'https://shared.invalid' },
  ]) assert.throws(() => configureStaging({ ...fresh(), ...change }));
});
test('rollback leaves ordinary routing untouched', () => {
  const env = { API_URL: 'http://localhost:8000' };
  configureStaging(env); assert.deepEqual(env, { API_URL: 'http://localhost:8000' });
});
test('real Next configuration uses staging rewrites and suppresses branch deployment', () => {
  const { spawnSync } = require('node:child_process');
  const code = `
    const assert = require('node:assert/strict');
    const config = require('./next.config.js');
    const hosting = require('./vercel.json');
    assert.equal(hosting.git.deploymentEnabled['codex/isolated-staging-api'], false);
    config.rewrites().then(result => {
      const rules = Array.isArray(result) ? result : Object.values(result).flat();
      assert(rules.some(rule => rule.destination.startsWith('https://isolated-staging.invalid/')));
      for (const rule of rules) {
        if (rule.destination.startsWith('http')) {
          assert(['isolated-staging.invalid', '127.0.0.1'].includes(new URL(rule.destination).hostname));
        }
      }
    }).catch(() => process.exit(1));
  `;
  const env = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
    ['PATH', 'SYSTEMROOT', 'SYSTEMDRIVE', 'WINDIR', 'TEMP', 'TMP'].includes(key.toUpperCase())));
  const result = spawnSync(process.execPath, ['-e', code], { cwd: __dirname, env: { ...env, ...fresh() } });
  assert.equal(result.status, 0, 'Next configuration must use only isolated routes');
});
