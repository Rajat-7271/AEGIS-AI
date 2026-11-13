// Loaded before any backend origins are resolved by next.config.js.
function configureStaging(env) {
  if (env.AISOC_STAGING_ONLY !== '1') return;
  if (env.VERCEL_ENV === 'production') {
    throw new Error('Staging routing is forbidden in a production deployment');
  }
  const origin = new URL(env.AISOC_STAGING_API_URL || '');
  if (
    origin.protocol !== 'https:' || origin.username || origin.password ||
    origin.pathname !== '/' || origin.search || origin.hash || origin.port ||
    origin.hostname !== env.AISOC_STAGING_API_HOST ||
    !origin.hostname.split('.')[0].includes('staging')
  ) throw new Error('An explicit isolated staging API origin is required');
  const backendKeys = [
    'API_URL', 'INTERNAL_API_URL', 'REALTIME_URL', 'AGENTS_URL', 'FUSION_URL', 'ENRICHMENT_URL',
    'OSQUERY_TLS_URL', 'HONEYTOKENS_URL', 'PURPLE_TEAM_URL',
  ];
  for (const key of Object.keys(env)) {
    if ((backendKeys.includes(key) || (key.startsWith('NEXT_PUBLIC_') && (key.endsWith('_URL') || key.endsWith('_API')))) && env[key]) {
      throw new Error(`Inherited backend routing forbidden in staging: ${key}`);
    }
  }
  env.API_URL = origin.origin;
  // Unavailable services fail locally; no hosted backend fallback.
  for (const key of backendKeys.filter(key => key !== 'API_URL')) env[key] = 'http://127.0.0.1:1';
}
module.exports = { configureStaging };
