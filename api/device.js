import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';
import { getOrCreateDeviceRegistration } from '../src/device-approval.mjs';

const CLIENT_OPTIONS = {
  auth: { autoRefreshToken: false, detectSessionInUrl: false, persistSession: false },
};

function json(response, status, body) {
  return response.status(status).json(body);
}

function authorizationHeader(request) {
  const value = request.headers?.authorization ?? request.headers?.Authorization;
  return Array.isArray(value) ? value[0] : value;
}

export function createDeviceHandler({
  appConfig = config,
  env = process.env,
  createSupabaseClient = createClient,
  createVerifier = createLoginVerifier,
} = {}) {
  let runtime;

  function getRuntime() {
    const supabaseUrl = env.SUPABASE_URL;
    const supabaseSecretKey = env.SUPABASE_SECRET_KEY;
    if (!supabaseUrl || !supabaseSecretKey) return null;
    if (runtime?.url === supabaseUrl && runtime?.key === supabaseSecretKey) return runtime;
    let parsedUrl;
    try { parsedUrl = new URL(supabaseUrl); } catch { return null; }
    if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password
        || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash
        || appConfig.identityProvider?.issuer !== `${parsedUrl.origin}/auth/v1`) return null;
    try {
      const supabase = createSupabaseClient(parsedUrl.href, supabaseSecretKey, CLIENT_OPTIONS);
      const verifyLogin = createVerifier({ config: appConfig, supabaseSecretKey, supabaseClient: supabase });
      runtime = { url: supabaseUrl, key: supabaseSecretKey, supabase, verifyLogin };
      return runtime;
    } catch { return null; }
  }

  return async function deviceHandler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    if (!['GET', 'POST'].includes(request.method)) {
      response.setHeader('Allow', 'GET, POST');
      return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    const active = getRuntime();
    if (!active) return json(response, 503, { error: 'DEVICE_APPROVAL_NOT_CONFIGURED' });
    const login = await active.verifyLogin(authorizationHeader(request));
    if (!login) return json(response, 401, { error: 'AUTH_REQUIRED' });

    // Judge traffic is already authenticated by the judge issuer. The browser
    // student flow below remains bound to the server-side device registry.
    if (login.kind !== 'student') {
      return json(response, 200, { deviceApproval: { approved: true, status: 'approved' } });
    }

    const registration = await getOrCreateDeviceRegistration({
      supabase: active.supabase,
      ownerId: login.userId,
      request,
    });
    if (!registration.ok) return json(response, 503, { error: registration.error });
    return json(response, 200, {
      deviceApproval: { approved: registration.approved, status: registration.status },
    });
  };
}

export default createDeviceHandler();
