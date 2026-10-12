import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };

const CLIENT_OPTIONS = {
  auth: {
    autoRefreshToken: false,
    detectSessionInUrl: false,
    persistSession: false,
  },
};

function json(response, status, body) {
  return response.status(status).json(body);
}

function requestBody(request) {
  if (request.body && typeof request.body === 'object' && !Buffer.isBuffer(request.body)) {
    return request.body;
  }
  if (typeof request.body !== 'string' && !Buffer.isBuffer(request.body)) return null;
  try {
    const parsed = JSON.parse(String(request.body));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export async function authHandler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    return json(response, 503, { error: 'AUTH_SERVICE_NOT_CONFIGURED' });
  }

  const body = requestBody(request);
  const action = body?.action ?? 'login';

  if (action === 'logout') {
    return json(response, 200, { ok: true });
  }

  const email = typeof body?.email === 'string' ? body.email.trim() : '';
  const password = typeof body?.password === 'string' ? body.password : '';

  if (!email || !password) {
    return json(response, 400, { error: 'EMAIL_AND_PASSWORD_REQUIRED' });
  }

  try {
    const supabase = createClient(supabaseUrl, supabaseSecretKey, CLIENT_OPTIONS);
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error || !data?.session) {
      return json(response, 401, { error: error?.message ?? 'INVALID_CREDENTIALS' });
    }

    return json(response, 200, {
      session: {
        access_token: data.session.access_token,
        token_type: data.session.token_type,
        expires_in: data.session.expires_in,
        user: {
          id: data.user.id,
          email: data.user.email,
        },
      },
    });
  } catch (err) {
    return json(response, 500, { error: 'AUTH_FAILED' });
  }
}

export default authHandler;
