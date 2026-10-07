import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from '../src/verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
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

function authorizationHeader(request) {
  const value = request.headers?.authorization ?? request.headers?.Authorization;
  return Array.isArray(value) ? value[0] : value;
}

function routeId(request) {
  const value = request.query?.id;
  return Array.isArray(value) ? null : value ?? null;
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

function noteInput(body, { allowId = false } = {}) {
  if (!body || typeof body.title !== 'string' || typeof body.body !== 'string') return null;
  const title = body.title.trim();
  const content = body.body.trim();
  if (!title || title.length > 200 || !content || content.length > 10000) return null;
  if (body.id !== undefined && (!allowId || typeof body.id !== 'string' || !UUID.test(body.id))) {
    return null;
  }
  return { id: body.id, title, content };
}

function publicNote(row) {
  return { id: row.id, title: row.title, body: row.content };
}

export function createNotesHandler({
  appConfig = config,
  env = process.env,
  createSupabaseClient = createClient,
  createVerifier = createLoginVerifier,
  generateId = randomUUID,
} = {}) {
  let runtime;

  function getRuntime() {
    const supabaseUrl = env.SUPABASE_URL;
    const supabaseSecretKey = env.SUPABASE_SECRET_KEY;
    if (!supabaseUrl || !supabaseSecretKey) return null;
    if (runtime?.url === supabaseUrl && runtime?.key === supabaseSecretKey) return runtime;

    let parsedUrl;
    try {
      parsedUrl = new URL(supabaseUrl);
    } catch {
      return null;
    }
    if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password
        || parsedUrl.pathname !== '/' || parsedUrl.search || parsedUrl.hash
        || appConfig.identityProvider?.issuer !== `${parsedUrl.origin}/auth/v1`) {
      return null;
    }

    try {
      const supabase = createSupabaseClient(parsedUrl.href, supabaseSecretKey, CLIENT_OPTIONS);
      const verifyLogin = createVerifier({
        config: appConfig,
        supabaseSecretKey,
        supabaseClient: supabase,
      });
      runtime = { url: supabaseUrl, key: supabaseSecretKey, supabase, verifyLogin };
      return runtime;
    } catch {
      return null;
    }
  }

  return async function notesHandler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');

    const active = getRuntime();
    if (!active) return json(response, 503, { error: 'NOTES_SERVICE_NOT_CONFIGURED' });

    const login = await active.verifyLogin(authorizationHeader(request));
    if (!login) return json(response, 401, { error: 'AUTH_REQUIRED' });

    const id = routeId(request);
    if (id !== null && !UUID.test(id)) return json(response, 400, { error: 'INVALID_NOTE_ID' });

    if (request.method === 'GET' && id === null) {
      const { data, error } = await active.supabase
        .from('notes')
        .select('id, title, content')
        .order('created_at', { ascending: true });
      if (error || !Array.isArray(data)) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      return json(response, 200, data.map(publicNote));
    }

    if (request.method === 'GET') {
      const { data, error } = await active.supabase
        .from('notes')
        .select('id, title, content')
        .eq('id', id)
        .maybeSingle();
      if (error) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!data) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      return json(response, 200, publicNote(data));
    }

    if (request.method === 'POST' && id === null) {
      const input = noteInput(requestBody(request), { allowId: true });
      if (!input) return json(response, 400, { error: 'INVALID_NOTE' });
      const noteId = input.id ?? generateId();
      const { data, error } = await active.supabase
        .from('notes')
        .insert({ id: noteId, owner_id: login.userId, title: input.title, content: input.content })
        .select('id')
        .single();
      if (error?.code === '23505') return json(response, 409, { error: 'NOTE_CONFLICT' });
      if (error || !data) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      return json(response, 201, { id: data.id });
    }

    if (request.method === 'PUT' && id !== null) {
      const input = noteInput(requestBody(request));
      if (!input) return json(response, 400, { error: 'INVALID_NOTE' });
      const { data, error } = await active.supabase
        .from('notes')
        .update({ title: input.title, content: input.content })
        .eq('id', id)
        .select('id, title, content')
        .maybeSingle();
      if (error?.code === '23505') return json(response, 409, { error: 'NOTE_CONFLICT' });
      if (error) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!data) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      return json(response, 200, publicNote(data));
    }

    if (request.method === 'DELETE' && id !== null) {
      const { data, error } = await active.supabase
        .from('notes')
        .delete()
        .eq('id', id)
        .select('id')
        .maybeSingle();
      if (error) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!data) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      return response.status(204).end();
    }

    response.setHeader('Allow', id === null ? 'GET, POST' : 'GET, PUT, DELETE');
    return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  };
}

export default createNotesHandler();
