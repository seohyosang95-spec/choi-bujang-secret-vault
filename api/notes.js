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

const INVALID_ROUTE_ID = Symbol('invalid-route-id');

function routeId(request) {
  const value = request.query?.id;
  if (Array.isArray(value)) return INVALID_ROUTE_ID;
  if (value !== undefined && value !== null) return String(value);

  // Vercel rewrites normally expose :id through req.query, but a direct
  // function invocation can retain the original path. Parse that fallback so
  // a single-note request never degrades into an unscoped list request.
  const rawUrl = request.url ?? request.originalUrl ?? request.path;
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;

  let parsed;
  try {
    parsed = new URL(rawUrl, 'https://internal.invalid');
  } catch {
    return INVALID_ROUTE_ID;
  }

  const queryIds = parsed.searchParams.getAll('id');
  if (queryIds.length > 1) return INVALID_ROUTE_ID;
  if (queryIds.length === 1) return queryIds[0];

  const match = parsed.pathname.match(/^\/api\/notes\/([^/]+)\/?$/iu);
  if (!match) return null;
  try {
    return decodeURIComponent(match[1]);
  } catch {
    return INVALID_ROUTE_ID;
  }
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

function requestResourceId(request) {
  const header = request.headers?.['x-resource-id'] ?? request.headers?.['X-Resource-ID'] ?? request.headers?.['x-resource'];
  const value = Array.isArray(header) ? header[0] : header;
  if (value) return String(value).trim().toLowerCase();
  if (request.query?.type === 'announcements' || request.query?.resource === 'announcements') {
    return 'announcements';
  }
  return 'notes';
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
    const currentResource = requestResourceId(request);
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('X-Content-Type-Options', 'nosniff');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    response.setHeader('X-Resource-ID', currentResource);

    const active = getRuntime();
    if (!active) return json(response, 503, { error: 'NOTES_SERVICE_NOT_CONFIGURED' });

    const login = await active.verifyLogin(authorizationHeader(request));
    if (!login) return json(response, 401, { error: 'AUTH_REQUIRED' });

    // 알 수 없는 다른 구역 요청 거부 (메뉴 우회 직접 API 요청 방어)
    if (currentResource !== 'notes' && currentResource !== 'announcements') {
      return json(response, 403, { error: 'FORBIDDEN' });
    }

    // 강사 공지 자원: 공지 읽기는 허용, 수정은 검증된 강사만 허용 (요청 본문/헤더의 role은 신뢰하지 않음)
    if (currentResource === 'announcements') {
      if (request.method === 'GET') {
        return json(response, 200, [
          { id: 'announcement-01', title: '강사 공지: 과제 안내', body: '8단계 마이크로세그멘테이션 구역 분리 적용', resourceId: 'announcements' },
        ]);
      }
      const isVerifiedInstructor = Boolean(login.kind === 'instructor' || login.role === 'instructor' || login.identity === 'instructor');
      if (!isVerifiedInstructor) {
        return json(response, 403, { error: 'FORBIDDEN' });
      }
      return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    const id = routeId(request);
    if (id === INVALID_ROUTE_ID) return json(response, 400, { error: 'INVALID_NOTE_ID' });
    if (id !== null && !UUID.test(id)) return json(response, 400, { error: 'INVALID_NOTE_ID' });

    if (request.method === 'GET' && id === null) {
      const { data, error } = await active.supabase
        .from('notes')
        .select('id, title, content')
        .eq('owner_id', login.userId)
        .order('created_at', { ascending: true });
      if (error || !Array.isArray(data)) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      return json(response, 200, data.map(publicNote));
    }

    if (request.method === 'GET') {
      const { data, error } = await active.supabase
        .from('notes')
        .select('id, title, content, owner_id')
        .eq('id', id)
        .maybeSingle();
      if (error) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!data) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      if (data.owner_id !== login.userId) {
        return json(response, 403, { error: 'FORBIDDEN' });
      }
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

      const { data: existing, error: existingError } = await active.supabase
        .from('notes')
        .select('id, owner_id')
        .eq('id', id)
        .maybeSingle();
      if (existingError) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!existing) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      if (existing.owner_id !== login.userId) {
        return json(response, 403, { error: 'FORBIDDEN' });
      }

      const { data, error } = await active.supabase
        .from('notes')
        .update({ title: input.title, content: input.content, owner_id: login.userId })
        .eq('id', id)
        .select('id, title, content')
        .maybeSingle();
      if (error?.code === '23505') return json(response, 409, { error: 'NOTE_CONFLICT' });
      if (error) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!data) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      return json(response, 200, publicNote(data));
    }

    if (request.method === 'DELETE' && id !== null) {
      const { data: existing, error: existingError } = await active.supabase
        .from('notes')
        .select('id, owner_id')
        .eq('id', id)
        .maybeSingle();
      if (existingError) return json(response, 502, { error: 'NOTES_UNAVAILABLE' });
      if (!existing) return json(response, 404, { error: 'NOTE_NOT_FOUND' });
      if (existing.owner_id !== login.userId) {
        return json(response, 403, { error: 'FORBIDDEN' });
      }

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
