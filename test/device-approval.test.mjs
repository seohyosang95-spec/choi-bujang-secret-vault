import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceHandler } from '../api/device.js';
import { createNotesHandler } from '../api/notes.js';

const userId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const appConfig = {
  step: 11,
  publicAppUrl: 'https://student-defense.vercel.app',
  judgeIssuer: 'https://judge.example.org/defense/judge',
  identityProvider: {
    issuer: 'https://student.supabase.co/auth/v1',
    audience: 'authenticated',
    jwksUrl: 'https://student.supabase.co/auth/v1/.well-known/jwks.json',
  },
};

function responseRecorder() {
  return {
    headers: new Map(), statusCode: undefined, body: undefined,
    setHeader(key, value) { this.headers.set(key.toLowerCase(), value); },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

function fakeSupabase({ registration = null, notes = [] } = {}) {
  return {
    from(table) {
      const operation = { table };
      const query = {
        select() { return query; },
        eq() { return query; },
        order() { return Promise.resolve({ data: notes, error: null }); },
        maybeSingle() {
          if (table === 'device_registrations') return Promise.resolve({ data: registration, error: null });
          return Promise.resolve({ data: null, error: null });
        },
        insert(value) {
          operation.insert = value;
          return query;
        },
      };
      if (table === 'device_registrations' && !registration) {
        query.maybeSingle = () => Promise.resolve({
          data: { id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', status: 'pending' }, error: null,
        });
      }
      return query;
    },
  };
}

test('기기 승인 요청은 HttpOnly 쿠키와 서버 pending만 만들고 키를 반환하지 않는다', async () => {
  const supabase = fakeSupabase({ registration: null });
  const handler = createDeviceHandler({
    appConfig,
    env: { SUPABASE_URL: 'https://student.supabase.co/', SUPABASE_SECRET_KEY: 'test-only' },
    createSupabaseClient: () => supabase,
    createVerifier: () => async () => ({ kind: 'student', userId }),
  });
  const response = responseRecorder();
  await handler({ method: 'POST', headers: {}, body: { action: 'request' } }, response);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body, { deviceApproval: { approved: false, status: 'pending' } });
  const cookie = response.headers.get('set-cookie');
  assert.match(cookie, /HttpOnly/u);
  assert.match(cookie, /Secure/u);
  assert.match(cookie, /SameSite=Lax/u);
  assert.doesNotMatch(JSON.stringify(response.body), /device_token|[A-Za-z0-9_-]{43}/u);
});

test('승인된 등록부 상태만 자료 API를 열고 승인 전에는 메모를 읽지 않는다', async () => {
  const pending = createNotesHandler({
    appConfig,
    env: { SUPABASE_URL: 'https://student.supabase.co/', SUPABASE_SECRET_KEY: 'test-only' },
    createSupabaseClient: () => fakeSupabase({ registration: null }),
    createVerifier: () => async () => ({ kind: 'student', userId }),
  });
  const denied = responseRecorder();
  await pending({ method: 'GET', headers: { authorization: 'Bearer pending' }, query: {} }, denied);
  assert.equal(denied.statusCode, 403);
  assert.deepEqual(denied.body, { error: 'DEVICE_NOT_APPROVED', status: 'pending' });

  const approved = createNotesHandler({
    appConfig,
    env: { SUPABASE_URL: 'https://student.supabase.co/', SUPABASE_SECRET_KEY: 'test-only' },
    createSupabaseClient: () => fakeSupabase({
      registration: { id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', status: 'approved' }, notes: [],
    }),
    createVerifier: () => async () => ({ kind: 'student', userId }),
  });
  const allowed = responseRecorder();
  await approved({ method: 'GET', headers: { authorization: 'Bearer approved' }, query: {} }, allowed);
  assert.equal(allowed.statusCode, 200);
  assert.deepEqual(allowed.body, []);
});
