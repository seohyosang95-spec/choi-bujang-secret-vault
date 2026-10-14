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

function fakeSupabase({ registration = null, notes = [], onInsert } = {}) {
  let deviceLookupCount = 0;
  return {
    from(table) {
      const operation = { table };
      const query = {
        select() { return query; },
        eq() { return query; },
        order() { return Promise.resolve({ data: notes, error: null }); },
        maybeSingle() {
          if (table === 'device_registrations') {
            deviceLookupCount += 1;
            if (registration || deviceLookupCount === 1) {
              return Promise.resolve({ data: registration, error: null });
            }
            return Promise.resolve({
              data: { id: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd', status: 'pending' }, error: null,
            });
          }
          return Promise.resolve({ data: null, error: null });
        },
        insert(value) {
          operation.insert = value;
          onInsert?.(value);
          return query;
        },
      };
      return query;
    },
  };
}

test('기기 승인 요청은 서버 pending만 만들고 식별자를 반환하거나 저장하지 않는다', async () => {
  let inserted;
  const supabase = fakeSupabase({ registration: null, onInsert: value => { inserted = value; } });
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
  assert.match(inserted?.device_fingerprint_hash ?? '', /^[a-f0-9]{64}$/u);
  assert.doesNotMatch(JSON.stringify(response.body), /fingerprint|identifier|key/u);
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
