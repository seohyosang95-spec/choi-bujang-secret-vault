import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import notesHandler, { createNotesHandler } from '../api/notes.js';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));
const implementedFunctions = ['api/notes.js'];

test('패키징 함수 기준표는 시작 틀의 실제 API와 일치한다', async () => {
  const actual = (await readdir(new URL('../api/', import.meta.url)))
    .filter(name => /\.(?:m?js|ts)$/u.test(name))
    .map(name => join('api', name).replaceAll('\\', '/')).sort();
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, []);
  assert.deepEqual(baseline.allowedNew, ['api/ai.js', 'api/threat-intel.js']);
  assert.deepEqual(actual, [...baseline.functions, ...baseline.allowedNew, ...implementedFunctions].sort());
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import(`../api/${name}.js`);
    const headers = new Map();
    let status;
    let body;
    handler({}, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\.png/u);
});

test('3단계 화면은 공식 SDK 로그인·로그아웃과 인증된 자료 요청을 사용한다', async () => {
  const page = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const publicData = JSON.parse(await readFile(new URL('../public/data.json', import.meta.url), 'utf8'));
  assert.match(page, /signInWithPassword/u);
  assert.match(page, /auth\.signOut/u);
  assert.match(page, /Authorization: `Bearer \$\{session\.access_token\}`/u);
  assert.doesNotMatch(page, /SUPABASE_SECRET_KEY/u);
  assert.deepEqual(publicData, { notes: [] });
});

test('자료 함수는 서버 설정이 없을 때 비밀값 없이 거부한다', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  let status;
  let body;
  const headers = new Map();
  const response = {
    setHeader: (key, value) => headers.set(key.toLowerCase(), value),
    status: value => { status = value; return response; },
    json: value => { body = value; return response; },
  };
  try {
    await notesHandler({ method: 'GET' }, response);
    assert.equal(status, 503);
    assert.deepEqual(body, { error: 'NOTES_SERVICE_NOT_CONFIGURED' });
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.equal(headers.get('x-content-type-options'), 'nosniff');
    assert.doesNotMatch(JSON.stringify(body), /SUPABASE_(?:URL|SECRET_KEY)/u);
  } finally {
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

function responseRecorder() {
  return {
    headers: new Map(),
    statusCode: undefined,
    body: undefined,
    ended: false,
    setHeader(key, value) { this.headers.set(key.toLowerCase(), value); },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
    end() { this.ended = true; return this; },
  };
}

function scriptedSupabase(results, operations) {
  return {
    auth: { getClaims: async () => ({ data: { claims: {} }, error: null }) },
    from(table) {
      assert.equal(table, 'notes');
      const operation = {};
      operations.push(operation);
      const result = results.shift();
      const query = {
        select(columns) { operation.select = columns; return query; },
        order(column) { operation.order = column; return Promise.resolve(result); },
        eq(column, value) { operation.eq = [column, value]; return query; },
        maybeSingle() { return Promise.resolve(result); },
        single() { return Promise.resolve(result); },
        insert(value) { operation.insert = value; return query; },
        update(value) { operation.update = value; return query; },
        delete() { operation.delete = true; return query; },
      };
      return query;
    },
  };
}

test('자료 함수는 검증된 사용자만 허용하고 생성 owner_id에 그 사용자 ID를 쓴다', async () => {
  const userId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
  const noteId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
  const operations = [];
  const supabase = scriptedSupabase([
    { data: [], error: null },
    { data: { id: noteId }, error: null },
    { data: { id: noteId, title: '수정', content: '수정 본문' }, error: null },
    { data: { id: noteId }, error: null },
    { data: null, error: null },
  ], operations);
  const handler = createNotesHandler({
    appConfig: {
      publicAppUrl: 'https://student-defense.vercel.app',
      judgeIssuer: 'https://judge.example.org/defense/judge',
      identityProvider: {
        issuer: 'https://student.supabase.co/auth/v1',
        audience: 'authenticated',
        jwksUrl: 'https://student.supabase.co/auth/v1/.well-known/jwks.json',
      },
    },
    env: { SUPABASE_URL: 'https://student.supabase.co/', SUPABASE_SECRET_KEY: 'test-only' },
    createSupabaseClient: () => supabase,
    createVerifier: () => async authorization => authorization === 'Bearer valid.test.token'
      ? { kind: 'student', userId } : null,
    generateId: () => noteId,
  });

  const denied = responseRecorder();
  await handler({ method: 'GET', headers: {}, query: {} }, denied);
  assert.equal(denied.statusCode, 401);
  assert.deepEqual(denied.body, { error: 'AUTH_REQUIRED' });
  assert.equal(operations.length, 0);

  const headers = { authorization: 'Bearer valid.test.token' };
  const listed = responseRecorder();
  await handler({ method: 'GET', headers, query: {} }, listed);
  assert.equal(listed.statusCode, 200);
  assert.deepEqual(listed.body, []);

  const created = responseRecorder();
  await handler({ method: 'POST', headers, query: {}, body: {
    title: '새 메모', body: '본문', userId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc', role: 'admin',
  } }, created);
  assert.equal(created.statusCode, 201);
  assert.deepEqual(created.body, { id: noteId });
  assert.deepEqual(operations[1].insert, {
    id: noteId, owner_id: userId, title: '새 메모', content: '본문',
  });

  const updated = responseRecorder();
  await handler({ method: 'PUT', headers, query: { id: noteId }, body: { title: '수정', body: '수정 본문' } }, updated);
  assert.equal(updated.statusCode, 200);
  assert.deepEqual(updated.body, { id: noteId, title: '수정', body: '수정 본문' });
  assert.deepEqual(operations[2].eq, ['id', noteId]);

  const removed = responseRecorder();
  await handler({ method: 'DELETE', headers, query: { id: noteId } }, removed);
  assert.equal(removed.statusCode, 204);
  assert.equal(removed.ended, true);

  const missing = responseRecorder();
  await handler({ method: 'GET', headers, query: { id: noteId } }, missing);
  assert.equal(missing.statusCode, 404);
  assert.deepEqual(missing.body, { error: 'NOTE_NOT_FOUND' });
});
