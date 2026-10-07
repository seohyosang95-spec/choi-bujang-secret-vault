import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';
import notesHandler from '../api/notes.js';

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

test('2단계 화면은 빈 정적 파일 대신 서버 자료 함수를 호출한다', async () => {
  const page = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const publicData = JSON.parse(await readFile(new URL('../public/data.json', import.meta.url), 'utf8'));
  assert.match(page, /fetch\('\/api\/notes'/u);
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
