import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { createOpsSummary } from '../src/ops-evidence.mjs';

const PROBES = Object.freeze({
  's02-forbidden-public-api': { path: '/api/notes', expected: 'deny' },
  's03-normal-my-notes': { path: '/api/my/notes', expected: 'allow' },
  's03-forbidden-logout-notes': { path: '/api/notes', expected: 'deny' },
});

function header(request, name) {
  const value = request.headers?.[name.toLowerCase()] ?? request.headers?.[name];
  return Array.isArray(value) ? value[0] : value;
}

function authorizationHeader(request) {
  return header(request, 'authorization');
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

function probeIds(body) {
  if (!Array.isArray(body?.probeIds) || !body.probeIds.length || body.probeIds.length > 3) return null;
  if (new Set(body.probeIds).size !== body.probeIds.length
      || body.probeIds.some(id => typeof id !== 'string' || !PROBES[id])) return null;
  return body.probeIds;
}

function requestOrigin(request) {
  const host = header(request, 'host');
  const proto = String(header(request, 'x-forwarded-proto') ?? 'https').split(',')[0].trim();
  if (!/^(?:https|http)$/u.test(proto) || typeof host !== 'string'
      || !/^[A-Za-z0-9.-]+(?::\d{1,5})?$/u.test(host)) return null;
  return `${proto}://${host}`;
}

function safeResult(response, body, expected) {
  const allowed = expected === 'allow' ? response.ok : [401, 403].includes(response.status);
  const errorCode = body && typeof body.error === 'string' ? body.error : null;
  if (allowed) {
    if (expected === 'allow' && Array.isArray(body)) {
      return `통과 · HTTP ${response.status} · 자료 ${body.length}건(본문 비표시)`;
    }
    return `통과 · HTTP ${response.status}${errorCode ? ` · ${errorCode}` : ''}`;
  }
  return `실패 · HTTP ${response.status}${errorCode ? ` · ${errorCode}` : ''}`;
}

async function runProbe(request, origin, id) {
  const probe = PROBES[id];
  const requestId = `ops-${randomUUID()}`;
  const checkedAt = new Date().toISOString();
  const headers = { 'X-Request-ID': requestId };
  if (probe.expected === 'allow') {
    const authorization = authorizationHeader(request);
    if (typeof authorization === 'string') headers.Authorization = authorization;
    headers['X-Resource-ID'] = 'notes';
  }
  const response = await fetch(new URL(probe.path, origin), {
    method: 'GET', headers, redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  const body = await response.json().catch(() => null);
  return {
    id,
    requestId: response.headers.get('x-request-id') ?? requestId,
    checkedAt,
    httpStatus: response.status,
    result: safeResult(response, body, probe.expected),
  };
}

export default function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (request.method === 'GET') {
    return response.status(200).json(createOpsSummary({ restoreRoute: config.restoreRoute ?? null }));
  }
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'GET, POST');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const ids = probeIds(requestBody(request));
  const origin = requestOrigin(request);
  if (!ids || !origin) return response.status(400).json({ error: 'INVALID_OPS_PROBE_REQUEST' });

  return Promise.all(ids.map(id => runProbe(request, origin, id)))
    .then(evidence => response.status(200).json(createOpsSummary({
      restoreRoute: config.restoreRoute ?? null,
      evidence,
    })))
    .catch(() => response.status(502).json({ error: 'OPS_PROBE_FAILED' }));
}

