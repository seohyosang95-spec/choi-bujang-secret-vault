import config from '../aleph.config.json' with { type: 'json' };
import { createOpsSummary } from '../src/ops-evidence.mjs';

export default function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }
  return response.status(200).json(createOpsSummary({ restoreRoute: config.restoreRoute ?? null }));
}

