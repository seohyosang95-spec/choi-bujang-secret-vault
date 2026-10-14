import { createHash, randomBytes } from 'node:crypto';

export const DEVICE_COOKIE_NAME = '__Host-vault-device';
const DEVICE_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const DEVICE_STATUS = new Set(['pending', 'approved', 'revoked']);

function headerValue(request, name) {
  const headers = request?.headers ?? {};
  return headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
}

function parseCookies(value) {
  if (typeof value !== 'string') return new Map();
  return new Map(value.split(';').map(part => part.trim().split('='))
    .filter(([key, item]) => key && item)
    .map(([key, ...items]) => [key, items.join('=')]));
}

export function readDeviceToken(request) {
  const token = parseCookies(headerValue(request, 'cookie')).get(DEVICE_COOKIE_NAME);
  return DEVICE_TOKEN.test(token ?? '') ? token : null;
}

export function hashDeviceToken(token) {
  if (!DEVICE_TOKEN.test(token ?? '')) throw new TypeError('invalid_device_token');
  return createHash('sha256').update(token, 'ascii').digest('hex');
}

export function issueDeviceCookie(response, token) {
  if (!DEVICE_TOKEN.test(token ?? '')) throw new TypeError('invalid_device_token');
  response.setHeader('Set-Cookie', `${DEVICE_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`);
}

function normalizedStatus(value) {
  return DEVICE_STATUS.has(value) ? value : 'pending';
}

async function findRegistration(supabase, ownerId, tokenHash) {
  return supabase.from('device_registrations')
    .select('id, status')
    .eq('owner_id', ownerId)
    .eq('device_token_hash', tokenHash)
    .maybeSingle();
}

/**
 * The browser never receives the device token through JavaScript or localStorage.
 * Only its SHA-256 digest is stored server-side; the opaque token is HttpOnly.
 */
export async function getOrCreateDeviceRegistration({
  supabase, ownerId, request, response, generateToken = () => randomBytes(32).toString('base64url'),
} = {}) {
  if (!supabase || typeof ownerId !== 'string' || !ownerId.trim()) {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }

  let token = readDeviceToken(request);
  const needsCookie = !token;
  if (!token) token = generateToken();
  if (!DEVICE_TOKEN.test(token)) return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };

  const tokenHash = hashDeviceToken(token);
  let result;
  try {
    result = await findRegistration(supabase, ownerId, tokenHash);
  } catch {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (result?.error) return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };

  if (needsCookie) {
    try { issueDeviceCookie(response, token); } catch { return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' }; }
  }

  if (result?.data) {
    const status = normalizedStatus(result.data.status);
    return { ok: true, approved: status === 'approved', status };
  }

  let created;
  try {
    created = await supabase.from('device_registrations')
      .insert({ owner_id: ownerId, device_token_hash: tokenHash, status: 'pending' })
      .select('id, status')
      .maybeSingle();
  } catch {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (created?.error && created.error.code !== '23505') {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (created?.error?.code === '23505') {
    try { created = await findRegistration(supabase, ownerId, tokenHash); } catch {
      return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
    }
  }
  if (created?.error || !created?.data) return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  const status = normalizedStatus(created.data.status);
  return { ok: true, approved: status === 'approved', status };
}
