import { createHash } from 'node:crypto';

const DEVICE_STATUS = new Set(['pending', 'approved', 'revoked']);
const FINGERPRINT_HEADERS = [
  'user-agent',
  'accept-language',
  'sec-ch-ua',
  'sec-ch-ua-mobile',
  'sec-ch-ua-platform',
];

function headerValue(request, name) {
  const headers = request?.headers ?? {};
  const value = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
  if (Array.isArray(value)) return typeof value[0] === 'string' ? value[0] : '';
  return typeof value === 'string' ? value : '';
}

/**
 * Derive a one-way server-side request fingerprint from ordinary browser
 * headers. No identifier is issued to, stored by, or returned to the browser.
 */
export function hashRequestFingerprint(request) {
  const material = FINGERPRINT_HEADERS
    .map(name => name + ':' + headerValue(request, name).slice(0, 512))
    .join('\n');
  return createHash('sha256').update(material, 'utf8').digest('hex');
}

function normalizedStatus(value) {
  return DEVICE_STATUS.has(value) ? value : 'pending';
}

async function findRegistration(supabase, ownerId, fingerprintHash) {
  return supabase.from('device_registrations')
    .select('id, status')
    .eq('owner_id', ownerId)
    .eq('device_fingerprint_hash', fingerprintHash)
    .maybeSingle();
}

/**
 * Registration is server-side only. The response contains status, never an
 * identifier that could be copied into browser storage or a submission.
 */
export async function getOrCreateDeviceRegistration({ supabase, ownerId, request } = {}) {
  if (!supabase || typeof ownerId !== 'string' || !ownerId.trim()) {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }

  const fingerprintHash = hashRequestFingerprint(request);
  let result;
  try {
    result = await findRegistration(supabase, ownerId, fingerprintHash);
  } catch {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (result?.error) return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };

  if (result?.data) {
    const status = normalizedStatus(result.data.status);
    return { ok: true, approved: status === 'approved', status };
  }

  let created;
  try {
    created = await supabase.from('device_registrations')
      .insert({ owner_id: ownerId, device_fingerprint_hash: fingerprintHash, status: 'pending' })
      .select('id, status')
      .maybeSingle();
  } catch {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (created?.error && created.error.code !== '23505') {
    return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  }
  if (created?.error?.code === '23505') {
    try { created = await findRegistration(supabase, ownerId, fingerprintHash); } catch {
      return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
    }
  }
  if (created?.error || !created?.data) return { ok: false, error: 'DEVICE_REGISTRY_UNAVAILABLE' };
  const status = normalizedStatus(created.data.status);
  return { ok: true, approved: status === 'approved', status };
}
