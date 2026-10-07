import { createClient } from '@supabase/supabase-js';

const CLIENT_OPTIONS = {
  auth: {
    autoRefreshToken: false,
    detectSessionInUrl: false,
    persistSession: false,
  },
};

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('X-Content-Type-Options', 'nosniff');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseSecretKey = process.env.SUPABASE_SECRET_KEY;
  if (!supabaseUrl || !supabaseSecretKey) {
    return response.status(503).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  }

  let parsedUrl;
  try {
    parsedUrl = new URL(supabaseUrl);
  } catch {
    return response.status(503).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  }
  if (parsedUrl.protocol !== 'https:' || parsedUrl.username || parsedUrl.password) {
    return response.status(503).json({ error: 'NOTES_SERVICE_NOT_CONFIGURED' });
  }

  const supabase = createClient(parsedUrl.href, supabaseSecretKey, CLIENT_OPTIONS);
  const { data, error } = await supabase
    .from('notes')
    .select('id, title, content')
    .order('id', { ascending: true });

  if (error || !Array.isArray(data)) {
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }

  return response.status(200).json({ notes: data });
}
