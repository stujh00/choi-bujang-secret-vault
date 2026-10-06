export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');

  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  }

  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) {
    return response.status(503).json({ error: 'NOTES_UNAVAILABLE' });
  }

  const { createClient } = await import('@supabase/supabase-js');
  const supabase = createClient(url, secretKey);
  const { data, error } = await supabase
    .from('vault_notes')
    .select('id,title,content')
    .order('id', { ascending: true });

  if (error) {
    return response.status(502).json({ error: 'NOTES_UNAVAILABLE' });
  }

  return response.status(200).json({ notes: data });
}