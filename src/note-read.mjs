// Shared GET request handler used by the public API and restore regression checks.
// Callers supply only an already verified principal, never request-body identity.
export async function readOwnedNote(request, response, { login, db }) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'GET') return response.status(405).json({error:'METHOD_NOT_ALLOWED'});
  if (!login?.userId) return response.status(401).json({error:'AUTH_REQUIRED'});
  const match = /^\/api\/notes\/([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})\/?$/i.exec(request.url ?? '');
  if (!match) return response.status(404).json({error:'NOTE_NOT_FOUND'});
  const {data,error} = await db.getOwned(match[1], login.userId);
  if (error) return response.status(502).json({error:'NOTES_UNAVAILABLE'});
  if (!data || data.owner_id.toLowerCase() !== login.userId.toLowerCase())
    return response.status(404).json({error:'NOTE_NOT_FOUND'});
  return response.status(200).json({id:data.id,title:data.title,body:data.content});
}
