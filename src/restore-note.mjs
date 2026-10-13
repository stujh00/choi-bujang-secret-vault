import { readJsonBody } from './auth-session.mjs';

export const TEST_B_NOTE_ID = '00000000-0000-4000-8000-000000000005';

export async function restoreAuthorizedTestNote(request, response, { verifyAuthorization, verifyBackup, restoreFromBackup }) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
  let parsed;
  try { parsed = new URL(request.url ?? '/api/restore', 'https://local.invalid'); } catch {
    return response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }
  if (parsed.pathname !== '/api/restore' || parsed.search || parsed.hash || /%/.test(request.url ?? '')) {
    return response.status(404).json({ error: 'RESOURCE_NOT_FOUND' });
  }
  const authorization = request.headers?.authorization;
  if (typeof authorization !== 'string' || !/^Bearer [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization)) {
    return response.status(401).json({ error: 'AUTH_REQUIRED' });
  }
  let identity;
  try { identity = await verifyAuthorization(authorization); } catch { identity = null; }
  if (!identity) return response.status(401).json({ error: 'AUTH_REQUIRED' });
  if (identity.kind !== 'judge' || identity.identity !== 'b' || !identity.runId) {
    return response.status(403).json({ error: 'RESTORE_FORBIDDEN' });
  }
  if (Number(request.headers?.['content-length'] ?? 0) > 2048) {
    return response.status(413).json({ error: 'INVALID_BODY' });
  }
  let body;
  try { body = readJsonBody(request); } catch { return response.status(400).json({ error: 'INVALID_BODY' }); }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return response.status(400).json({ error: 'INVALID_BODY' });
  for (const key of ['id','noteId','targetId']) {
    if (body[key] !== undefined && body[key] !== TEST_B_NOTE_ID) {
      return response.status(403).json({ error: 'RESTORE_TARGET_FORBIDDEN' });
    }
  }
  // Always re-read and validate the pre-incident snapshot independently.
  // Never attempt a DB mutation when the verification fails or is unavailable.
  let verification;
  try { verification = await verifyBackup(); } catch {
    return response.status(503).json({ error: 'VERIFIED_BACKUP_UNAVAILABLE' });
  }
  const proof = verification?.data;
  if (verification?.error || proof?.verified !== true || proof?.noteId !== TEST_B_NOTE_ID
      || proof?.ownerVerified !== true || !/^[0-9a-f]{64}$/.test(proof?.contentSha256 ?? '')) {
    return response.status(503).json({ error: 'VERIFIED_BACKUP_UNAVAILABLE' });
  }
  let result;
  try { result = await restoreFromBackup(); } catch {
    return response.status(503).json({ error: 'VERIFIED_BACKUP_UNAVAILABLE' });
  }
  const value = result?.data;
  if (result?.error || value?.restored !== true || value?.noteId !== TEST_B_NOTE_ID
      || value?.ownerVerified !== true || !/^[0-9a-f]{64}$/.test(value?.contentSha256 ?? '')
      || value.contentSha256 !== proof.contentSha256) {
    return response.status(503).json({ error: 'VERIFIED_BACKUP_UNAVAILABLE' });
  }
  return response.status(200).json({ restored:true, noteId:TEST_B_NOTE_ID,
    contentSha256:value.contentSha256, ownerVerified:true });
}
