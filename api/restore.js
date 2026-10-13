import fs from 'node:fs';
import { createClient } from '@supabase/supabase-js';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { restoreAuthorizedTestNote } from '../src/restore-note.mjs';

export default async function handler(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  if (request.method !== 'POST') return response.status(405).json({ error:'METHOD_NOT_ALLOWED' });
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) return response.status(503).json({ error:'NOTES_UNAVAILABLE' });
  let config;
  try { config = JSON.parse(fs.readFileSync(new URL('../aleph.config.json',import.meta.url),'utf8')); }
  catch { return response.status(503).json({ error:'RESTORE_UNAVAILABLE' }); }
  const verifyAuthorization = createLoginVerifier({config,supabaseSecretKey:secretKey});
  const supabase = createClient(url,secretKey,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
  return restoreAuthorizedTestNote(request,response,{
    verifyAuthorization,
    verifyBackup:()=>supabase.rpc('verify_test_note_b_backup'),
    restoreFromBackup:()=>supabase.rpc('restore_test_note_b'),
  });
}
