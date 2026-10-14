import {createClient} from '@supabase/supabase-js';
const argument=name=>process.argv.find(x=>x.startsWith('--'+name+'='))?.slice(name.length+3);
const url=process.env.SUPABASE_URL,key=process.env.SUPABASE_SECRET_KEY;
if(!url||!key)throw new Error('Server-side SUPABASE_URL and SUPABASE_SECRET_KEY are required.');
const client=createClient(url,key,{auth:{autoRefreshToken:false,persistSession:false,detectSessionInUrl:false}});
const id=argument('approve')??argument('revoke');
if(id) {
  if(!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(id)||argument('confirm')!==id)
    throw new Error('Review a request, then provide matching --confirm=<request-id>.');
  const approving=Boolean(argument('approve'));
  const result=await client.from('vault_devices').update(approving
    ?{status:'approved',approved_at:new Date().toISOString(),expires_at:new Date(Date.now()+30*86400000).toISOString(),reviewed_by:'server-operator'}
    :{status:'revoked',expires_at:new Date().toISOString(),reviewed_by:'server-operator'})
    .eq('id',id).select('id,status,expires_at').maybeSingle();
  if(result.error||!result.data)throw new Error('Device review failed or request was not found.');
  console.log(JSON.stringify(result.data));
} else {
  const result=await client.from('vault_devices').select('id,status,requested_at,expires_at').order('requested_at',{ascending:false}).limit(100);
  if(result.error)throw new Error('Cannot read device review requests.');
  console.log(JSON.stringify({requests:result.data},null,2));
}
