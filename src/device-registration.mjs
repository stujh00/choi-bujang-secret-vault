import {readSessionCookie} from './auth-session.mjs';

export function deviceRegistry(client) {
  return {
    get:(owner,id)=>client.from('vault_devices').select('id,owner_id,device_id,status,approved_at,expires_at')
      .eq('owner_id',owner).eq('device_id',id).maybeSingle(),
    request:async(owner,id)=>{
      const previous=await client.from('vault_devices').select('id,owner_id,device_id,status,approved_at,expires_at')
        .eq('owner_id',owner).eq('device_id',id).maybeSingle();
      if(previous.error||previous.data) return previous;
      const result=await client.from('vault_devices').insert({owner_id:owner,device_id:id,status:'pending'})
        .select('id,owner_id,device_id,status,approved_at,expires_at').single();
      if(result.error?.code==='23505')return client.from('vault_devices').select('id,owner_id,device_id,status,approved_at,expires_at')
        .eq('owner_id',owner).eq('device_id',id).maybeSingle();
      return result;
    },
  };
}
export function safeDeviceState(row,owner,id,now=Date.now()) {
  const bound=row?.owner_id===owner&&row?.device_id===id;
  const registered=bound&&row.status==='approved'&&Number.isFinite(Date.parse(row.approved_at))
    &&Date.parse(row.approved_at)<=now&&Date.parse(row.expires_at)>now;
  return {registered:Boolean(registered),status:registered?'approved':bound?row.status==='approved'?'expired':row.status:'unverified',
    source:'server',requestId:bound?row.id:null};
}
export async function getDeviceState({request,userId,secretKey,registry}) {
  const id=readSessionCookie(request,secretKey)?.device_id;
  if(!/^[0-9a-f]{16}$/.test(id??''))return safeDeviceState(null,userId,id);
  const result=await registry.get(userId,id);
  if(result.error)throw new Error('DEVICE_REGISTRY_UNAVAILABLE');
  return safeDeviceState(result.data,userId,id);
}
export async function requireRegisteredDevice(request,login,client,secretKey,step) {
  // Operator-signed judge traffic retains its existing isolated verification path.
  // Student JWTs cannot obtain this role by supplying headers or body fields.
  if(step<11||login.kind==='judge') return null;
  try {
    const session=readSessionCookie(request,secretKey);
    if(request.headers?.authorization && request.headers.authorization!=='Bearer '+session?.access_token)
      return {status:403,error:'DEVICE_NOT_REGISTERED'};
    const state=await getDeviceState({request,userId:login.userId,secretKey,registry:deviceRegistry(client)});
    return state.registered?null:{status:403,error:'DEVICE_NOT_REGISTERED'};
  } catch {return {status:503,error:'DEVICE_REGISTRY_UNAVAILABLE'};}
}
