import { operationsReport } from '../src/operations-room.mjs';
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  return res.status(200).json(await operationsReport());
}
