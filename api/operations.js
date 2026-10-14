import {getOperations} from '../src/restore-state.mjs';
export default async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  if(req.method!=='GET') return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
  return res.status(200).json({schema:'vault.operations.v1',checks:[
    ...getOperations(),
    {name:'policy_restore_in_this_runtime',status:'not_run',evidence:[]},
    {name:'stage1_to9_full_live_regression',status:'not_run',evidence:[]},
  ]});
}
