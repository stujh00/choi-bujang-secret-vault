import {getRestoreOperations} from '../src/restore-env.mjs';
export default async function handler(req,res) {
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='GET')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 const history=getRestoreOperations();
 const restores=history.filter(x=>x.action==='restore');
 const retests=history.filter(x=>x.action==='retest');
 return res.status(200).json({
  schema:'vault.operations.v1',
  checks:[
   {name:'policy_snapshot_sha256',status:'not_run',detail:'Use npm run restore:plan'},
   {name:'judge_restore_deleted_note',status:'not_run',detail:'Judge integration not yet observed'},
   {name:'restore_after_corruption',status:'not_run',detail:'Judge integration not yet observed'},
   {name:'post_restore_handler_access',status:retests.length?'measured':'not_run',evidence:retests},
   {name:'verified_note_restore',status:restores.length?'measured':'not_run',evidence:restores},
  ],
 });
}
