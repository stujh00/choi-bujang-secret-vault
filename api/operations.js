export default async function handler(req,res) {
 res.setHeader('Cache-Control','no-store');
 if(req.method!=='GET')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
 return res.status(200).json({
  schema:'vault.operations.v1',
  checks:[
   {name:'policy_snapshot_sha256',status:'not_run',detail:'Use npm run restore:plan'},
   {name:'judge_restore_deleted_note',status:'not_run',detail:'Judge integration not yet observed'},
   {name:'restore_after_corruption',status:'not_run',detail:'Judge integration not yet observed'},
   {name:'post_restore_live_access',status:'not_run',detail:'No measured live owner/other-user request'},
  ],
 });
}
