import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {test} from 'node:test';
import {verifiedSnapshot} from '../scripts/restore-policy.mjs';
const digest = s => createHash('sha256').update(Buffer.from(s,'utf8')).digest('hex');
test('verified stage 9 policy backup survives Windows CRLF checkout without bypassing digest',()=>{
 const raw=readFileSync(new URL('../backups/step10/safe-policy.json',import.meta.url),'utf8');
 const expected=readFileSync(new URL('../backups/step10/safe-policy.sha256',import.meta.url),'utf8').trim().split(/\s+/)[0];
 const canonical=raw.replace(/\r\n/g,'\n');
 assert.equal(digest(canonical),expected);
 assert.equal(digest(canonical.replace(/\n/g,'\r\n').replace(/\r\n/g,'\n')),expected);
 assert.notEqual(digest(canonical.replace('vault.safe-policy.v1','vault.unsafe-policy.v1')),expected);
 assert.equal(verifiedSnapshot().version,'step9-reviewed');
});
