import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import {
  ANNOUNCEMENT_ID, isNoteId, isAnnouncementId, exactRoute,
  verifiedInstructor, validNotePayload,
} from '../src/resource-zones.mjs';

const ownId = '00000000-0000-4000-8000-000000000001';
const otherId = '00000000-0000-4000-8000-000000000005';
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const student = id => ({ kind: 'student', userId: id });

test('resource IDs have separate zones and reject arbitrary or query-selected functions', () => {
  assert.ok(isNoteId(ownId));
  assert.ok(isNoteId(otherId));
  assert.ok(!isNoteId(ANNOUNCEMENT_ID));
  assert.ok(isAnnouncementId(ANNOUNCEMENT_ID));
  assert.deepEqual(exactRoute({url:'/api/notes'},'notes'),{type:'list'});
  assert.deepEqual(exactRoute({url:'/api/notes/'+ownId},'notes'),{type:'item',id:ownId});
  assert.deepEqual(exactRoute({url:'/api/announcements/'+ANNOUNCEMENT_ID},'announcements'),
    {type:'item',id:ANNOUNCEMENT_ID});
  assert.equal(exactRoute({url:'/api/notes/'+ANNOUNCEMENT_ID},'notes'),null);
  assert.equal(exactRoute({url:'/api/notes/export'},'notes'),null);
  assert.equal(exactRoute({url:'/api/notes/'+ownId+'/export'},'notes'),null);
  assert.equal(exactRoute({url:'/api/notes?id='+otherId},'notes'),null);
  assert.equal(exactRoute({url:'/api/notes/%65xport'},'notes'),null);
  assert.equal(exactRoute({url:'/api/notes/'+ownId+'?role=instructor'},'notes'),null);
  assert.equal(exactRoute({url:'/api/announcements/export'},'announcements'),null);
});

test('client-supplied roles and ownership cannot become a resource permission', async () => {
  assert.ok(validNotePayload({ title:'mine',body:'lesson',id:ownId }));
  // Legacy clients may send extra fields; authorization never trusts them.
  assert.equal(validNotePayload({ title:'fake', body:'fake', owner_id:B, role:'instructor' }), true);
  assert.equal(validNotePayload({ title:'fake', body:'fake', app_metadata:{vault_role:'instructor'} }), true);

  const service = ({id,role,userRole}) => ({
    auth: {admin: {getUserById: async () => ({
      data:{user:{id,app_metadata:{vault_role:role},user_metadata:{vault_role:userRole}}},error:null,
    })}},
  });
  assert.equal(await verifiedInstructor(student(A),service({id:A,role:'instructor'})),true);
  assert.equal(await verifiedInstructor(student(B),service({id:B,role:'student',userRole:'instructor'})),false);
  assert.equal(await verifiedInstructor(student(A),service({id:B,role:'instructor'})),false);
  assert.equal(await verifiedInstructor({kind:'judge',userId:A},service({id:A,role:'instructor'})),false);
  assert.equal(await verifiedInstructor(student(A),{auth:{admin:{getUserById:async()=>{throw Error('down')}}}}),false);
});

test('device and step-up stage 6/7 controls remain active', async () => {
  const {normal,suspicious} = fixtureRequests();
  const check = async (input,want) => assert.equal((await decide(input)).decision,want);
  await check(normal,'allow');
  await check({...normal,deviceRegistered:false},'deny');
  await check(suspicious,'step_up');
  await check({...suspicious,stepUp:{verified:true,authAgeSeconds:60}},'allow');
  assert.ok(RULE_IDS.includes('resource_boundary'));
});

test('exact resource zone decision denies unverified roles, mutation and export aliases', async () => {
  const {normal}=fixtureRequests();
  const base={...normal,signals:{source:'none',region:'unknown',network:'unknown',hour:null}};
  const own={...base,route:'GET /notes/:id',path:'/notes/'+ownId};
  const other={...base,route:'GET /notes/:id',path:'/notes/'+otherId};
  // Engine does not provide owner_id; both reads are provisional at the SDP layer.
  // The API enforces owner_id against validated Supabase userId on each DB query.
  assert.equal((await decide(own)).decision,'allow');
  assert.equal((await decide(other)).decision,'allow');
  for (const request of [
    {...own,method:'PUT',route:'PUT /notes/:id'},
    {...own,method:'DELETE',route:'DELETE /notes/:id'},
    {...own,path:'/notes/export'},
    {...own,path:'/notes/'+ANNOUNCEMENT_ID},
    {...own,path:'/notes/'+ownId+'/export'},
    {...own,path:'/announcements/'+ANNOUNCEMENT_ID,
      route:'PUT /announcements/:id',method:'PUT'},
  ]) assert.equal((await decide(request)).decision,'deny');
  assert.equal((await decide({...base,route:'GET /announcements/:id',
    path:'/announcements/'+ANNOUNCEMENT_ID})).decision,'allow');
});

test('server API sources enforce stored ownerId and reserved resource boundaries', async () => {
  const list = await readFile(new URL('../api/notes.js',import.meta.url),'utf8');
  const one = await readFile(new URL('../api/notes/[id].js',import.meta.url),'utf8');
  const notices = await readFile(new URL('../src/announcement-api.mjs',import.meta.url),'utf8');
  assert.match(list,/\.eq\('owner_id', login\.userId\)/u);
  assert.match(list,/\.neq\('id', ANNOUNCEMENT_ID\)/u);
  assert.match(list,/data\.filter\(row => row\.owner_id === login\.userId\)/u);
  assert.match(one,/\.eq\('owner_id', login\.userId\)/u);
  assert.match(one,/exactRoute\(request, 'notes'\)/u);
  assert.doesNotMatch(one,/request\.query\?\.id/u);
  assert.match(notices,/verifiedInstructor\(login, supabase\)/u);
  assert.match(notices,/ZONE_FORBIDDEN/u);
  assert.match(notices,/\.eq\('id', ANNOUNCEMENT_ID\)/u);
});
