import test from 'node:test';
import assert from 'node:assert/strict';
import {selectAIContext} from '../dist/ai-context.mjs';

test('AI evidence budget covers later high-priority findings',()=>{
  const events=Array.from({length:80},(_,i)=>({id:i+1}));
  const findings=[
    {id:'F-001',evidence:Array.from({length:60},(_,i)=>i+1)},
    {id:'F-002',evidence:[61,62]},
    {id:'F-003',evidence:[63]}
  ];
  const context=selectAIContext(findings,events);
  assert.equal(context.events.length,40);
  assert.deepEqual(context.events.slice(0,3).map(e=>e.id),[1,61,63]);
  assert.deepEqual(context.findings[1].evidence,[61,62]);
  assert.deepEqual(context.findings[2].evidence,[63]);
  assert.ok(context.findings.every(f=>f.evidence.every(id=>context.events.some(e=>e.id===id))));
});

test('AI review without findings receives a bounded event sample',()=>{
  const context=selectAIContext([],Array.from({length:80},(_,i)=>({id:i+1})));
  assert.equal(context.events.length,40);
  assert.equal(context.events[0].id,1);
});
