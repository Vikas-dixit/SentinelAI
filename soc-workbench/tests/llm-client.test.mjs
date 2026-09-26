import test from 'node:test';
import assert from 'node:assert/strict';
import {validateBriefRequest,createAnalystBrief} from '../site/lib/llm-client.mjs';

const context=validateBriefRequest({findings:[{id:'F-001',rule:'AUTH-001',title:'Repeated failures',severity:'high',evidence:[1]}],events:[{id:1,timestamp:'2026-09-26T06:00:00Z',type:'login_failed',source_ip:'203.0.113.4',raw:'Failed password from 203.0.113.4'}]});
test('limits external context and rejects malformed records',()=>{
  assert.throws(()=>validateBriefRequest({findings:[],events:Array(41).fill({})}),/limit/);
  assert.throws(()=>validateBriefRequest({findings:[null],events:[]}),/invalid/);
  assert.equal(context.events[0].id,1);
});
test('makes a non-stored structured Responses request and validates cited evidence',async()=>{
  let sent;
  const mock=async(url,options)=>{sent={url,options,body:JSON.parse(options.body)};return {ok:true,json:async()=>({output:[{type:'message',content:[{type:'output_text',text:JSON.stringify({assessment:'Investigate the source.',evidence_ids:[1,999],uncertainties:['Owner unknown'],next_steps:['Check auth logs']})}]}]})};};
  const brief=await createAnalystBrief(context,'test-key',mock);
  assert.equal(sent.url,'https://api.openai.com/v1/responses');
  assert.equal(sent.body.store,false);
  assert.equal(sent.body.text.format.type,'json_schema');
  assert.deepEqual(brief.evidence_ids,[1]);
  assert.equal(sent.options.headers.Authorization,'Bearer test-key');
});
test('reports API quota failure without treating it as a valid brief',async()=>{
  const mock=async()=>({ok:false,status:429,json:async()=>({error:{message:'quota'}})});
  await assert.rejects(createAnalystBrief(context,'test-key',mock),/rate limit or quota/);
});
