import test from 'node:test';
import assert from 'node:assert/strict';
import {parseLogs,investigate,reportMarkdown} from '../dist/detector.mjs';

const t=i=>new Date(Date.UTC(2026,8,26,6,i)).toISOString();
test('correlates a successful login following repeated failures',()=>{
  const records=[...Array.from({length:5},(_,i)=>({timestamp:t(i),event_type:'login',source_ip:'203.0.113.10',username:'admin',success:false})),
    {timestamp:t(6),event_type:'login',source_ip:'203.0.113.10',username:'admin',success:true}];
  const events=parseLogs(JSON.stringify(records));
  const result=investigate(events);
  assert.equal(result.findings[0].severity,'critical');
  assert.equal(result.findings[0].evidence.length,6);
  assert.match(reportMarkdown(result,events),/Successful login after repeated failures/);
});
test('does not merge separate sources into brute force',()=>{
  const records=Array.from({length:6},(_,i)=>({timestamp:t(i),event_type:'login_failed',source_ip:`203.0.113.${i+1}`}));
  assert.equal(investigate(parseLogs(JSON.stringify(records))).findings.length,0);
});
test('parses quoted CSV and finds a large transfer',()=>{
  const csv=`timestamp,event_type,source_ip,bytes_sent,path\n${t(0)},transfer,10.0.0.1,60000000,"/a,b"`;
  const events=parseLogs(csv,'events.csv');
  assert.equal(events[0].path,'/a,b');
  assert.equal(investigate(events).findings[0].rule,'DATA-004');
});
test('parses SSH auth text and rejects malformed JSON lines',()=>{
  const logs=`Sep 26 06:00:00 host sshd[1]: Failed password for admin from 203.0.113.4 port 22 ssh2\nSep 26 06:00:01 host sshd[1]: Accepted password for admin from 203.0.113.4 port 22 ssh2`;
  const events=parseLogs(logs,'auth.log');
  assert.deepEqual(events.map(e=>e.type),['login_failed','login_success']);
  assert.equal(new Date(events[0].timestamp).getUTCFullYear(),new Date().getUTCFullYear());
  assert.throws(()=>parseLogs('{"event_type":"login"}\nnot-json','events.jsonl'),/line 2/);
});
test('retains Apache access log timestamp and request path',()=>{
  const events=parseLogs('203.0.113.4 - - [26/Sep/2026:06:00:00 +0000] "GET /admin HTTP/1.1" 404 123','access.log');
  assert.equal(events[0].timestamp,'2026-09-26T06:00:00.000Z');
  assert.equal(events[0].path,'/admin');
});
test('eight destination ports in five minutes produce one network finding',()=>{
  const records=Array.from({length:8},(_,i)=>({timestamp:t(i/4),event_type:'network',source_ip:'198.51.100.7',destination_port:20+i}));
  const result=investigate(parseLogs(JSON.stringify(records)));
  assert.equal(result.findings[0].rule,'NET-002');
});
test('undated authentication events cannot fabricate a correlated incident',()=>{
  const records=Array.from({length:6},()=>({event_type:'auth_failure',source_ip:'203.0.113.10',username:'admin'}));
  const events=parseLogs(JSON.stringify(records));
  const result=investigate(events);
  assert.equal(result.undated_count,6);
  assert.equal(result.findings.length,0);
  assert.equal(result.timeline[0].timestamp,null);
  assert.match(reportMarkdown(result,events),/Events without a valid timestamp: 6/);
});
test('invalid timestamps do not contaminate a valid authentication window',()=>{
  const records=[...Array.from({length:4},(_,i)=>({timestamp:t(i),event_type:'failed_login',source_ip:'203.0.113.10'})),
    {timestamp:'not a date',event_type:'failed_login',source_ip:'203.0.113.10'},
    {timestamp:t(5),event_type:'successful_login',source_ip:'203.0.113.10'}];
  const result=investigate(parseLogs(JSON.stringify(records)));
  assert.equal(result.undated_count,1);
  assert.equal(result.findings.length,0);
});
test('detects reordered CSV headers and authentication synonyms',()=>{
  const csv=['source_ip,event_type,timestamp',...Array.from({length:5},(_,i)=>`203.0.113.10,authentication_failure,${t(i)}`),`203.0.113.10,auth_success,${t(6)}`].join('\n');
  const events=parseLogs(csv);
  assert.equal(events[0].type,'login_failed');
  assert.equal(investigate(events).findings[0].severity,'critical');
});
test('undated standalone indicators can still create findings',()=>{
  const result=investigate(parseLogs(JSON.stringify([{event_type:'transfer',bytes_sent:50_000_000},{event_type:'process',command:'powershell.exe -EncodedCommand AAAA'}])));
  assert.deepEqual(result.findings.map(f=>f.rule),['DATA-004','PROC-005']);
  assert.equal(result.findings[0].first_seen,null);
});
test('CSV rejects malformed rows and missing required fields',()=>{
  assert.throws(()=>parseLogs(`timestamp,event_type,source_ip\n${t(0)},network`,'events.csv'),/row 2 has 2 columns/);
  assert.throws(()=>parseLogs('source_ip,bytes_sent\n10.0.0.1,50000000','events.csv'),/needs a timestamp/);
});
test('events without source identity cannot form a shared time-window alert',()=>{
  const records=Array.from({length:8},(_,i)=>({timestamp:t(i/4),event_type:'network',destination_port:20+i}));
  assert.equal(investigate(parseLogs(JSON.stringify(records))).findings.length,0);
});
