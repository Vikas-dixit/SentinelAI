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
test('login records without an outcome cannot become failed logins',()=>{
  const records=Array.from({length:6},(_,i)=>({timestamp:t(i),event_type:'login',source_ip:'203.0.113.10'}));
  const events=parseLogs(JSON.stringify(records));
  const result=investigate(events);
  assert.equal(events[0].type,'login_unknown');
  assert.equal(result.unknown_outcome_count,6);
  assert.equal(result.findings.length,0);
  assert.match(reportMarkdown(result,events),/Login events with unknown outcome: 6/);
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
test('yearless syslog dates ahead of today resolve to the previous year',()=>{
  const now=new Date();
  const tomorrow=new Date(Date.now()+2*24*60*60_000);
  if(tomorrow.getFullYear()!==now.getFullYear()) return;
  const month=tomorrow.toLocaleString('en-US',{month:'short',timeZone:'UTC'});
  const day=tomorrow.getUTCDate();
  const event=parseLogs(`${month} ${day} 06:00:00 host sshd[1]: Failed password for admin from 203.0.113.4 port 22 ssh2`,'auth.log')[0];
  assert.equal(new Date(event.timestamp).getUTCFullYear(),now.getUTCFullYear()-1);
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
test('web probing needs five suspicious requests from one source in ten minutes',()=>{
  const probes=Array.from({length:5},(_,i)=>({timestamp:t(i),event_type:'http',source_ip:'192.0.2.55',method:'GET',path:i%2?'/admin':'/.env',status:404}));
  const result=investigate(parseLogs(JSON.stringify(probes)));
  assert.equal(result.findings[0].rule,'WEB-003');
  assert.equal(result.findings[0].evidence.length,5);
  const benign=Array.from({length:5},(_,i)=>({...probes[i],path:'/health',status:200}));
  assert.equal(investigate(parseLogs(JSON.stringify(benign))).findings.length,0);
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
test('parses Unix second and millisecond timestamps without inventing dates',()=>{
  const iso='2026-09-26T06:00:00.000Z';
  const epoch=Date.parse(iso);
  const events=parseLogs(JSON.stringify([
    {timestamp:epoch/1000,event_type:'network',source_ip:'192.0.2.1'},
    {timestamp:String(epoch),event_type:'network',source_ip:'192.0.2.1'},
    {timestamp:'1',event_type:'network',source_ip:'192.0.2.1'},
    {timestamp:0,event_type:'network',source_ip:'192.0.2.1'}
  ]));
  assert.deepEqual(events.map(e=>e.timestamp),[iso,iso,null,'1970-01-01T00:00:00.000Z']);
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
test('pasted log text obeys the same input size limit as uploads',()=>{
  assert.throws(()=>parseLogs('x'.repeat(2*1024*1024+1)),/2 MB/);
  assert.throws(()=>parseLogs('अ'.repeat(800_000)),/2 MB/);
});
test('events without source identity cannot form a shared time-window alert',()=>{
  const records=Array.from({length:8},(_,i)=>({timestamp:t(i/4),event_type:'network',destination_port:20+i}));
  assert.equal(investigate(parseLogs(JSON.stringify(records))).findings.length,0);
});
test('parses IPv6 source addresses in SSH and web access logs',()=>{
  const ssh=parseLogs('Sep 26 06:00:00 host sshd[1]: Failed password for admin from 2001:db8::42 port 22 ssh2','auth.log');
  const web=parseLogs('2001:db8::42 - - [26/Sep/2026:06:00:00 +0000] "GET /admin HTTP/1.1" 404 123','access.log');
  assert.equal(ssh[0].source_ip,'2001:db8::42');
  assert.equal(web[0].source_ip,'2001:db8::42');
  assert.equal(parseLogs('Sep 26 06:00:00 host sshd[1]: Failed password for admin from badhost port 22 ssh2','auth.log')[0].source_ip,'');
  assert.equal(parseLogs('Sep 26 06:00:00 host sshd[1]: Failed password for admin from bad:port port 22 ssh2','auth.log')[0].source_ip,'');
  assert.equal(parseLogs('999.999.999.999 - - [26/Sep/2026:06:00:00 +0000] "GET /admin HTTP/1.1" 404 123','access.log')[0].source_ip,'');
});
test('unrecognized text remains visible with an explicit coverage count',()=>{
  const events=parseLogs('Sep 26 06:00:00 host customd[1]: unrelated event','custom.log');
  const result=investigate(events);
  assert.equal(result.unrecognized_count,1);
  assert.equal(result.timeline[0].type,'other');
  assert.match(reportMarkdown(result,events),/Events with an unrecognized type: 1/);
});
test('maps common Windows security event IDs to authentication findings',()=>{
  const records=[...Array.from({length:5},(_,i)=>({TimeCreated:t(i),EventID:4625,IpAddress:'203.0.113.44',TargetUserName:'admin'})),
    {TimeCreated:t(6),EventID:4624,IpAddress:'203.0.113.44',TargetUserName:'admin'}];
  const events=parseLogs(JSON.stringify(records));
  assert.deepEqual(events.map(e=>e.type),['login_failed','login_failed','login_failed','login_failed','login_failed','login_success']);
  assert.equal(investigate(events).findings[0].rule,'AUTH-001');
});
test('parses Windows Security CSV with reordered columns',()=>{
  const csv=`IpAddress,EventID,TimeCreated,TargetUserName\n203.0.113.44,4625,${t(0)},admin`;
  const events=parseLogs(csv);
  assert.equal(events[0].type,'login_failed');
  assert.equal(events[0].source_ip,'203.0.113.44');
  assert.equal(events[0].timestamp,t(0));
});
test('maps nested ECS authentication, web, network, and process fields',()=>{
  const auth=[...Array.from({length:5},(_,i)=>({'@timestamp':t(i),event:{category:['authentication'],action:'user_login',outcome:'failure'},source:{ip:'203.0.113.66'},user:{name:'admin'}})),
    {'@timestamp':t(6),event:{category:['authentication'],action:'user_login',outcome:'success'},source:{ip:'203.0.113.66'},user:{name:'admin'}}];
  const events=parseLogs(JSON.stringify(auth));
  assert.equal(events[0].type,'login_failed');
  assert.equal(events[0].username,'admin');
  assert.equal(investigate(events).findings[0].severity,'critical');
  const nested=parseLogs(JSON.stringify([
    {'@timestamp':t(0),event:{category:['network']},source:{ip:'192.0.2.1'},destination:{ip:'10.0.0.1',port:443}},
    {'@timestamp':t(1),event:{category:['web']},source:{ip:'192.0.2.1'},http:{request:{method:'GET'},response:{status_code:404}},url:{path:'/.env'}},
    {'@timestamp':t(2),process:{command_line:'powershell.exe -EncodedCommand AAAA'}}
  ]));
  assert.equal(nested[0].type,'network');
  assert.equal(nested[0].destination_port,443);
  assert.equal(nested[1].type,'http');
  assert.equal(nested[1].path,'/.env');
  assert.equal(nested[2].process_name,'powershell.exe -EncodedCommand AAAA');
});
test('correlation respects the window boundary and finds later clusters',()=>{
  const base=Date.UTC(2026,8,26,6,0);
  const at=ms=>new Date(base+ms).toISOString();
  const failures=[0,4,8,12,15,31].map(minutes=>({timestamp:at(minutes*60_000),event_type:'login_failed',source_ip:'203.0.113.99'}));
  const atBoundary=investigate(parseLogs(JSON.stringify(failures.slice(0,5))));
  assert.equal(atBoundary.findings[0].rule,'AUTH-001');
  const outside=failures.slice(0,5).map((e,i)=>i===4?{...e,timestamp:at(15*60_000+1)}:e);
  assert.equal(investigate(parseLogs(JSON.stringify(outside))).findings.length,0);
  const scan=[...Array.from({length:8},(_,i)=>({timestamp:at(i*6*60_000),event_type:'network',source_ip:'198.51.100.55',destination_port:20+i})),
    ...Array.from({length:8},(_,i)=>({timestamp:at(60*60_000+i*10_000),event_type:'network',source_ip:'198.51.100.55',destination_port:100+i}))];
  const result=investigate(parseLogs(JSON.stringify(scan)));
  assert.equal(result.findings[0].rule,'NET-002');
  assert.deepEqual(result.findings[0].evidence,Array.from({length:8},(_,i)=>i+9));
});
test('handles 5,000 nonmatching network events',()=>{
  const records=Array.from({length:5000},(_,i)=>({timestamp:new Date(Date.UTC(2026,8,26,6)+i*1000).toISOString(),event_type:'network',source_ip:'198.51.100.9',destination_port:443}));
  const result=investigate(parseLogs(JSON.stringify(records)));
  assert.equal(result.event_count,5000);
  assert.equal(result.findings.length,0);
});
test('exports evidence for a large batch of standalone findings',()=>{
  const records=Array.from({length:1000},(_,i)=>({timestamp:new Date(Date.UTC(2026,8,26,6)+i*1000).toISOString(),event_type:'transfer',source_ip:'10.0.0.1',bytes_sent:50_000_000}));
  const events=parseLogs(JSON.stringify(records));
  const result=investigate(events);
  assert.equal(result.findings.length,1000);
  assert.equal(result.score,60);
  assert.equal(result.severity,'high');
  const report=reportMarkdown(result,events);
  assert.match(report,/Event 1000 \[/);
});
test('one critical authentication pattern yields critical overall risk',()=>{
  const records=[...Array.from({length:5},(_,i)=>({timestamp:t(i),event_type:'login_failed',source_ip:'203.0.113.10'})),
    {timestamp:t(6),event_type:'login_success',source_ip:'203.0.113.10'}];
  const result=investigate(parseLogs(JSON.stringify(records)));
  assert.equal(result.score,70);
  assert.equal(result.severity,'critical');
});
test('success after the fifth failure is retained even if another failure follows',()=>{
  const records=[...Array.from({length:5},(_,i)=>({timestamp:t(i),event_type:'login_failed',source_ip:'203.0.113.10'})),
    {timestamp:t(5),event_type:'login_success',source_ip:'203.0.113.10'},
    {timestamp:t(6),event_type:'login_failed',source_ip:'203.0.113.10'}];
  const result=investigate(parseLogs(JSON.stringify(records)));
  assert.equal(result.findings[0].severity,'critical');
  assert.deepEqual(result.findings[0].evidence,[1,2,3,4,5,6]);
  assert.equal(result.findings[0].last_seen,t(5));
});
test('separate authentication and port-sweep bursts produce separate findings',()=>{
  const base=Date.UTC(2026,8,26,6);
  const at=minute=>new Date(base+minute*60_000).toISOString();
  const auth=[...Array.from({length:5},(_,i)=>({timestamp:at(i),event_type:'login_failed',source_ip:'203.0.113.10'})),
    ...Array.from({length:5},(_,i)=>({timestamp:at(60+i),event_type:'login_failed',source_ip:'203.0.113.10'}))];
  const authFindings=investigate(parseLogs(JSON.stringify(auth))).findings;
  assert.equal(authFindings.filter(f=>f.rule==='AUTH-001').length,2);
  assert.deepEqual(authFindings.map(f=>f.evidence),[[1,2,3,4,5],[6,7,8,9,10]]);
  const scans=[...Array.from({length:8},(_,i)=>({timestamp:at(i/10),event_type:'network',source_ip:'198.51.100.1',destination_port:20+i})),
    ...Array.from({length:8},(_,i)=>({timestamp:at(60+i/10),event_type:'network',source_ip:'198.51.100.1',destination_port:100+i}))];
  assert.equal(investigate(parseLogs(JSON.stringify(scans))).findings.filter(f=>f.rule==='NET-002').length,2);
});
