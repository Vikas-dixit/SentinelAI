const MINUTE = 60_000;

export function parseLogs(text, filename = '') {
  if (text.length > 2*1024*1024 || new TextEncoder().encode(text).byteLength > 2*1024*1024)
    throw new Error('Use at most 2 MB of log text per investigation.');
  const source = text.trim();
  if (!source) throw new Error('Paste logs or choose a file first.');
  let records;
  if (source.startsWith('[') || source.startsWith('{')) {
    let value;
    try {
      value = JSON.parse(source);
    } catch {
      records = source.split(/\r?\n/).filter(Boolean).map((line, i) => {
        try { return JSON.parse(line); }
        catch { throw new Error(`Invalid JSON on line ${i + 1}.`); }
      });
    }
    if (value !== undefined) {
      if (value && typeof value==='object' && !Array.isArray(value) && 'events' in value && !Array.isArray(value.events))
        throw new Error('The JSON events field must be an array.');
      records = Array.isArray(value) ? value : Array.isArray(value?.events) ? value.events : [value];
    }
  } else if (filename.toLowerCase().endsWith('.csv') || looksLikeCSV(source)) {
    const rows = parseCSV(source);
    const headers = rows.shift()?.map(s => s.trim().replace(/^\uFEFF/, '').toLowerCase()) || [];
    if (!headers.some(h => ['timestamp','time','@timestamp','date','timecreated','time_created'].includes(h)) || !headers.some(h => ['event_type','type','action','eventid','event_id'].includes(h)))
      throw new Error('CSV needs a timestamp and an event_type, type, action, or EventID column.');
    records = rows.filter(row => row.some(Boolean)).map((row, i) => {
      if (row.length !== headers.length) throw new Error(`CSV row ${i + 2} has ${row.length} columns; expected ${headers.length}.`);
      return Object.fromEntries(headers.map((h, column) => [h, row[column]]));
    });
  } else {
    records = source.split(/\r?\n/).filter(Boolean).map(parseTextLine).filter(Boolean);
  }
  if (!records.length) throw new Error('No security events found.');
  if (records.length > 5000) throw new Error('Use at most 5,000 events per investigation.');
  return records.map((record, i) => normalize(record, i));
}

function looksLikeCSV(source) {
  const header = source.split(/\r?\n/, 1)[0].split(',').map(s => s.trim().replace(/^\uFEFF/, '').replace(/^"|"$/g, '').toLowerCase());
  const known=new Set(['timestamp','time','@timestamp','date','timecreated','time_created','event_type','type','action','eventid','event_id','source_ip','src_ip','ipaddress','username','destination_port','bytes_sent']);
  return header.length>=2 && header.filter(h=>known.has(h)).length>=2;
}

function parseCSV(text) {
  const rows = []; let row = []; let cell = ''; let quoted = false; let closedQuote=false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && quoted && text[i + 1] === '"') { cell += '"'; i++; }
    else if (c === '"' && quoted) { quoted=false; closedQuote=true; }
    else if (c === '"') {
      if (cell || closedQuote) throw new Error('CSV contains an unexpected quote.');
      quoted=true;
    }
    else if (c === ',' && !quoted) { row.push(cell); cell = ''; closedQuote=false; }
    else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = ''; closedQuote=false;
    } else {
      if (closedQuote && c!==' ' && c!=='\t') throw new Error('CSV contains text after a closing quote.');
      cell += c;
    }
  }
  if (quoted) throw new Error('CSV contains an unclosed quote.');
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

function parseTextLine(line) {
  const apacheTime = line.match(/\[(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d\d:\d\d:\d\d)\s+([+-]\d{4})\]/);
  const time = apacheTime ? `${apacheTime[1]} ${apacheTime[2]} ${apacheTime[3]} ${apacheTime[4]} GMT${apacheTime[5].slice(0,3)}:${apacheTime[5].slice(3)}`
    : line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ][\d:.+-Z]+)/)?.[1];
  const ip = literalIP(line.match(/(?:from |src(?:_ip)?=|client=)(\[?[0-9a-f:.]+\]?)/i)?.[1]);
  const user = line.match(/(?:for (?:invalid user )?|user(?:name)?=)([\w.@-]+)/i)?.[1] || '';
  const port = Number(line.match(/(?:port |dpt=)(\d+)/i)?.[1] || 0);
  const http = line.match(/"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP\/[^\"]+"\s+(\d{3})/i);
  if (/Failed password|authentication failure|login failed/i.test(line)) return {timestamp: time, event_type:'login_failed', source_ip:ip, username:user, destination_port:port, raw:line};
  if (/Accepted password|Accepted publickey|login success/i.test(line)) return {timestamp:time, event_type:'login_success', source_ip:ip, username:user, destination_port:port, raw:line};
  if (http) return {timestamp:time, event_type:'http', source_ip:ip || literalIP(line.match(/^(\[?[0-9a-f:.]+\]?)\s/i)?.[1]), method:http[1], path:http[2], status:Number(http[3]), raw:line};
  if (/DPT=|port scan/i.test(line)) return {timestamp:time, event_type:'network', source_ip:ip, destination_port:port, raw:line};
  return {timestamp:time, event_type:'other', source_ip:ip, username:user, raw:line};
}

function literalIP(value) {
  const candidate=(value||'').replace(/^\[|\]$/g,'');
  if (candidate.includes(':')) {
    try { new URL(`http://[${candidate}]/`); return candidate; }
    catch { return ''; }
  }
  const octets=candidate.split('.');
  return octets.length===4 && octets.every(x=>/^\d{1,3}$/.test(x) && Number(x)<=255) ? candidate : '';
}

function identity(value,max) {
  const label=String(value??'').trim().slice(0,max);
  return /^(?:-|unknown|n\/a|null|none|undefined)$/i.test(label)?'':label;
}

function normalize(r, i) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new Error(`Event ${i + 1} must be an object.`);
  const obj=value=>value && typeof value==='object' && !Array.isArray(value) ? value : {};
  const ecsEvent=obj(r.event), ecsSource=obj(r.source), ecsDestination=obj(r.destination);
  const ecsUser=obj(r.user), ecsProcess=obj(r.process), ecsHttp=obj(r.http);
  const ecsRequest=obj(ecsHttp.request), ecsResponse=obj(ecsHttp.response), ecsUrl=obj(r.url);
  const rawTime = r.timestamp ?? r.time ?? r['@timestamp'] ?? r.date ?? r.TimeCreated ?? r.timecreated ?? r.time_created;
  const timestamp=parseTimestamp(rawTime);
  // Missing or invalid dates must not become fabricated time-window evidence.
  const explicitType=r.event_type ?? r.type ?? r.action;
  const type = String(explicitType ?? ecsEvent.action ?? 'other').toLowerCase().replace(/[ -]/g,'_');
  const outcome=String(ecsEvent.outcome||'').toLowerCase();
  const successValue=r.success ?? r.outcome ?? outcome;
  const success=['true','1','success'].includes(String(successValue).toLowerCase());
  const failure=['false','0','failure','failed'].includes(String(successValue).toLowerCase());
  const authType = {
    auth_failure:'login_failed', authentication_failure:'login_failed', failed_login:'login_failed', login_failure:'login_failed',
    auth_success:'login_success', authentication_success:'login_success', successful_login:'login_success', login_succeeded:'login_success'
  };
  const windowsEventId = Number(r.event_id ?? r.EventID ?? r.eventId ?? r.eventid);
  const windowsAuthType = [4624,4625].includes(windowsEventId) && ['other','windows_security','security'].includes(type)
    ? (windowsEventId===4624?'login_success':'login_failed') : null;
  const categories=Array.isArray(ecsEvent.category)?ecsEvent.category:[ecsEvent.category];
  const ecsType=categories.includes('authentication') && ['success','failure'].includes(outcome)
    ? (outcome==='success'?'login_success':'login_failed')
    : categories.includes('web')?'http'
    : categories.includes('network')?'network':null;
  const port=Number(r.destination_port ?? r.dst_port ?? r.port ?? ecsDestination.port ?? 0);
  const bytes=Number(r.bytes_sent ?? r.bytes_out ?? ecsSource.bytes ?? 0);
  const status=Number(r.status ?? r.status_code ?? ecsResponse.status_code ?? 0);
  return {
    id: i + 1, timestamp, type: windowsAuthType || (type === 'login' ? (success ? 'login_success' : failure ? 'login_failed' : 'login_unknown') : authType[type] || (explicitType==null?ecsType:null) || type),
    source_ip: identity(r.source_ip ?? r.src_ip ?? r.src ?? r.ip ?? r.IpAddress ?? r.ipaddress ?? r.ip_address ?? ecsSource.ip,80),
    destination_ip: String(r.destination_ip ?? r.dst_ip ?? r.dst ?? ecsDestination.ip ?? '').slice(0,80),
    username: identity(r.username ?? (typeof r.user==='string'?r.user:undefined) ?? r.TargetUserName ?? r.targetusername ?? r.target_user_name ?? ecsUser.name,100),
    destination_port: Number.isInteger(port) && port>=1 && port<=65535 ? port : 0,
    process_name: String(r.process_name ?? (typeof r.process==='string'?r.process:undefined) ?? r.command ?? ecsProcess.command_line ?? ecsProcess.name ?? '').slice(0,250),
    bytes_sent: Number.isFinite(bytes) && bytes>=0 ? bytes : 0,
    method: String(r.method ?? ecsRequest.method ?? '').slice(0,20), path: String(r.path ?? (typeof r.url==='string'?r.url:undefined) ?? ecsUrl.path ?? '').slice(0,400),
    status: Number.isInteger(status) && status>=100 && status<=599 ? status : 0,
    raw: String(r.raw ?? JSON.stringify(r)).slice(0,1200)
  };
}

function parseTimestamp(value) {
  if (value==null || value==='') return null;
  if (typeof value==='number' || /^\d+$/.test(String(value))) {
    const numeric=Number(value);
    if (!Number.isFinite(numeric) || (typeof value==='string' && !/^\d{10,13}$/.test(value))) return null;
    const date=new Date(numeric<100_000_000_000?numeric*1000:numeric);
    return isNaN(+date)?null:date.toISOString();
  }
  if (typeof value!=='string') return null;
  // Syslog omits the year. A date well ahead of now is likely from last year.
  const syslog=/^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d$/.test(value);
  const now=new Date();
  let date=new Date(syslog?`${now.getFullYear()} ${value}`:value);
  if (syslog && +date > +now + 24*60*60_000) date=new Date(`${now.getFullYear()-1} ${value}`);
  return isNaN(+date)?null:date.toISOString();
}

export function investigate(events) {
  const ordered = [...events].sort((a,b) => (a.timestamp ? Date.parse(a.timestamp) : Infinity) - (b.timestamp ? Date.parse(b.timestamp) : Infinity));
  const findings = [];
  const groups = new Map();
  for (const event of ordered) {
    const key = event.source_ip || event.username;
    if (!key) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(event);
  }
  function add(rule, title, severity, confidence, evidence, explanation, nextSteps, tactic) {
    if (!evidence.length) return;
    findings.push({id:`F-${String(findings.length+1).padStart(3,'0')}`,rule,title,severity,confidence,
      source:evidence[0].source_ip || evidence[0].username || 'unknown',
      first_seen:evidence[0].timestamp,last_seen:evidence.at(-1).timestamp,
      evidence:evidence.map(e=>e.id),explanation,next_steps:nextSteps,tactic});
  }
  for (const [source, items] of groups) {
    const failures = items.filter(e => e.timestamp && e.type === 'login_failed');
    const usedSuccesses=new Set();
    for(const cluster of rollingClusters(failures,15*MINUTE,5)) {
      const thresholdTime=Date.parse(cluster[4].timestamp);
      const laterSuccess = items.find(e => e.timestamp && e.type === 'login_success' && !usedSuccesses.has(e.id) && Date.parse(e.timestamp) >= thresholdTime && Date.parse(e.timestamp) - thresholdTime <= 30*MINUTE);
      if(laterSuccess) usedSuccesses.add(laterSuccess.id);
      const supportingFailures=laterSuccess?cluster.filter(e=>Date.parse(e.timestamp)<=Date.parse(laterSuccess.timestamp)):cluster;
      add('AUTH-001',laterSuccess?'Successful login after repeated failures':'Repeated authentication failures',laterSuccess?'critical':'high',laterSuccess?'high':'medium',laterSuccess?[...supportingFailures,laterSuccess]:cluster,
        `${source} produced ${supportingFailures.length} failed logins in 15 minutes${laterSuccess?' followed by a successful login':''}. This pattern warrants account and source review.`,
        ['Validate whether the source and account activity were authorized.','Review related authentication events and reset credentials if compromise is confirmed.','Apply rate limiting or MFA where appropriate.'],'Credential Access');
    }
    const network = items.filter(e=>e.timestamp && e.source_ip && e.destination_port>0 && ['network','connection','firewall'].includes(e.type));
    for(const ports of rollingDistinctPortClusters(network,5*MINUTE,8)) add('NET-002','Multi-port connection sweep','high','medium',ports,
      `${source} contacted ${new Set(ports.map(e=>e.destination_port)).size} distinct ports within five minutes.`,
      ['Confirm whether this is an approved scanner.','Review firewall and endpoint logs for follow-on access.','Restrict the source if unauthorized.'],'Discovery');
    const web = items.filter(e=>e.timestamp && e.source_ip && e.type==='http');
    const probes = web.filter(e=>/\b(401|403|404|500)\b/.test(String(e.status)) || /(\.\.|%2e|union(?:%20|\+| )select|<script|%3cscript|\/admin|\/\.env)/i.test(e.path));
    for(const webCluster of rollingClusters(probes,10*MINUTE,5)) add('WEB-003','Repeated web probing','medium','medium',webCluster,
      `${source} generated ${webCluster.length} error or suspicious-path requests in ten minutes.`,
      ['Inspect requested paths and response bodies.','Check WAF and application logs for exploit evidence.','Block only after validating the source is unauthorized.'],'Reconnaissance');
  }
  for (const e of ordered) {
    if (e.bytes_sent >= 50_000_000) add('DATA-004','Large outbound transfer','high','low',[e],
      `${(e.bytes_sent/1_000_000).toFixed(1)} MB outbound transfer recorded. Size alone does not prove exfiltration.`,
      ['Validate destination and expected workload.','Compare transfer with baseline and data-access logs.','Preserve related endpoint and network telemetry.'],'Exfiltration');
    if (/(powershell|pwsh).*\s-(enc|encodedcommand)\b|certutil.*-urlcache|curl.*\|\s*(sh|bash)/i.test(e.process_name))
      add('PROC-005','Suspicious command pattern','high','medium',[e],
        'The process command matches a commonly abused execution pattern; investigate context before taking action.',
        ['Capture process tree and command line.','Review parent process, user, and script content.','Isolate the host if malicious activity is confirmed.'],'Execution');
  }
  const rank={critical:4,high:3,medium:2,low:1};
  findings.sort((a,b)=>rank[b.severity]-rank[a.severity] || (a.first_seen || '').localeCompare(b.first_seen || ''));
  const byRule=new Map();
  for(const finding of findings) {
    const group=byRule.get(finding.rule)||{weight:0,count:0};
    group.weight=Math.max(group.weight,({critical:70,high:40,medium:15,low:7}[finding.severity]||0));
    group.count++;
    byRule.set(finding.rule,group);
  }
  const score=Math.min(100,Math.round([...byRule.values()].reduce((total,{weight,count})=>
    total+weight+Math.min(weight/2,Math.max(0,count-1)*3),0)));
  return {generated_at:new Date().toISOString(),event_count:events.length,undated_count:events.filter(e=>!e.timestamp).length,
    unrecognized_count:events.filter(e=>e.type==='other').length,unknown_outcome_count:events.filter(e=>e.type==='login_unknown').length,findings,score,
    severity:score>=70?'critical':score>=40?'high':score>=15?'medium':'low',
    timeline:ordered.map(e=>({id:e.id,timestamp:e.timestamp,type:e.type,source:e.source_ip||e.username||'unknown',summary:eventSummary(e)}))};
}

function rollingClusters(items,windowMs,min) {
  const clusters=[];
  let end=0;
  for (let start=0;start<items.length;) {
    if(end<start) end=start;
    while(end<items.length && Date.parse(items[end].timestamp)-Date.parse(items[start].timestamp)<=windowMs) end++;
    if(end-start>=min) { clusters.push(items.slice(start,end)); start=end; }
    else start++;
  }
  return clusters;
}
function rollingDistinctPortClusters(items,windowMs,min) {
  const clusters=[];
  let end=0;
  const counts=new Map();
  for(let start=0;start<items.length;) {
    while(end<items.length && Date.parse(items[end].timestamp)-Date.parse(items[start].timestamp)<=windowMs) {
      const port=items[end].destination_port;
      counts.set(port,(counts.get(port)||0)+1);
      end++;
    }
    if(counts.size>=min) { clusters.push(items.slice(start,end)); start=end; counts.clear(); continue; }
    const port=items[start].destination_port;
    const next=counts.get(port)-1;
    if(next) counts.set(port,next); else counts.delete(port);
    start++;
  }
  return clusters;
}
function eventSummary(e) {
  if(e.type==='http') return `${e.method||'HTTP'} ${e.path||'/'} → ${e.status||'?'}`;
  if(e.type.startsWith('login')) return `${e.type.replace('_',' ')}${e.username?' · '+e.username:''}`;
  if(e.process_name) return e.process_name;
  if(e.bytes_sent) return `${(e.bytes_sent/1_000_000).toFixed(1)} MB to ${e.destination_ip||'destination'}`;
  return e.destination_port?`Connection to port ${e.destination_port}`:e.type;
}

export function reportMarkdown(result, events) {
  const eventById=new Map(events.map(e=>[e.id,e]));
  const lines=['# SentinelAI Incident Investigation','',`Generated: ${result.generated_at}`,`Events analyzed: ${result.event_count}`,`Events without a valid timestamp: ${result.undated_count || 0}`,`Login events with unknown outcome: ${result.unknown_outcome_count || 0}`,`Events with an unrecognized type: ${result.unrecognized_count || 0}`,`Risk score: ${result.score}/100 (${result.severity})`,'',
    '## Scope and method','Rule-based triage of supplied logs. Findings are hypotheses requiring analyst validation; no external enrichment or live endpoint action was performed.','',
    '## Findings'];
  if(!result.findings.length) lines.push('No configured detection rule matched. This does not establish that the activity is benign.');
  for(const f of result.findings) {
    lines.push('',`### ${f.id} — ${f.title}`,`Severity: ${f.severity} | Confidence: ${f.confidence} | Rule: ${f.rule} | Tactic: ${f.tactic}`,
      `Source: ${f.source} | Window: ${f.first_seen || 'unknown'} to ${f.last_seen || 'unknown'}`,'',f.explanation,'','Evidence:');
    for(const id of f.evidence.slice(0,25)) { const e=eventById.get(id); if(e) lines.push(`- Event ${id} [${e.timestamp || 'time unknown'}]: ${e.raw.replace(/[\r\n]+/g,' ').slice(0,300)}`); }
    if(f.evidence.length>25) lines.push(`- ${f.evidence.length-25} further matching events omitted from this text report.`);
    lines.push('','Recommended validation:',...f.next_steps.map(s=>`- ${s}`));
  }
  lines.push('','## Limitations','Rules cover selected auth, network, web, process, and transfer patterns. Missing context can cause false positives or false negatives. Events without a valid timestamp are excluded from time-window correlation. Unrecognized event types remain in the timeline; standalone process and transfer fields can still match.');
  return lines.join('\n');
}
