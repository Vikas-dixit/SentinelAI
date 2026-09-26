const MINUTE = 60_000;

export function parseLogs(text, filename = '') {
  const source = text.trim();
  if (!source) throw new Error('Paste logs or choose a file first.');
  let records;
  if (source.startsWith('[') || source.startsWith('{')) {
    try {
      const value = JSON.parse(source);
      records = Array.isArray(value) ? value : Array.isArray(value.events) ? value.events : [value];
    } catch {
      records = source.split(/\r?\n/).filter(Boolean).map((line, i) => {
        try { return JSON.parse(line); }
        catch { throw new Error(`Invalid JSON on line ${i + 1}.`); }
      });
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
  return header.length >= 2 && header.some(h => ['timestamp','time','@timestamp','date','timecreated','time_created'].includes(h))
    && header.some(h => ['event_type','type','action','eventid','event_id'].includes(h));
}

function parseCSV(text) {
  const rows = []; let row = []; let cell = ''; let quoted = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"' && quoted && text[i + 1] === '"') { cell += '"'; i++; }
    else if (c === '"') quoted = !quoted;
    else if (c === ',' && !quoted) { row.push(cell); cell = ''; }
    else if ((c === '\n' || c === '\r') && !quoted) {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += c;
  }
  if (quoted) throw new Error('CSV contains an unclosed quote.');
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows;
}

function parseTextLine(line) {
  const apacheTime = line.match(/\[(\d{1,2})\/([A-Z][a-z]{2})\/(\d{4}):(\d\d:\d\d:\d\d)\s+([+-]\d{4})\]/);
  const time = apacheTime ? `${apacheTime[1]} ${apacheTime[2]} ${apacheTime[3]} ${apacheTime[4]} GMT${apacheTime[5].slice(0,3)}:${apacheTime[5].slice(3)}`
    : line.match(/^([A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d|\d{4}-\d\d-\d\d[T ][\d:.+-Z]+)/)?.[1];
  const ip = line.match(/(?:from |src(?:_ip)?=|client=)(\[?[0-9a-f:.]+\]?)/i)?.[1]?.replace(/^\[|\]$/g,'') || '';
  const user = line.match(/(?:for (?:invalid user )?|user(?:name)?=)([\w.@-]+)/i)?.[1] || '';
  const port = Number(line.match(/(?:port |dpt=)(\d+)/i)?.[1] || 0);
  const http = line.match(/"(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP\/[^\"]+"\s+(\d{3})/i);
  if (/Failed password|authentication failure|login failed/i.test(line)) return {timestamp: time, event_type:'login_failed', source_ip:ip, username:user, destination_port:port, raw:line};
  if (/Accepted password|Accepted publickey|login success/i.test(line)) return {timestamp:time, event_type:'login_success', source_ip:ip, username:user, destination_port:port, raw:line};
  if (http) return {timestamp:time, event_type:'http', source_ip:ip || line.match(/^(\[?[0-9a-f:.]+\]?)\s/i)?.[1]?.replace(/^\[|\]$/g,''), method:http[1], path:http[2], status:Number(http[3]), raw:line};
  if (/DPT=|port scan/i.test(line)) return {timestamp:time, event_type:'network', source_ip:ip, destination_port:port, raw:line};
  return {timestamp:time, event_type:'other', source_ip:ip, username:user, raw:line};
}

function normalize(r, i) {
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new Error(`Event ${i + 1} must be an object.`);
  const rawTime = r.timestamp ?? r.time ?? r['@timestamp'] ?? r.date ?? r.TimeCreated ?? r.timecreated ?? r.time_created;
  const syslogTime = typeof rawTime === 'string' && /^[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d$/.test(rawTime);
  const parsed = rawTime ? new Date(syslogTime ? `${new Date().getFullYear()} ${rawTime}` : rawTime) : null;
  let timestamp = parsed && !isNaN(+parsed) ? parsed.toISOString() : null;
  // Syslog timestamps omit a year. Use the current year for display only.
  if (rawTime && isNaN(Date.parse(rawTime))) {
    const guess = new Date(`${new Date().getFullYear()} ${rawTime}`);
    timestamp = isNaN(+guess) ? null : guess.toISOString();
  }
  // Missing or invalid dates must not become fabricated time-window evidence.
  const type = String(r.event_type ?? r.type ?? r.action ?? 'other').toLowerCase().replace(/[ -]/g,'_');
  const success = r.success === true || String(r.success).toLowerCase() === 'true';
  const authType = {
    auth_failure:'login_failed', authentication_failure:'login_failed', failed_login:'login_failed', login_failure:'login_failed',
    auth_success:'login_success', authentication_success:'login_success', successful_login:'login_success', login_succeeded:'login_success'
  };
  const windowsEventId = Number(r.event_id ?? r.EventID ?? r.eventId ?? r.eventid);
  const windowsAuthType = [4624,4625].includes(windowsEventId) && ['other','windows_security','security'].includes(type)
    ? (windowsEventId===4624?'login_success':'login_failed') : null;
  return {
    id: i + 1, timestamp, type: windowsAuthType || (type === 'login' ? (success ? 'login_success' : 'login_failed') : authType[type] || type),
    source_ip: String(r.source_ip ?? r.src_ip ?? r.src ?? r.ip ?? r.IpAddress ?? r.ipaddress ?? r.ip_address ?? '').slice(0,80),
    destination_ip: String(r.destination_ip ?? r.dst_ip ?? r.dst ?? '').slice(0,80),
    username: String(r.username ?? r.user ?? r.TargetUserName ?? r.targetusername ?? r.target_user_name ?? '').slice(0,100),
    destination_port: Number(r.destination_port ?? r.dst_port ?? r.port ?? 0) || 0,
    process_name: String(r.process_name ?? r.process ?? r.command ?? '').slice(0,250),
    bytes_sent: Number(r.bytes_sent ?? r.bytes_out ?? 0) || 0,
    method: String(r.method ?? '').slice(0,20), path: String(r.path ?? r.url ?? '').slice(0,400),
    status: Number(r.status ?? r.status_code ?? 0) || 0,
    raw: String(r.raw ?? JSON.stringify(r)).slice(0,1200)
  };
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
    const cluster = rollingCluster(failures,15*MINUTE,5);
    if (cluster) {
      const laterSuccess = items.find(e => e.timestamp && e.type === 'login_success' && Date.parse(e.timestamp) >= Date.parse(cluster.at(-1).timestamp) && Date.parse(e.timestamp) - Date.parse(cluster.at(-1).timestamp) <= 30*MINUTE);
      add('AUTH-001',laterSuccess?'Successful login after repeated failures':'Repeated authentication failures',laterSuccess?'critical':'high',laterSuccess?'high':'medium',laterSuccess?[...cluster,laterSuccess]:cluster,
        `${source} produced ${cluster.length} failed logins in 15 minutes${laterSuccess?' followed by a successful login':''}. This pattern warrants account and source review.`,
        ['Validate whether the source and account activity were authorized.','Review related authentication events and reset credentials if compromise is confirmed.','Apply rate limiting or MFA where appropriate.'],'Credential Access');
    }
    const network = items.filter(e=>e.timestamp && e.source_ip && e.destination_port>0 && ['network','connection','firewall'].includes(e.type));
    const ports = rollingDistinctPorts(network,5*MINUTE,8);
    if (ports) add('NET-002','Multi-port connection sweep','high','medium',ports,
      `${source} contacted ${new Set(ports.map(e=>e.destination_port)).size} distinct ports within five minutes.`,
      ['Confirm whether this is an approved scanner.','Review firewall and endpoint logs for follow-on access.','Restrict the source if unauthorized.'],'Discovery');
    const web = items.filter(e=>e.timestamp && e.source_ip && e.type==='http');
    const probes = web.filter(e=>/\b(401|403|404|500)\b/.test(String(e.status)) || /(\.\.|%2e|union(?:%20|\+| )select|<script|%3cscript|\/admin|\/\.env)/i.test(e.path));
    const webCluster = rollingCluster(probes,10*MINUTE,5);
    if (webCluster) add('WEB-003','Repeated web probing','medium','medium',webCluster,
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
  const score=Math.min(100,findings.reduce((n,f)=>n+({critical:45,high:27,medium:15,low:7}[f.severity]||0),0));
  return {generated_at:new Date().toISOString(),event_count:events.length,undated_count:events.filter(e=>!e.timestamp).length,
    unrecognized_count:events.filter(e=>e.type==='other').length,findings,score,
    severity:score>=70?'critical':score>=40?'high':score>=15?'medium':'low',
    timeline:ordered.map(e=>({id:e.id,timestamp:e.timestamp,type:e.type,source:e.source_ip||e.username||'unknown',summary:eventSummary(e)}))};
}

function rollingCluster(items,windowMs,min) {
  for (let start=0;start<items.length;start++) {
    let end=start;
    while(end<items.length && Date.parse(items[end].timestamp)-Date.parse(items[start].timestamp)<=windowMs) end++;
    if(end-start>=min) return items.slice(start,end);
  }
  return null;
}
function rollingDistinctPorts(items,windowMs,min) {
  for(let start=0;start<items.length;start++) {
    const subset=[];const ports=new Set();
    for(let end=start;end<items.length && Date.parse(items[end].timestamp)-Date.parse(items[start].timestamp)<=windowMs;end++) {subset.push(items[end]);ports.add(items[end].destination_port);}
    if(ports.size>=min) return subset;
  }
  return null;
}
function eventSummary(e) {
  if(e.type==='http') return `${e.method||'HTTP'} ${e.path||'/'} → ${e.status||'?'}`;
  if(e.type.startsWith('login')) return `${e.type.replace('_',' ')}${e.username?' · '+e.username:''}`;
  if(e.process_name) return e.process_name;
  if(e.bytes_sent) return `${(e.bytes_sent/1_000_000).toFixed(1)} MB to ${e.destination_ip||'destination'}`;
  return e.destination_port?`Connection to port ${e.destination_port}`:e.type;
}

export function reportMarkdown(result, events) {
  const lines=['# SentinelAI Incident Investigation','',`Generated: ${result.generated_at}`,`Events analyzed: ${result.event_count}`,`Events without a valid timestamp: ${result.undated_count || 0}`,`Events with an unrecognized type: ${result.unrecognized_count || 0}`,`Risk score: ${result.score}/100 (${result.severity})`,'',
    '## Scope and method','Rule-based triage of supplied logs. Findings are hypotheses requiring analyst validation; no external enrichment or live endpoint action was performed.','',
    '## Findings'];
  if(!result.findings.length) lines.push('No configured detection rule matched. This does not establish that the activity is benign.');
  for(const f of result.findings) {
    lines.push('',`### ${f.id} — ${f.title}`,`Severity: ${f.severity} | Confidence: ${f.confidence} | Rule: ${f.rule} | Tactic: ${f.tactic}`,
      `Source: ${f.source} | Window: ${f.first_seen || 'unknown'} to ${f.last_seen || 'unknown'}`,'',f.explanation,'','Evidence:');
    for(const id of f.evidence.slice(0,25)) { const e=events.find(item=>item.id===id); if(e) lines.push(`- Event ${id} [${e.timestamp || 'time unknown'}]: ${e.raw.replace(/[\r\n]+/g,' ').slice(0,300)}`); }
    if(f.evidence.length>25) lines.push(`- ${f.evidence.length-25} further matching events omitted from this text report.`);
    lines.push('','Recommended validation:',...f.next_steps.map(s=>`- ${s}`));
  }
  lines.push('','## Limitations','Rules cover selected auth, network, web, process, and transfer patterns. Missing context can cause false positives or false negatives. Events without a valid timestamp are excluded from time-window correlation. Unrecognized event types remain in the timeline; standalone process and transfer fields can still match.');
  return lines.join('\n');
}
