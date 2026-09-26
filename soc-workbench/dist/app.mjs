import {parseLogs, investigate, reportMarkdown} from './detector.mjs';

const $ = id => document.getElementById(id);
const sampleTime = Date.now() - 30 * 60_000;
const stamp = minutes => new Date(sampleTime + minutes * 60_000).toISOString();
const sample = [
  ...Array.from({length:6},(_,i)=>({timestamp:stamp(i),event_type:'login',source_ip:'203.0.113.42',username:'admin',success:false,destination_port:22})),
  {timestamp:stamp(7),event_type:'login',source_ip:'203.0.113.42',username:'admin',success:true,destination_port:22},
  ...[21,22,23,25,80,443,8080,8443].map((port,i)=>({timestamp:stamp(8+i*.3),event_type:'network',source_ip:'198.51.100.17',destination_ip:'10.0.0.12',destination_port:port})),
  {timestamp:stamp(12),event_type:'process',source_ip:'10.0.0.12',process_name:'powershell.exe -EncodedCommand SQBFAFgA'},
  {timestamp:stamp(14),event_type:'transfer',source_ip:'10.0.0.12',destination_ip:'192.0.2.50',bytes_sent:72_000_000},
  {timestamp:stamp(16),event_type:'http',source_ip:'192.0.2.33',method:'GET',path:'/health',status:200}
];
let current={events:[],result:null,selected:null,filename:'sample-incident.json',aiBrief:null};
let investigationRevision=0;
const text=$('logs');
text.value=JSON.stringify(sample,null,2);

function escapeHTML(value) {return String(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
function fmt(iso) {return iso?new Date(iso).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit',second:'2-digit'}):'Time unknown';}
function setActive(id) { for(const item of ['sample-btn','file-btn','paste-btn']) $(item).classList.toggle('current',item===id); }
function setError(message) { $('error').textContent=message; $('error').hidden=!message; }
function analyze() {
  investigationRevision++;
  setError('');
  try {
    const events=parseLogs(text.value,current.filename);
    const result=investigate(events);
    current={...current,events,result,selected:result.findings[0]?.id||null,aiBrief:null};
    render();
    $('ai-brief').replaceChildren();
    $('input-meta').textContent=`${events.length} events parsed · ${result.findings.length} findings${result.undated_count?` · ${result.undated_count} undated (excluded from time-window rules)`:''}${result.unrecognized_count?` · ${result.unrecognized_count} unrecognized event types`:''}`;
  } catch(err) {setError(`${err instanceof Error?err.message:'Could not read the supplied logs.'} Previous results, if any, are still displayed.`);}
}
function render() {
  const {events,result}=current;
  $('risk-score').textContent=String(result.score);
  $('finding-count').textContent=String(result.findings.length);
  $('event-count').textContent=String(result.event_count);
  $('timeline-count').textContent=`${result.event_count} EVENTS`;
  $('download-report').disabled=false;$('download-json').disabled=false;
  const list=$('findings');list.replaceChildren();
  if(!result.findings.length) list.innerHTML='<div class="empty-list">No configured rule matched. Review the timeline and remember that absence of alerts does not prove safety.</div>';
  for(const f of result.findings) {
    const button=document.createElement('button'); button.type='button';
    button.className=`finding-card ${f.severity}${f.id===current.selected?' selected':''}`;
    button.dataset.findingId=f.id;
    button.setAttribute('aria-pressed',String(f.id===current.selected));
    button.innerHTML=`<span class="finding-bar"></span><span class="finding-content"><span class="finding-top"><strong>${escapeHTML(f.title)}</strong><span class="severity">${escapeHTML(f.severity)}</span></span><p>${escapeHTML(f.source)} · ${f.evidence.length} evidence event${f.evidence.length===1?'':'s'} · ${escapeHTML(f.rule)}</p></span>`;
    button.addEventListener('click',()=>{current.selected=f.id;renderFindingsSelection();renderDetail();});
    list.append(button);
  }
  $('timeline').replaceChildren();
  for(const e of result.timeline) {
    const row=document.createElement('div');row.className='timeline-row';
    row.innerHTML=`<span class="timeline-time">${escapeHTML(fmt(e.timestamp))}</span><span class="timeline-main"><strong>${escapeHTML(e.type.replaceAll('_',' '))} · ${escapeHTML(e.source)}</strong><span>${escapeHTML(e.summary)}</span></span>`;
    $('timeline').append(row);
  }
  renderDetail();
}
function renderFindingsSelection() {
  for(const button of $('findings').querySelectorAll('.finding-card')) {
    const selected=button.dataset.findingId===current.selected;
    button.classList.toggle('selected',!!selected);button.setAttribute('aria-pressed',String(!!selected));
  }
}
function renderDetail() {
  const f=current.result?.findings.find(item=>item.id===current.selected);
  if(!f) { $('detail').className='detail-empty';$('detail').textContent='No finding selected. Review the timeline for context.';return; }
  $('detail').className='detail-body';
  const evidence=f.evidence.slice(0,30).map(id=>current.events.find(e=>e.id===id)).filter(Boolean);
  $('detail').innerHTML=`<div class="detail-title"><h3>${escapeHTML(f.title)}</h3><span class="severity">${escapeHTML(f.severity)}</span></div>
    <div class="brief-meta"><span>${escapeHTML(f.id)} / ${escapeHTML(f.rule)}</span><span>${escapeHTML(f.tactic)}</span><span>${escapeHTML(f.confidence)} confidence</span><span>${escapeHTML(f.source)}</span></div>
    <p>${escapeHTML(f.explanation)}</p><h4>EVIDENCE · ${f.evidence.length} EVENTS</h4>
    <ul class="evidence-list">${evidence.map(e=>`<li><strong>#${e.id} · ${escapeHTML(fmt(e.timestamp))}</strong><br><code>${escapeHTML(e.raw.slice(0,350))}</code></li>`).join('')}</ul>
    <h4>ANALYST CHECKS</h4><ol class="steps">${f.next_steps.map(s=>`<li>${escapeHTML(s)}</li>`).join('')}</ol>`;
}
function download(name,data,type) {
  const url=URL.createObjectURL(new Blob([data],{type}));
  const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
function setFile(file) {
  if(!file) return;
  if(file.size>2*1024*1024){setError('Choose a file under 2 MB.');return;}
  if(!/\.(json|jsonl|csv|log|txt)$/i.test(file.name)){setError('Supported files: JSON, JSONL, CSV, LOG and TXT.');return;}
  const reader=new FileReader();
  reader.onload=()=>{text.value=String(reader.result||'');current.filename=file.name;$('file-name').textContent=file.name;$('input-meta').textContent=`${file.name} · ${Math.round(file.size/1024)} KB`;setActive('file-btn');setError('');analyze();};
  reader.onerror=()=>setError('Could not read this file.');reader.readAsText(file);
}
$('sample-btn').addEventListener('click',()=>{text.value=JSON.stringify(sample,null,2);current.filename='sample-incident.json';$('file-name').textContent=current.filename;setActive('sample-btn');analyze();});
$('file-btn').addEventListener('click',()=>$('file-input').click());
$('paste-btn').addEventListener('click',()=>{setActive('paste-btn');text.focus();});
$('file-input').addEventListener('change',e=>setFile(e.target.files?.[0]));
$('dropzone').addEventListener('click',()=>$('file-input').click());
$('dropzone').addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();$('file-input').click();}});
$('dropzone').addEventListener('dragover',e=>{e.preventDefault();e.dataTransfer.dropEffect='copy';});
$('dropzone').addEventListener('drop',e=>{e.preventDefault();setFile(e.dataTransfer.files?.[0]);});
$('analyze-btn').addEventListener('click',analyze);
$('download-report').addEventListener('click',()=>{if(current.result){let report=reportMarkdown(current.result,current.events);if(current.aiBrief){report+='\n\n## External AI analyst brief\n'+current.aiBrief.assessment+'\n\nCited event IDs: '+current.aiBrief.evidence_ids.join(', ')+'\n\nUncertainties:\n'+current.aiBrief.uncertainties.map(s=>'- '+s).join('\n')+'\n\nNext steps:\n'+current.aiBrief.next_steps.map(s=>'- '+s).join('\n');}download('sentinelai-incident-report.md',report,'text/markdown');}});
$('download-json').addEventListener('click',()=>{if(current.result)download('sentinelai-investigation.json',JSON.stringify({investigation:current.result,events:current.events,ai_brief:current.aiBrief},null,2),'application/json');});
async function checkAI() {
  try {const response=await fetch('/api/analyst',{cache:'no-store'});const data=await response.json();
    $('ai-status').textContent=data.configured?`OpenAI ${data.model} ready`:'API key not configured';
    $('ask-ai').disabled=!data.configured;
  } catch { $('ai-status').textContent='AI service unavailable';$('ask-ai').disabled=true; }
}
async function askAI() {
  if(!current.result)return;
  const revision=investigationRevision;
  const button=$('ask-ai');button.disabled=true;button.textContent='Reviewing evidence…';$('ai-error').hidden=true;
  const ids=new Set(current.result.findings.flatMap(f=>f.evidence));
  const selected=current.events.filter(e=>ids.has(e.id)).slice(0,40);
  const events=selected.length?selected:current.events.slice(0,40);
  try {
    const response=await fetch('/api/analyst',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({findings:current.result.findings.slice(0,20),events})});
    const data=await response.json();if(!response.ok)throw new Error(data.error||`AI request failed (${response.status})`);
    if(revision!==investigationRevision)return;
    current.aiBrief=data.brief;const b=data.brief;
    $('ai-brief').innerHTML=`<div class="ai-result"><h3>Model assessment</h3><p>${escapeHTML(b.assessment)}</p><h4>CITED EVENTS</h4><p>${b.evidence_ids.length?b.evidence_ids.map(id=>'#'+id).join(', '):'No specific event cited'}</p><h4>UNCERTAINTIES</h4><ul>${b.uncertainties.map(s=>`<li>${escapeHTML(s)}</li>`).join('')}</ul><h4>VALIDATION STEPS</h4><ul>${b.next_steps.map(s=>`<li>${escapeHTML(s)}</li>`).join('')}</ul></div>`;
  } catch(error) { if(revision===investigationRevision){$('ai-error').textContent=error instanceof Error?error.message:'AI review unavailable';$('ai-error').hidden=false;} }
  finally {button.disabled=false;button.textContent='Ask external AI';}
}
$('ask-ai').addEventListener('click',askAI);
analyze();
checkAI();
