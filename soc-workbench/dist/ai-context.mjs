export function selectAIContext(allFindings, allEvents) {
  const findings=allFindings.slice(0,20);
  const ids=[];
  const seen=new Set();
  const maxEvidence=Math.max(0,...findings.map(f=>f.evidence.length));
  for(let index=0;index<maxEvidence && ids.length<40;index++) {
    for(const finding of findings) {
      const id=finding.evidence[index];
      if(Number.isInteger(id) && !seen.has(id)) {seen.add(id);ids.push(id);}
      if(ids.length===40) break;
    }
  }
  const eventById=new Map(allEvents.map(e=>[e.id,e]));
  const selected=ids.map(id=>eventById.get(id)).filter(Boolean);
  const events=selected.length?selected:allEvents.slice(0,40);
  const sentIds=new Set(events.map(e=>e.id));
  return {findings:findings.map(f=>({...f,evidence:f.evidence.filter(id=>sentIds.has(id))})),events};
}
