// Learn Hub — interactive hacking topics
const esc=(s)=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const CATS=['Reconnaissance','Web Application','Network Attacks','Privilege Escalation','Exploitation','Post-Exploitation','Cryptography','Forensics & IR','Cloud & Container','Defense & Blue Team'];
const CAT_EMOJI={'Reconnaissance':'[R]','Web Application':'[W]','Network Attacks':'[N]','Privilege Escalation':'[PE]','Exploitation':'[EX]','Post-Exploitation':'[PX]','Cryptography':'[CR]','Forensics & IR':'[FR]','Cloud & Container':'[CL]','Defense & Blue Team':'[DF]'};
const RANKS=[[0,'Noob'],[500,'Script Kiddie'],[2000,'Hacker'],[5000,'Elite'],[10000,'L33t'],[20000,'Shadow'],[40000,'Ghost']];
const DIFF_LABEL={1:'Beginner',2:'Intermediate',3:'Advanced',4:'Expert',5:'Master'};
const DIFF_COLOR={1:'#3fb950',2:'#d29922',3:'#f85149',4:'#bc4dff',5:'#ff4d4d'};
const SK='sw_learn_progress';
const BADGES=[
{id:'first-blood',title:'First Blood',desc:'Complete your first topic',icon:'*',check:p=>p.completedTopics.length>=1},
{id:'ten-down',title:'Ten Down',desc:'Complete 10 topics',icon:'x10',check:p=>p.completedTopics.length>=10},
{id:'fifty',title:'Half Century',desc:'Complete 50 topics',icon:'50',check:p=>p.completedTopics.length>=50},
{id:'century',title:'Century',desc:'Complete 100 topics',icon:'100',check:p=>p.completedTopics.length>=100},
{id:'scholar',title:'Scholar',desc:'Earn 10000 XP',icon:'S',check:p=>p.xp>=10000},
{id:'legend',title:'Legend',desc:'Earn 40000 XP',icon:'L',check:p=>p.xp>=40000}];
function loadP(){try{return JSON.parse(localStorage.getItem(SK))||{completedTopics:[],xp:0};}catch(_){return {completedTopics:[],xp:0};}}
function saveP(p){try{localStorage.setItem(SK,JSON.stringify(p));}catch(_){}}
function getRank(xp){let r=RANKS[0];for(const[t,n]of RANKS)if(xp>=t)r=[t,n];return r[1];}
let TOPICS=[];
async function _loadTopics(){
  if(TOPICS.length)return;
  const r=await fetch('/data/topics.json');
  TOPICS=await r.json();
}

export async function renderLearnHub(main){
await _loadTopics();
const TOTAL_XP=TOPICS.reduce((s,t)=>s+t.xp,0);

const prog=loadP();
let fCat='',fDiff=0,search='';
function renderMain(){
const fl=TOPICS.filter(t=>{
if(fCat&&t.cat!==fCat)return false;
if(fDiff&&t.diff!==fDiff)return false;
if(search&&!t.title.toLowerCase().includes(search.toLowerCase())&&!t.cat.toLowerCase().includes(search.toLowerCase()))return false;
return true;});
const cc={};CATS.forEach(c=>{cc[c]={total:0,done:0};});
TOPICS.forEach(t=>{if(!cc[t.cat])cc[t.cat]={total:0,done:0};cc[t.cat].total++;if(prog.completedTopics.includes(t.id))cc[t.cat].done++;});
const rank=getRank(prog.xp),nr=RANKS.find(r=>r[0]>prog.xp);
main.innerHTML=`<div class="lh">
<h1 class="pg-h1">Learn Hub</h1>
<p class="muted pg-sub">${TOPICS.length} hands-on topics covering reconnaissance, exploitation, privilege escalation, post-exploitation, cryptography, forensics, cloud security, and defense. Each topic teaches a real technique with code you can run, then tests your understanding.</p>
<div class="lh-stats">
<div class="lh-st"><h3>Rank</h3><div class="v" style="color:var(--accent)">${esc(rank)}</div>${nr?`<div class="lh-bar"><div style="width:${Math.round((prog.xp/nr[0])*100)}%"></div></div><div style="font-size:.68rem;color:var(--mut)">${prog.xp}/${nr[0]} XP to ${nr[1]}</div>`:'<div style="font-size:.72rem;color:#3fb950">Max rank!</div>'}</div>
<div class="lh-st"><h3>XP</h3><div class="v" style="color:#3fb950">${prog.xp.toLocaleString()}</div><div style="font-size:.68rem;color:var(--mut)">${Math.round((prog.xp/TOTAL_XP)*100)}% of ${TOTAL_XP.toLocaleString()}</div></div>
<div class="lh-st"><h3>Completed</h3><div class="v">${prog.completedTopics.length}</div><div style="font-size:.68rem;color:var(--mut)">of ${TOPICS.length}</div></div>
</div>
<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0">${BADGES.map(b=>{const earned=b.check(prog);return '<div style="padding:6px 10px;border-radius:6px;font-size:.78rem;background:'+(earned?'var(--card,#161b22)':'transparent')+';border:1px solid '+(earned?'#3fb950':'var(--line,#30363d)')+';opacity:'+(earned?'1':'.4')+'" title="'+esc(b.desc)+'">'+(b.icon||'')+' '+esc(b.title)+'</div>';}).join('')}</div>
<div style="margin:16px 0">${CATS.map(c=>{const d=cc[c],p=d.total?Math.round((d.done/d.total)*100):0;return`<div class="lh-cb"><span class="nm">${CAT_EMOJI[c]||''} ${esc(c)}</span><div class="br"><div style="width:${p}%"></div></div><span class="pc">${d.done}/${d.total}</span></div>`;}).join('')}</div>
<input class="lh-inp" id="lhS" placeholder="Search ${TOPICS.length} topics..." value="${esc(search)}">
<div class="lh-chips">
<button class="lh-ch${fCat?'':' on'}" data-cat="">All</button>
${CATS.map(c=>`<button class="lh-ch${fCat===c?' on':''}" data-cat="${esc(c)}">${CAT_EMOJI[c]||''} ${esc(c)}</button>`).join('')}
</div>
<div class="lh-chips">
<button class="lh-ch${fDiff===0?' on':''}" data-diff="0">All levels</button>
<button class="lh-ch${fDiff===1?' on':''}" data-diff="1" style="border-color:#3fb95060">Beginner</button>
<button class="lh-ch${fDiff===2?' on':''}" data-diff="2" style="border-color:#d2992260">Intermediate</button>
<button class="lh-ch${fDiff===3?' on':''}" data-diff="3" style="border-color:#f8514960">Advanced</button>
<button class="lh-ch${fDiff===4?' on':''}" data-diff="4" style="border-color:#bc4dff60">Expert</button>
<button class="lh-ch${fDiff===5?' on':''}" data-diff="5" style="border-color:#ff4d4d60">Master</button>
</div>
<div class="lh-cnt">${fl.length} topics</div>
<div class="lh-grid">
${fl.map(t=>{const d=prog.completedTopics.includes(t.id);return`<div class="lh-c${d?' done':''}" data-tid="${esc(t.id)}">
${d?'<span class="lh-ck" style="color:#3fb950">done</span>':''}
<span class="cat">${CAT_EMOJI[t.cat]||''} ${esc(t.cat)}</span>
<h4>${esc(t.title)}</h4>
<div class="intro">${esc(t.intro)}</div>
<div class="ft"><span class="lh-df" style="color:${DIFF_COLOR[t.diff]};border:1px solid ${DIFF_COLOR[t.diff]}30">${DIFF_LABEL[t.diff]}</span><span class="lh-xp">${t.xp} XP</span></div>
</div>`;}).join('')}
</div></div>`;
const _s=main.querySelector('#lhS');if(_s)_s.oninput=e=>{search=e.target.value;renderMain();};
main.querySelectorAll('[data-cat]').forEach(b=>b.onclick=()=>{fCat=b.dataset.cat;renderMain();});
main.querySelectorAll('[data-diff]').forEach(b=>b.onclick=()=>{fDiff=+b.dataset.diff;renderMain();});
main.querySelectorAll('[data-tid]').forEach(c=>c.onclick=()=>openTopic(c.dataset.tid));
}
function openTopic(tid){
const t=TOPICS.find(x=>x.id===tid);if(!t)return;
const d=prog.completedTopics.includes(t.id);
const qs={};
main.innerHTML=`<div class="lh-tp">
<button class="lh-bk" id="lhB">← Back to topics</button>
<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
<div><span class="cat" style="font-size:.75rem">${CAT_EMOJI[t.cat]||''} ${esc(t.cat)}</span><h1 style="margin:4px 0;font-size:1.3rem">${esc(t.title)}</h1></div>
<div><span class="lh-df" style="color:${DIFF_COLOR[t.diff]};border:1px solid ${DIFF_COLOR[t.diff]}30">${DIFF_LABEL[t.diff]}</span><span class="lh-xp" style="margin-left:8px">${t.xp} XP</span>${d?' [done]':''}</div>
</div>
<div style="background:var(--card,#161b22);border:1px solid var(--line,#30363d);border-radius:8px;padding:16px;margin:16px 0">
<div style="font-size:.68rem;font-weight:600;color:var(--accent);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Overview</div>
<p style="margin:0;font-size:.92rem;line-height:1.8;color:var(--fg,#e6edf3)">${esc(t.intro)}</p>
${t.wild?`<div class="lh-wild" style="margin-top:12px">${esc(t.wild)}</div>`:''}
<div style="display:flex;gap:16px;margin-top:12px;font-size:.78rem;color:var(--mut)">
<span>${t.sections.filter(s=>s.type==='text').length} concept${t.sections.filter(s=>s.type==='text').length!==1?'s':''}</span>
<span>${t.sections.filter(s=>s.type==='code').length} code example${t.sections.filter(s=>s.type==='code').length!==1?'s':''}</span>
<span>${t.sections.filter(s=>s.type==='quiz').length} knowledge check${t.sections.filter(s=>s.type==='quiz').length!==1?'s':''}</span>
</div>
</div>
${t.sections.map((s,i)=>rSec(s,i)).join('')}
${d?'<div style="text-align:center;padding:16px;font-size:1.1rem;color:#3fb950">Completed · +'+t.xp+' XP earned</div>':`<button class="lh-done" id="lhD">Complete & earn ${t.xp} XP</button>`}
</div>`;
const _b=main.querySelector('#lhB');if(_b)_b.onclick=()=>renderMain();
main.querySelectorAll('.lh-qsel').forEach(o=>{o.onclick=()=>{
const qi=o.dataset.qi;if(qs[qi])return;
main.querySelectorAll(`.lh-qsel[data-qi="${qi}"]`).forEach(b=>b.classList.remove('sel'));
o.classList.add('sel');
const sub=main.querySelector(`.lh-qsub[data-qi="${qi}"]`);
if(sub){sub.disabled=false;sub.dataset.pick=o.dataset.idx;}
};});
main.querySelectorAll('.lh-qsub').forEach(sub=>{sub.onclick=()=>{
const qi=sub.dataset.qi;if(qs[qi]||sub.disabled)return;
const pick=+sub.dataset.pick;const ans=+sub.dataset.ans;
const picked=main.querySelector(`.lh-qsel[data-qi="${qi}"][data-idx="${pick}"]`);
if(pick===ans){picked.classList.add('ok');sub.textContent='Correct!';sub.classList.add('lh-qsub-ok');}
else{picked.classList.add('no');main.querySelectorAll(`.lh-qsel[data-qi="${qi}"][data-idx="${ans}"]`).forEach(c=>c.classList.add('ok'));sub.textContent='Incorrect - see the correct answer above';sub.classList.add('lh-qsub-no');}
qs[qi]=true;sub.disabled=true;
};});
main.querySelectorAll('.lh-cp').forEach(b=>{b.onclick=e=>{e.stopPropagation();const c=b.parentElement.querySelector('code');navigator.clipboard?.writeText(c.textContent);b.textContent='copied!';setTimeout(()=>b.textContent='copy',1000);};});
const db=main.querySelector('#lhD');
if(db)db.onclick=()=>{const totalQ=t.sections.filter(s=>s.type==='quiz').length;const answered=Object.keys(qs).length;if(totalQ>0&&answered<totalQ){db.textContent='Answer all knowledge checks first';db.classList.add('lh-qsub-no');setTimeout(()=>{db.textContent=`Complete & earn ${t.xp} XP`;db.classList.remove('lh-qsub-no');},1500);return;}if(!prog.completedTopics.includes(t.id)){prog.completedTopics.push(t.id);prog.xp+=t.xp;saveP(prog);}db.textContent=`+${t.xp} XP earned!`;db.disabled=true;db.classList.add('lhp');setTimeout(()=>renderMain(),1200);};
}
function rSec(s,i){
if(s.type==='text')return`<div class="lh-sec"><div style="font-size:.68rem;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Concept</div><p style="margin:0;font-size:.9rem;line-height:1.8">${esc(s.content)}</p></div>`;
if(s.type==='code')return`<div class="lh-sec"><div style="font-size:.68rem;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">${esc(s.lang||'code')} - try this in your terminal</div><div class="lh-code"><button class="lh-cp">copy</button><code>${esc(s.content)}</code></div></div>`;
if(s.type==='quiz')return`<div class="lh-sec"><div style="font-size:.68rem;font-weight:600;color:var(--accent);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Knowledge Check</div><p style="margin:0 0 12px;font-weight:600;font-size:.92rem">${esc(s.q)}</p><div class="lh-qo">${s.opts.map((o,j)=>`<button class="lh-qsel" data-qi="${i}" data-idx="${j}" data-ans="${s.ans}">${String.fromCharCode(65+j)}) ${esc(o)}</button>`).join('')}</div><button class="lh-qsub" data-qi="${i}" data-ans="${s.ans}" disabled>Submit Answer</button></div>`;
if(s.type==='task')return`<div class="lh-sec task"><div style="font-size:.68rem;font-weight:600;color:var(--accent);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Hands-on Challenge</div><p style="margin:0;font-size:.9rem;line-height:1.7">${esc(s.content)}</p></div>`;
if(s.type==='tip')return`<div class="lh-sec tip"><div style="font-size:.68rem;font-weight:600;color:#3fb950;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Pro Tip</div><p style="margin:0;font-size:.88rem;line-height:1.7">${esc(s.content)}</p></div>`;
if(s.type==='warning')return`<div class="lh-sec warning"><div style="font-size:.68rem;font-weight:600;color:#f85149;text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Warning</div><p style="margin:0;font-size:.88rem;line-height:1.7">${esc(s.content)}</p></div>`;
return'';
}
renderMain();
}
