// lightweight admin dashboard script
const API_BASE = '/admin/api';
async function api(path, method='GET', body=null){
  const headers = {};
  let hasBody = false;
  if(method !== 'GET' && method !== 'HEAD'){
    headers['Content-Type'] = 'application/json'; hasBody = true;
  }
  // session-based admin: include CSRF token from meta tag if present
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrf = meta ? meta.getAttribute('content') : null;
  if(csrf) headers['X-CSRFToken'] = csrf;
  const opts = {method, headers};
  if(body && hasBody) opts.body = JSON.stringify(body);
  try{
    const res = await fetch(API_BASE + path, opts);
    if(res.status === 403){
      // Show login modal to allow admin to sign in
      try{ document.getElementById('admin-login-modal').style.display = 'flex'; }catch(e){}
      return {status:'error', message: 'مطلوب تسجيل دخول المشرف (403)'};
    }
    return await res.json();
  }catch(e){
    return {status:'error', message: 'failed to contact server'};
  }
}

// helpers
function fmtTimeSmart(seconds){
  seconds = Number(seconds) || 0;
  if(seconds < 60) return `${seconds} ث`;
  const mins = Math.floor(seconds/60);
  if(mins < 60) return `${mins} د`;
  const hrs = Math.floor(mins/60);
  if(hrs < 24) return `${hrs} س`;
  const days = Math.floor(hrs/24);
  return `${days} يوم`;
}

function setStatusDot(el, ok){ el.style.background = ok ? 'green' : 'red'; }

// render users table
async function loadUsers(){
  const res = await api('/users');
  const tbody = document.querySelector('#users-table tbody');
  if(!tbody) return;
  while(tbody.firstChild) tbody.removeChild(tbody.firstChild);
  if(res.status !== 'success'){ tbody.appendChild(Object.assign(document.createElement('tr'),{innerHTML:`<td colspan="7">${res.message||'خطأ'}</td>`})); return; }
  res.users.forEach(u=>{
    const tr = document.createElement('tr');
    const id = document.createElement('td'); id.textContent = u.id;
    const un = document.createElement('td'); un.textContent = u.username || '';
    const em = document.createElement('td'); em.textContent = u.email || '';
    const pw = document.createElement('td');
    const pwInput = document.createElement('input'); pwInput.type='password'; pwInput.value = u.admin_plaintext_pw || '';
    pwInput.readOnly = true; pwInput.style.maxWidth='200px'; pw.appendChild(pwInput);
    const show = document.createElement('button'); show.className='btn small ghost'; show.textContent='عرض'; show.addEventListener('click', ()=>{ pwInput.type = pwInput.type==='password' ? 'text' : 'password'; show.textContent = pwInput.type==='password' ? 'عرض' : 'إخفاء'; }); pw.appendChild(show);
    const ver = document.createElement('td'); ver.textContent = (u.is_verified==1||u.is_verified==='1') ? 'نعم' : 'لا';
    const act = document.createElement('td'); act.textContent = (u.is_active==1||u.is_active==='1') ? 'نعم' : 'لا';
    const actions = document.createElement('td');
    const btnToggle = document.createElement('button'); btnToggle.className='btn'; btnToggle.textContent = (u.is_active==1||u.is_active==='1') ? 'تعطيل' : 'تفعيل';
    btnToggle.addEventListener('click', async ()=>{
      const want = btnToggle.textContent !== 'تعطيل';
      const r = await api(`/user/${u.id}`, 'PATCH', {is_active: want?1:0});
      if(r.status === 'success'){ act.textContent = want ? 'نعم' : 'لا'; btnToggle.textContent = want ? 'تعطيل' : 'تفعيل'; }
      alert(r.message||'تم');
    });
    const btnPw = document.createElement('button'); btnPw.className='btn'; btnPw.textContent='تعيين كلمة'; btnPw.addEventListener('click', async ()=>{
      const p = prompt('أدخل كلمة مرور جديدة (6+ أحرف):'); if(p===null) return; if(p.length<6){ alert('ضع 6 أحرف على الأقل'); return; }
      const r = await api(`/user/${u.id}/password`, 'POST', {password: p}); if(r.status==='success'){ pwInput.value = p; pwInput.type='password'; alert('تم'); } else alert(r.message||'فشل');
    });
    const btnEdit = document.createElement('button'); btnEdit.className='btn'; btnEdit.textContent='تعديل'; btnEdit.addEventListener('click', async ()=>{
      const newEmail = prompt('الإيميل الجديد', u.email); if(newEmail===null) return; const newUser = prompt('اسم المستخدم الجديد', u.username); const isv = confirm('تعيين موثق؟ OK=نعم'); const r = await api(`/user/${u.id}`, 'PATCH', {email:newEmail, username:newUser, is_verified: isv?1:0}); if(r.status==='success') loadUsers(); else alert(r.message||'فشل');
    });
    const btnDel = document.createElement('button'); btnDel.className='btn danger'; btnDel.textContent='حذف'; btnDel.addEventListener('click', async ()=>{ if(!confirm('تأكيد الحذف؟')) return; const r = await api('/users','DELETE',{ids:[u.id]}); if(r.status==='success') loadUsers(); else alert(r.message||'فشل'); });
    actions.appendChild(btnToggle); actions.appendChild(document.createTextNode(' ')); actions.appendChild(btnPw); actions.appendChild(document.createTextNode(' ')); actions.appendChild(btnEdit); actions.appendChild(document.createTextNode(' ')); actions.appendChild(btnDel);

    tr.appendChild(id); tr.appendChild(un); tr.appendChild(em); tr.appendChild(pw); tr.appendChild(ver); tr.appendChild(act); tr.appendChild(actions);
    tbody.appendChild(tr);
  });
}

// Files: list, delete, rename, upload
async function loadFiles(){
  const r = await api('/downloads');
  const el = document.getElementById('files-list'); if(!el) return; el.innerHTML='';
  if(r.status!=='success'){ el.textContent = r.message || 'خطأ'; return; }
  r.files.forEach(f=>{
    const row = document.createElement('div'); row.className='file-row';
    const left = document.createElement('div'); left.textContent = `${f.name} (${f.size} bytes)`;
    const controls = document.createElement('div');
    const a = document.createElement('a'); a.className='btn'; a.href = '/static/downloads/' + encodeURIComponent(f.name); a.target='_blank'; a.textContent='تنزيل';
    const del = document.createElement('button'); del.className='btn danger'; del.textContent='حذف'; del.addEventListener('click', async ()=>{ if(!confirm('حذف الملف؟')) return; const rr = await api('/downloads','DELETE',{name:f.name}); if(rr.status==='success') loadFiles(); else alert(rr.message||'فشل'); });
    const rename = document.createElement('button'); rename.className='btn'; rename.textContent='إعادة تسمية'; rename.addEventListener('click', async ()=>{ const nn = prompt('الاسم الجديد', f.name); if(nn===null) return; const rr = await api('/downloads/rename','POST',{old_name:f.name, new_name: nn}); if(rr.status==='success') loadFiles(); else alert(rr.message||'فشل'); });
    controls.appendChild(a); controls.appendChild(document.createTextNode(' ')); controls.appendChild(rename); controls.appendChild(document.createTextNode(' ')); controls.appendChild(del);
    row.appendChild(left); row.appendChild(controls); el.appendChild(row);
  });
}

async function uploadFile(){
  const inp = document.getElementById('upload-file'); if(!inp.files || inp.files.length===0){ alert('اختر ملف'); return; }
  const fd = new FormData(); fd.append('file', inp.files[0]);
  // include CSRF token header
  const meta = document.querySelector('meta[name="csrf-token"]'); const csrf = meta ? meta.getAttribute('content') : null;
  const headers = csrf ? {'X-CSRFToken': csrf} : {};
  const res = await fetch('/admin/api/downloads', {method:'POST', headers, body: fd});
  const j = await res.json(); if(j.status==='success') loadFiles(); else alert(j.message || 'فشل الرفع');
}

// site status and active users
async function loadSiteStatus(){
  const r = await api('/status');
  const dot = document.getElementById('site-dot'); const s = document.getElementById('site-status'); const meta = document.getElementById('site-meta');
  if(r.status !== 'success'){ s.textContent = r.message || 'خطأ'; setStatusDot(dot, false); meta.textContent=''; return; }
  const ok = true; // basic: if API returned success we treat as up
  s.textContent = `Up ${fmtTimeSmart(r.uptime)}`; setStatusDot(dot, ok);
  meta.textContent = `DB: ${r.db_size} bytes · Users: ${r.total_users} (verified ${r.verified_users})`;
}

async function loadActiveUsers(){
  const el = document.getElementById('active-users');
  const [rActive, rAll] = await Promise.all([ api('/active-users'), api('/users') ]);
  if(rActive.status!=='success'){ el.textContent = rActive.message || 'خطأ'; return; }
  const container = document.createElement('div');
  if(rActive.active && rActive.active.length){
    const h = document.createElement('div'); h.textContent = 'نشطون حالياً:'; container.appendChild(h);
    const ul = document.createElement('ul'); rActive.active.forEach(u=>{ const li = document.createElement('li'); li.textContent = `${u.username || '(مجهول)'} (${u.email||'--'}) — منذ ${fmtTimeSmart(u.seconds_ago)}`; ul.appendChild(li); }); container.appendChild(ul);
  } else {
    const p = document.createElement('div'); p.textContent = 'لا يوجد مستخدمين نشطين حالياً'; container.appendChild(p);
  }
  // show registered users who never logged in (last_seen null or 0)
  if(rAll.status === 'success'){
    const never = rAll.users.filter(u => !u.last_seen || u.last_seen === null);
    if(never.length){ const h2 = document.createElement('div'); h2.style.marginTop='8px'; h2.textContent = 'مسجّلون لكن لم يسجلوا دخول:'; const ul2 = document.createElement('ul'); never.forEach(u=>{ const li = document.createElement('li'); li.textContent = `${u.username || '(بدون)'} (${u.email||'--'})`; ul2.appendChild(li); }); container.appendChild(h2); container.appendChild(ul2); }
  }
  el.innerHTML=''; el.appendChild(container);
}

// messages
async function loadMessages(){
  const r = await api('/messages'); const el = document.getElementById('messages-area'); if(r.status!=='success'){ el.textContent = r.message || 'خطأ'; return; }
  if(!r.messages || r.messages.length===0){ el.textContent = 'لا توجد رسائل جديدة'; return; }
  const container = document.createElement('div'); r.messages.forEach(m=>{
    const card = document.createElement('div'); card.className='card'; card.style.marginBottom='8px';
    const head = document.createElement('div'); const name = document.createElement('strong'); name.textContent = m.name||'(بدون اسم)'; head.appendChild(name);
    if(m.replied){ const b = document.createElement('span'); b.style.color='green'; b.style.marginLeft='8px'; b.textContent='(تم الرد)'; head.appendChild(b); }
    const info = document.createElement('div'); info.textContent = `${m.email||'(غير مسجل)'} — منذ ${fmtTimeSmart(m.age_seconds)}`; head.appendChild(info);
    const body = document.createElement('div'); (m.message||'').split('\n').forEach((ln, i)=>{ body.appendChild(document.createTextNode(ln)); if(i < (m.message||'').split('\n').length-1) body.appendChild(document.createElement('br')); });
    const actions = document.createElement('div'); actions.style.marginTop='8px';
    const rep = document.createElement('button'); rep.className='btn'; rep.textContent='رد'; rep.addEventListener('click', ()=>{ document.getElementById('reply-modal').style.display='flex'; document.getElementById('reply-text').value=''; document.getElementById('reply-send').dataset.id = m.id; });
    const del = document.createElement('button'); del.className='btn danger'; del.textContent='حذف'; del.addEventListener('click', async ()=>{ if(!confirm('حذف الرسالة؟')) return; const rr = await api('/messages','DELETE',{id:m.id}); if(rr.status==='success') loadMessages(); else alert(rr.message||'فشل'); });
    actions.appendChild(rep); actions.appendChild(document.createTextNode(' ')); actions.appendChild(del);
    card.appendChild(head); card.appendChild(body); card.appendChild(actions); container.appendChild(card);
  }); el.innerHTML=''; el.appendChild(container);
}

// settings save
async function loadSettings(){ const r = await api('/settings'); if(r.status!=='success') return; const s = r.settings||{}; document.getElementById('setting-maintenance').checked = !!s.maintenance_mode; document.getElementById('setting-welcome').value = s.welcome_message || ''; }
async function saveSettings(){ const maintenance = document.getElementById('setting-maintenance').checked; const welcome = document.getElementById('setting-welcome').value; const r = await api('/settings','POST',{maintenance_mode: maintenance, welcome_message: welcome}); if(r.status==='success') alert('تم الحفظ'); else alert(r.message||'فشل'); }

// enable all users
async function enableAllUsers(){ if(!confirm('هل تود إعادة تفعيل جميع الحسابات؟')) return; const r = await api('/users/enable_all','POST',{}); alert(r.message||'تم'); loadUsers(); }

// reply send handlers
document.addEventListener('click', (e)=>{
  if(e.target && e.target.id === 'reply-cancel'){ document.getElementById('reply-modal').style.display='none'; }
  if(e.target && e.target.id === 'reply-send'){ (async ()=>{ const id = e.target.dataset.id; const reply = document.getElementById('reply-text').value.trim(); if(!reply){ alert('أدخل نص الرد'); return; } const r = await api('/messages/reply','POST',{id, reply}); if(r.status==='success') alert('تم'); else alert(r.message||'فشل'); document.getElementById('reply-modal').style.display='none'; loadMessages(); })(); }
});

// wire up UI buttons
document.addEventListener('DOMContentLoaded', ()=>{
  document.getElementById('btn-load').addEventListener('click', ()=>{ loadAll(); });
  const live = document.getElementById('live-updates'); let timer = null; live.addEventListener('change', (e)=>{ if(e.target.checked){ timer = setInterval(loadAll, 5000); } else { clearInterval(timer); } });
  document.getElementById('btn-enable-all').addEventListener('click', enableAllUsers);
  document.getElementById('btn-upload').addEventListener('click', uploadFile);
  document.getElementById('save-settings').addEventListener('click', saveSettings);
  // login modal handlers
  const loginModal = document.getElementById('admin-login-modal');
  const loginSubmit = document.getElementById('login-submit');
  const loginCancel = document.getElementById('login-cancel');
  if(loginCancel) loginCancel.addEventListener('click', ()=>{ loginModal.style.display = 'none'; });
  if(loginSubmit) loginSubmit.addEventListener('click', async ()=>{
    const u = document.getElementById('login-username').value.trim();
    const p = document.getElementById('login-password').value;
    if(!u || !p){ document.getElementById('login-msg').textContent = 'املأ الحقول'; return; }
    const r = await api('/login','POST',{username: u, password: p});
    if(r && r.status === 'success'){ loginModal.style.display = 'none'; loadAll(); }
    else { document.getElementById('login-msg').textContent = r.message || 'فشل تسجيل الدخول'; }
  });
  document.getElementById('reply-cancel').addEventListener('click', ()=>{ document.getElementById('reply-modal').style.display='none'; });
  // auto initial load
  setTimeout(loadAll, 200);
});

async function loadAll(){ await Promise.all([ loadUsers(), loadFiles(), loadSiteStatus(), loadActiveUsers(), loadMessages(), loadSettings() ]); }

