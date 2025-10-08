function postData(url = '', data = {}) {
  // attach CSRF token header when provided via meta tag
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrf = meta ? meta.getAttribute('content') : null;
  const headers = { 'Content-Type': 'application/json' };
  if (csrf) headers['X-CSRFToken'] = csrf;
  return fetch(url, {
    method: 'POST',
    credentials: 'same-origin',
    headers,
    body: JSON.stringify(data)
  }).then(async response => {
        const json = await response.json().catch(() => null);
        return { status: response.status, body: json };
    }).catch(err => ({ status: 0, body: { message: 'خطأ في الاتصال' } }));
}

function showMessage(msg, isError = false) {
    let el = document.getElementById('message-box');
    if (!el) {
        el = document.createElement('div');
        el.id = 'message-box';
        el.style.position = 'fixed';
        el.style.top = '20px';
        el.style.left = '50%';
        el.style.transform = 'translateX(-50%)';
        el.style.padding = '12px 18px';
        el.style.borderRadius = '8px';
        el.style.zIndex = 9999;
        document.body.appendChild(el);
    }
    el.style.background = isError ? '#ef4444' : '#10b981';
    el.style.color = '#fff';
    el.textContent = msg;
    setTimeout(() => el.remove(), 3500);
}

function showToast(msg, isError=false){
  const t = document.createElement('div');
  t.className = 'toast ' + (isError ? 'error' : 'success');
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 3500);
}

// attach global CSRF token if template injected it
if(window.csrf_token){
  // nothing needed; server uses cookie-based csrf
}

// override showFormMessage to use toast as fallback
function showFormMessage(msg, isError=false){
  const el = document.getElementById('form-message');
  if(!el){ showToast(msg, isError); return; }
  el.textContent = msg;
  el.className = 'message ' + (isError ? 'error' : 'success');
  setTimeout(()=>{ if(el) el.textContent=''; },4000);
}

// تسجيل الدخول
function loginUser() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    postData('/login', {username, password}).then(res => {
    if (res.status === 200) { showFormMessage(res.body.message); setTimeout(()=>location.reload(),700); return; }
    // 403 pending verification -> redirect to verify page with email if provided
    if (res.status === 403 && res.body && res.body.status === 'pending_verification'){
      showFormMessage(res.body.message, true);
      const em = res.body.email || document.getElementById('username')?.value;
      setTimeout(()=>{ location.href = '/verify?email=' + encodeURIComponent(em); }, 800);
      return;
    }
    showFormMessage(res.body?.message || 'خطأ', true);
    });
}

// تسجيل حساب جديد
function registerUser() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const email = document.getElementById('email').value; // إضافة البريد الإلكتروني
  postData('/register', {username, password, email}).then(res => {
    // If server returned 2xx and provided JSON, or returned 2xx HTML (body==null), treat as success
    if ((res.status >= 200 && res.status < 300) && (res.body === null || res.body?.status === 'pending_verification' || res.status === 201)) {
      // server created account and sent verification
      const msg = res.body?.message || 'تم إنشاء الحساب. تحقق من بريدك للرمز.';
      showFormMessage(msg);
            // redirect to verify page (server may provide canonical redirect URL)
            const redirectTo = res.body?.redirect || ('/verify?email=' + encodeURIComponent(email));
            setTimeout(()=>{ location.href = redirectTo; }, 800);
      return;
    }
    // show server error message (including 409 or validation errors)
    showFormMessage(res.body?.message || 'خطأ في التسجيل', true);
  });
}

// تواصل
function sendContact() {
  const message = (document.getElementById('message')||{}).value || '';
  const name = (document.getElementById('name')||{}).value || '';
  const email = (document.getElementById('email')||{}).value || '';
  if(!message || message.trim().length < 3){ showMessage('الرجاء كتابة رسالة صالحة', true); return; }
  // attempt AJAX submit first, include name/email when present
  postData('/contact', {name, email, message}).then(res => {
    if(res.body && res.body.status === 'success'){
      showMessage(res.body.message || 'تم الإرسال');
      document.getElementById('message').value = '';
      return;
    }
    // show server error (if available), otherwise fallback to form submit
    if(res.body && res.body.message){ showMessage(res.body.message, true); return; }
    document.getElementById('contact-form').submit();
  }).catch(()=>{ document.getElementById('contact-form').submit(); });
}

function clientValidateLogin(){
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value;
    if(!u || !p){ showFormMessage('الرجاء تعبئة اسم المستخدم وكلمة المرور', true); return false; }
    return true;
}

function clientValidateRegister(){
    const u = (document.getElementById('username')?.value || '').trim();
    const e = (document.getElementById('email')?.value || '').trim();
    const p = (document.getElementById('password')?.value || '');
    if(!u || !e || !p){ showFormMessage('الرجاء تعبئة جميع الحقول', true); return false; }
    if(u.includes('@')){ showFormMessage('اسم المستخدم لا يجب أن يحتوي @', true); return false; }
    if(!e.includes('@') || !e.includes('.')){ showFormMessage('البريد الإلكتروني غير صالح', true); return false; }
    if(p.length < 6){ showFormMessage('كلمة المرور قصيرة', true); return false; }
    return true;
}

// attach validation to register form submit
document.addEventListener('DOMContentLoaded', function(){
  const regForm = document.getElementById('register-form');
  if(regForm){
    // Always use AJAX for registration to ensure the verification flow runs
    regForm.addEventListener('submit', function(e){
      e.preventDefault();
      if(!clientValidateRegister()){ return; }
      if(typeof registerUser === 'function'){
        try{ registerUser(); }catch(err){ console.error('registerUser threw', err); showFormMessage('خطأ داخلي. افتح الكونسول.', true); }
      }
    });
  }
});

// submit verification code from verify.html
function submitVerification(evt){
  if(evt) evt.preventDefault();
  const email = document.getElementById('email')?.value || '';
  // if we have individual digits, assemble
  const codeEl = document.getElementById('code');
  const digitEls = document.querySelectorAll('.code-digit');
  let code = '';
  if(digitEls && digitEls.length){
    digitEls.forEach(d=> code += (d.value||'').trim());
    if(codeEl) codeEl.value = code;
  } else {
    code = document.getElementById('code')?.value || '';
  }
  if(!email || !code){ showFormMessage('الرجاء إدخال البريد والرمز', true); return false; }
  postData('/verify', {email: email, code: code}).then(res => {
    if(res.status >=200 && res.status < 300 && res.body && res.body.status === 'success'){
      showFormMessage(res.body.message || 'تم التحقق');
      setTimeout(()=>{ location.href = '/login'; },800);
      return;
    }
    showFormMessage(res.body?.message || 'خطأ في التحقق', true);
  });
  return false;
}

// code input UX: allow typing one digit per box, support paste
document.addEventListener('DOMContentLoaded', function(){
  const codeWrap = document.getElementById('code-inputs');
  if(!codeWrap) return;
  const inputs = Array.from(codeWrap.querySelectorAll('.code-digit'));
  inputs.forEach((inp, idx) => {
    inp.addEventListener('input', (e)=>{
      const v = inp.value.replace(/[^0-9]/g,''); inp.value = v;
      if(v.length === 1 && idx < inputs.length-1){ inputs[idx+1].focus(); }
    });
    inp.addEventListener('keydown', (e)=>{
      if(e.key === 'Backspace' && !inp.value && idx > 0){ inputs[idx-1].focus(); }
      if(e.key === 'ArrowLeft' && idx>0){ inputs[idx-1].focus(); }
      if(e.key === 'ArrowRight' && idx < inputs.length-1){ inputs[idx+1].focus(); }
    });
    inp.addEventListener('paste', (e)=>{
      e.preventDefault();
      const text = (e.clipboardData || window.clipboardData).getData('text') || '';
      const digits = text.replace(/\D/g,'').slice(0, inputs.length);
      for(let i=0;i<digits.length;i++){ inputs[i].value = digits[i]; }
      if(digits.length > 0 && digits.length < inputs.length) inputs[digits.length].focus();
    });
  });
  // focus first input on load
  setTimeout(()=>{ if(inputs[0]) inputs[0].focus(); }, 120);
});
