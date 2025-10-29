(async function(){
  const loginBtn = document.getElementById('login');
  const userEl = document.getElementById('user');
  const passEl = document.getElementById('pass');
  const status = document.getElementById('loginStatus');
  const createBtn = document.getElementById('create');
  const clearBtn = document.querySelector('button[style*="clear"]') || document.getElementById('clear');
  const codeEl = document.getElementById('code');
  const titleEl = document.getElementById('title');
  const out = document.getElementById('out');
  const meta = document.getElementById('meta');
  const loaderLink = document.getElementById('loaderLink');
  const copyBtn = document.getElementById('copyBtn');

  let sessionToken = null;

  loginBtn.addEventListener('click', async ()=>{
    status.textContent = 'logging in...';
    try{
      const res = await fetch('/api/admin/login', { method:'POST', headers:{ 'content-type':'application/json' }, body: JSON.stringify({ username: userEl.value, password: passEl.value }) });
      const j = await res.json();
      if (!res.ok){ status.textContent = j.error || 'login failed'; return; }
      sessionToken = j.sessionToken;
      status.textContent = 'ok';
    }catch(e){ status.textContent = 'network'; }
  });

  clearBtn.addEventListener('click', ()=>{ codeEl.value=''; titleEl.value=''; out.textContent='paste obf code and press create. loader link will appear here.'; meta.style.display='none'; });

  copyBtn.addEventListener('click', async ()=>{
    const url = loaderLink.href;
    if(!url) return;
    try { await navigator.clipboard.writeText(url); copyBtn.textContent='copied'; setTimeout(()=>copyBtn.textContent='copy',1200); }catch(e){ copyBtn.textContent='unable'; setTimeout(()=>copyBtn.textContent='copy',1200); }
  });

  createBtn.addEventListener('click', async ()=>{
    if(!sessionToken){ out.textContent='not authenticated'; return; }
    const obfCode = codeEl.value.trim();
    if(!obfCode){ out.textContent='paste obf payload'; return; }
    out.textContent = 'creating...';
    try{
      const res = await fetch('/api/create', { method:'POST', headers:{ 'content-type':'application/json', 'x-session-token': sessionToken }, body: JSON.stringify({ title: titleEl.value||'', obfCode }) });
      const j = await res.json();
      if (!res.ok){ out.textContent = 'error: '+(j.error || JSON.stringify(j)); return; }
      const loader = j.rawUrl;
      loaderLink.href = loader; loaderLink.textContent = loader; meta.style.display='flex';
      out.textContent = 'created. give loader url to executor only.';
    }catch(e){ out.textContent='network error'; }
  });
})();
