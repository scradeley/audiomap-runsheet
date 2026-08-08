import { readFile, writeFile } from 'node:fs/promises';

const PASSWORD = 'antari';
const src = await readFile(new URL('./source.html', import.meta.url), 'utf8');

// --- split: everything up to </head>, and the panels payload ---
const headEnd = src.indexOf('</head>') + '</head>'.length;
const head = src.slice(0, headEnd);

const startMark = '<!-- COVER -->';
const endMark = '<!-- BOTTOM STEP BAR -->';
const startIdx = src.indexOf(startMark);
const endIdx = src.indexOf(endMark);
if (startIdx < 0 || endIdx < 0) throw new Error('markers not found');
const payloadHtml = src.slice(startIdx, endIdx).trim();  // the 9 panels

// --- encrypt with WebCrypto (identical API to the browser) ---
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const ITER = 150000;

const baseKey = await crypto.subtle.importKey('raw', enc.encode(PASSWORD), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey(
  { name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' },
  baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
);
const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(payloadHtml));

const b64 = (u8) => Buffer.from(u8).toString('base64');
const SALT = b64(salt), IV = b64(iv), DATA = b64(new Uint8Array(ctBuf));

// --- self-test: decrypt round-trip + wrong-password must fail ---
async function decrypt(pw, saltB64, ivB64, dataB64) {
  const dec = new TextDecoder();
  const b = (s) => Uint8Array.from(Buffer.from(s, 'base64'));
  const bk = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  const k = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b(saltB64), iterations: ITER, hash: 'SHA-256' },
    bk, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b(ivB64) }, k, b(dataB64));
  return dec.decode(pt);
}
const ok = await decrypt(PASSWORD, SALT, IV, DATA);
if (ok !== payloadHtml) throw new Error('round-trip mismatch');
let wrongFailed = false;
try { await decrypt('wrong', SALT, IV, DATA); } catch { wrongFailed = true; }
if (!wrongFailed) throw new Error('wrong password did NOT fail');
console.log('SELF-TEST OK · payload', payloadHtml.length, 'chars · ct', DATA.length, 'b64');

// --- emit gated index.html ---
const gated = head + `
<body>

<div class="progress" id="progress"></div>
<button class="theme-btn" id="themeBtn" aria-label="Toggle theme">◐</button>

<div class="gate" id="gate">
  <div class="gate-card">
    <div class="gate-mark">◆</div>
    <p class="gate-kick">AudioMap</p>
    <h1 class="gate-title">Demo Run Sheet</h1>
    <form id="gateForm" autocomplete="off">
      <input id="pw" type="password" inputmode="text" placeholder="Password"
             autocapitalize="off" autocorrect="off" spellcheck="false" aria-label="Password">
      <button type="submit">Enter</button>
    </form>
    <p class="gate-err" id="gateErr">&nbsp;</p>
  </div>
</div>

<div id="deck" hidden></div>

<nav class="bar" id="navbar" hidden><div class="bar-scroll" id="barScroll"></div></nav>

<style>
  .gate {
    position:fixed; inset:0; z-index:50; background:var(--bg);
    display:grid; place-items:center; padding:24px;
    padding-top:calc(env(safe-area-inset-top) + 24px);
  }
  .gate-card { width:100%; max-width:340px; text-align:center; }
  .gate-mark { font-family:var(--mono); font-size:42px; color:var(--signal); margin-bottom:8px; }
  .gate-kick { font-family:var(--mono); font-size:15px; letter-spacing:.2em; text-transform:uppercase; color:var(--signal); margin:0 0 8px; }
  .gate-title { font-size:38px; margin:0 0 30px; letter-spacing:-0.02em; font-weight:780; }
  #gateForm { display:flex; flex-direction:column; gap:12px; }
  #pw {
    font-family:var(--sans); font-size:21px; text-align:center;
    color:var(--ink); background:var(--panel); border:1px solid var(--line);
    border-radius:14px; padding:18px 18px; outline:none; width:100%;
  }
  #pw:focus { border-color:var(--signal); }
  #gateForm button {
    font-family:var(--mono); font-size:18px; font-weight:700; letter-spacing:.04em;
    color:var(--bg); background:var(--signal); border:0; border-radius:14px;
    padding:18px; cursor:pointer; width:100%;
  }
  .gate-err { font-family:var(--mono); font-size:15px; color:#ff6b6b; margin:16px 0 0; min-height:20px; }
</style>

<script>
(function(){
  var SALT="${SALT}", IV="${IV}", DATA="${DATA}", ITER=${ITER};
  var enc=new TextEncoder(), dec=new TextDecoder();
  function b(s){ return Uint8Array.from(atob(s), function(c){return c.charCodeAt(0);}); }

  async function decrypt(pw){
    var bk=await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
    var k=await crypto.subtle.deriveKey(
      {name:'PBKDF2', salt:b(SALT), iterations:ITER, hash:'SHA-256'},
      bk, {name:'AES-GCM', length:256}, false, ['decrypt']);
    var pt=await crypto.subtle.decrypt({name:'AES-GCM', iv:b(IV)}, k, b(DATA));
    return dec.decode(pt);
  }

  function reveal(html){
    var deck=document.getElementById('deck');
    deck.innerHTML=html; deck.hidden=false;
    var gate=document.getElementById('gate'); if(gate) gate.remove();
    document.getElementById('navbar').hidden=false;
    initRunsheet();
  }

  async function tryPw(pw, onFail){
    try {
      var html=await decrypt(pw);
      try { localStorage.setItem('rs_pw', pw); } catch(e){}
      reveal(html);
    } catch(e){ if(onFail) onFail(); }
  }

  var form=document.getElementById('gateForm');
  form.addEventListener('submit', function(e){
    e.preventDefault();
    var pw=document.getElementById('pw').value.trim();
    document.getElementById('gateErr').textContent='\\u00a0';
    tryPw(pw, function(){
      document.getElementById('gateErr').textContent='Incorrect — try again';
      document.getElementById('pw').select();
    });
  });

  // auto-unlock within the same session
  try {
    var cached=localStorage.getItem('rs_pw');
    if(cached) tryPw(cached, function(){ try{localStorage.removeItem('rs_pw');}catch(e){} });
  } catch(e){}

  // theme toggle (works pre- and post-unlock)
  document.getElementById('themeBtn').addEventListener('click', function(){
    var r=document.documentElement, cur=r.getAttribute('data-theme')||'dark';
    r.setAttribute('data-theme', cur==='dark'?'light':'dark');
    var m=document.querySelector('meta[name=theme-color]');
    if(m) m.setAttribute('content', cur==='dark'?'#f4f6f8':'#0c0f13');
  });

  // ---- run sheet nav (runs after content is injected) ----
  function initRunsheet(){
    var panels=Array.prototype.slice.call(document.querySelectorAll('.panel'));
    var bar=document.getElementById('barScroll');
    var progress=document.getElementById('progress');
    panels.forEach(function(p,i){
      var btn=document.createElement('button');
      btn.innerHTML=(i===0?'<span class="bn">\\u25c6</span>':'<span class="bn">'+i+'</span>')
                    +'<span>'+p.dataset.label+'</span>';
      btn.addEventListener('click', function(){
        document.getElementById(p.id).scrollIntoView({behavior:'smooth', block:'start'});
      });
      bar.appendChild(btn);
    });
    var btns=Array.prototype.slice.call(bar.children);
    function setActive(idx){
      btns.forEach(function(b,i){ b.classList.toggle('active', i===idx); });
      var el=btns[idx]; if(el) el.scrollIntoView({inline:'center', block:'nearest', behavior:'smooth'});
      progress.style.width=(idx/(panels.length-1))*100+'%';
    }
    var io=new IntersectionObserver(function(entries){
      entries.forEach(function(e){
        if(e.isIntersecting){ var idx=panels.indexOf(e.target); if(idx>=0) setActive(idx); }
      });
    }, {rootMargin:'-45% 0px -45% 0px', threshold:0});
    panels.forEach(function(p){ io.observe(p); });
    setActive(0);
    window.scrollTo(0,0);
  }
})();
</script>
</body>
</html>`;

await writeFile(new URL('./index.html', import.meta.url), gated, 'utf8');
console.log('WROTE gated index.html');
