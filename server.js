const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const app = express();

app.use(cors());
app.use(express.json());

const DB = './db.json';
function db() {
  if (!fs.existsSync(DB)) {
    const d = { accounts: [], logs: [] };
    fs.writeFileSync(DB, JSON.stringify(d, null, 2));
    return d;
  }
  return JSON.parse(fs.readFileSync(DB));
}
function save(d) { fs.writeFileSync(DB, JSON.stringify(d, null, 2)); }

// ── ADMIN CREDENTIALS ─────────────────────────────────────────────────────────
const ADMIN_USER = process.env.ADMIN_USER || 'brodie';
const ADMIN_PASS = process.env.ADMIN_PASS || 'brodie1234';

// ── ADMIN LOGIN ───────────────────────────────────────────────────────────────
app.post('/admin/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USER && password === ADMIN_PASS)
    return res.json({ success: true });
  res.status(401).json({ success: false });
});

// ── ADMIN AUTH MIDDLEWARE ─────────────────────────────────────────────────────
function adminAuth(req, res, next) {
  const { username, password } = req.headers;
  if (username === ADMIN_USER && password === ADMIN_PASS) return next();
  res.status(401).json({ error: 'Unauthorized' });
}

// ══════════════════════════════════════════════════════════════════════════════
// DYLIB ENDPOINT — /api/login
// Called by the dylib with: { username, password, hwid, version }
// Must return: { success: true/false, expiry_date: "YYYY-MM-DD", message: "..." }
// ══════════════════════════════════════════════════════════════════════════════
app.post('/api/login', (req, res) => {
  const { username, password, hwid, version } = req.body;

  if (!username || !password || !hwid) {
    return res.json({ success: false, message: 'Missing fields' });
  }

  const d = db();
  const account = d.accounts.find(a => a.username === username);

  if (!account) {
    logEvent(d, username, hwid, false, 'User not found');
    save(d);
    return res.json({ success: false, message: 'User not found' });
  }

  if (account.password !== password) {
    logEvent(d, username, hwid, false, 'Wrong password');
    save(d);
    return res.json({ success: false, message: 'Wrong password' });
  }

  if (!account.active) {
    logEvent(d, username, hwid, false, 'Account disabled');
    save(d);
    return res.json({ success: false, message: 'Account disabled' });
  }

  // Check expiry
  if (account.expiry_date) {
    const expiry = new Date(account.expiry_date);
    if (new Date() > expiry) {
      logEvent(d, username, hwid, false, 'License expired');
      save(d);
      return res.json({ success: false, message: 'Your license has expired!' });
    }
  }

  // HWID lock — max devices check
  if (!account.hwids) account.hwids = [];
  const known = account.hwids.find(h => h.hwid === hwid);
  if (!known) {
    if (account.hwids.length >= (account.max_devices || 1)) {
      logEvent(d, username, hwid, false, 'Max devices reached');
      save(d);
      return res.json({ success: false, message: `Max devices (${account.max_devices || 1}) reached. Contact discord.gg/brodie` });
    }
    account.hwids.push({ hwid, first_seen: new Date().toISOString() });
  }

  account.last_login = new Date().toISOString();
  logEvent(d, username, hwid, true, 'Login success');
  save(d);

  // Format expiry_date as YYYY-MM-DD for dylib timer
  const expiry_date = account.expiry_date
    ? account.expiry_date.substring(0, 10)
    : null;

  return res.json({
    success: true,
    expiry_date: expiry_date,
    message: `Welcome ${username}!`
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// DYLIB ENDPOINT — /api/use_token
// Called when user wants to unban device using a token
// ══════════════════════════════════════════════════════════════════════════════
app.post('/api/use_token', (req, res) => {
  const { username, password, hwid, token } = req.body;
  if (!username || !password) return res.json({ success: false, message: 'Missing fields' });

  const d = db();
  const account = d.accounts.find(a => a.username === username && a.password === password);
  if (!account) return res.json({ success: false, message: 'Invalid credentials' });

  // Reset HWID (unban device)
  account.hwids = [];
  if (!account.hwids) account.hwids = [];
  account.hwids.push({ hwid, first_seen: new Date().toISOString() });
  save(d);

  return res.json({ success: true, tokens_left: 1, message: 'Device reset successfully!' });
});

// ── ADMIN: get accounts ───────────────────────────────────────────────────────
app.get('/admin/accounts', adminAuth, (req, res) => {
  const d = db();
  res.json(d.accounts.map(a => ({ ...a, password: '••••' })));
});

// ── ADMIN: create account ─────────────────────────────────────────────────────
app.post('/admin/accounts', adminAuth, (req, res) => {
  const { username, password, days, max_devices = 1, note = '' } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  const d = db();
  if (d.accounts.find(a => a.username === username))
    return res.status(400).json({ error: 'Username exists' });
  const expiry_date = days
    ? new Date(Date.now() + parseInt(days) * 86400000).toISOString()
    : null;
  const acc = {
    id: crypto.randomUUID(),
    username, password, active: true,
    created_at: new Date().toISOString(),
    expiry_date, max_devices, note,
    hwids: [], last_login: null
  };
  d.accounts.push(acc);
  save(d);
  res.json({ ...acc, password: '••••' });
});

// ── ADMIN: update account ─────────────────────────────────────────────────────
app.patch('/admin/accounts/:id', adminAuth, (req, res) => {
  const d = db();
  const a = d.accounts.find(a => a.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Not found' });
  Object.assign(a, req.body);
  save(d);
  res.json({ ...a, password: '••••' });
});

// ── ADMIN: delete account ─────────────────────────────────────────────────────
app.delete('/admin/accounts/:id', adminAuth, (req, res) => {
  const d = db();
  d.accounts = d.accounts.filter(a => a.id !== req.params.id);
  save(d);
  res.json({ success: true });
});

// ── ADMIN: reset devices ──────────────────────────────────────────────────────
app.post('/admin/accounts/:id/reset', adminAuth, (req, res) => {
  const d = db();
  const a = d.accounts.find(a => a.id === req.params.id);
  if (!a) return res.status(404).json({ error: 'Not found' });
  a.hwids = [];
  save(d);
  res.json({ success: true });
});

// ── ADMIN: stats ──────────────────────────────────────────────────────────────
app.get('/admin/stats', adminAuth, (req, res) => {
  const d = db(); const now = new Date();
  res.json({
    total: d.accounts.length,
    active: d.accounts.filter(a => a.active && !(a.expiry_date && new Date(a.expiry_date) < now)).length,
    expired: d.accounts.filter(a => a.expiry_date && new Date(a.expiry_date) < now).length,
    disabled: d.accounts.filter(a => !a.active).length,
    logins: (d.logs || []).filter(l => l.success).length
  });
});

// ── ADMIN: logs ───────────────────────────────────────────────────────────────
app.get('/admin/logs', adminAuth, (req, res) => {
  const d = db();
  res.json((d.logs || []).slice(-200).reverse());
});

function logEvent(d, username, hwid, success, reason) {
  if (!d.logs) d.logs = [];
  d.logs.push({ username, hwid, success, reason, ts: new Date().toISOString() });
  if (d.logs.length > 500) d.logs = d.logs.slice(-500);
}



// ── DYLIB SHORT ROUTES (patched endpoints) ────────────────────────────────────
app.post('/lg', (req, res) => {
  req.url = '/api/login';
  app.handle(req, res);
});
app.post('/tk', (req, res) => {
  req.url = '/api/use_token';
  app.handle(req, res);
});

// ── HOMEPAGE — serves the admin dashboard ────────────────────────────────────
const DASHBOARD_HTML = `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Brodie Scripts Admin</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;}
body{background:#000;color:#fff;font-family:-apple-system,BlinkMacSystemFont,sans-serif;min-height:100vh;}

#login{display:flex;align-items:center;justify-content:center;min-height:100vh;
  background:radial-gradient(ellipse at top,#1a004466,transparent),#000;}
.lbox{width:340px;max-width:92vw;background:#0a0010;border:1px solid #3a1a5a;
  border-radius:22px;padding:38px 28px;text-align:center;}
.logo{width:72px;height:72px;border-radius:50%;
  background:linear-gradient(135deg,#5500aa,#8833cc);
  display:flex;align-items:center;justify-content:center;
  font-size:27px;font-weight:900;color:#fff;margin:0 auto 16px;box-shadow:0 0 35px #6600cc77;}
.brand{font-size:24px;font-weight:800;letter-spacing:2px;color:#cc88ff;margin-bottom:4px;}
.sub{font-size:12px;color:#553366;margin-bottom:28px;}
.inp{display:block;width:100%;background:#050010;border:1.5px solid #2a0a4a;border-radius:12px;
  color:#fff;font-size:16px;padding:14px 16px;margin-bottom:14px;outline:none;-webkit-appearance:none;}
.inp:focus{border-color:#8833cc;}
.inp::placeholder{color:#2a1a3a;}
.lbtn{width:100%;background:linear-gradient(135deg,#5500aa,#8833cc);border:none;border-radius:12px;
  color:#fff;font-size:17px;font-weight:800;letter-spacing:1px;padding:16px;cursor:pointer;
  -webkit-appearance:none;box-shadow:0 4px 20px #6600cc55;}
.lerr{color:#ff4466;font-size:13px;margin-top:14px;padding:10px 14px;background:#1a0010;
  border-radius:10px;border:1px solid #4a0020;display:none;}

#app{display:none;padding-bottom:30px;}
.hdr{background:#050010;border-bottom:1px solid #1a0a2a;padding:16px 18px;
  display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:50;}
.hdr-ico{width:38px;height:38px;border-radius:10px;flex-shrink:0;
  background:linear-gradient(135deg,#5500aa,#8833cc);display:flex;align-items:center;
  justify-content:center;font-size:15px;font-weight:900;color:#fff;}
.hdr-brand{font-size:18px;font-weight:800;letter-spacing:1px;color:#cc88ff;}
.hdr-sub{font-size:11px;color:#553366;}
.hdr-out{margin-left:auto;background:#0d0015;border:1px solid #2a0a4a;border-radius:8px;
  color:#884499;font-size:12px;font-weight:600;padding:7px 12px;cursor:pointer;-webkit-appearance:none;}

.wrap{padding:16px;max-width:700px;margin:0 auto;}
.ptitle{font-size:22px;font-weight:800;letter-spacing:1px;color:#cc88ff;margin:14px 0 4px;}
.psub{font-size:12px;color:#553366;margin-bottom:16px;}

.stats{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:20px;}
.stat{background:#080010;border:1px solid #1a0a2a;border-radius:14px;padding:14px;}
.sl{font-size:9px;text-transform:uppercase;letter-spacing:.08em;color:#553366;margin-bottom:5px;}
.sv{font-size:24px;font-weight:800;font-family:monospace;color:#aa55ff;}

.bigbtn{width:100%;background:linear-gradient(135deg,#5500aa,#8833cc);border:none;border-radius:12px;
  color:#fff;font-size:16px;font-weight:700;padding:15px;cursor:pointer;margin-bottom:18px;
  -webkit-appearance:none;box-shadow:0 4px 15px #6600cc44;}

.srch{width:100%;background:#080010;border:1.5px solid #1a0a2a;border-radius:10px;color:#fff;
  font-size:14px;padding:11px 14px;outline:none;margin-bottom:14px;-webkit-appearance:none;}
.srch:focus{border-color:#8833cc;}
.srch::placeholder{color:#2a1a3a;}

.card{background:#080010;border:1px solid #1a0a2a;border-radius:14px;margin-bottom:10px;overflow:hidden;}
.ch{padding:13px 15px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid #0d0018;}
.cn{font-size:15px;font-weight:700;color:#eeddff;}
.cnote{font-size:11px;color:#553366;margin-top:2px;}
.cb{padding:10px 15px;display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.cinfo{font-size:12px;color:#553366;}
.cinfo b{color:#aa88cc;}
.ca{padding:9px 15px;border-top:1px solid #0d0018;display:flex;gap:8px;flex-wrap:wrap;}

.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:11px;font-weight:700;}
.bga{background:#002211;color:#00ff88;border:1px solid #004422;}
.bgr{background:#1a0010;color:#ff3355;border:1px solid #4a001a;}
.bgy{background:#1a1000;color:#ffaa00;border:1px solid #4a3000;}
.tchip{font-family:monospace;font-size:11px;color:#aa55ff;background:#1a0a2a;padding:3px 9px;
  border-radius:6px;border:1px solid #2a0a4a;}

.btn{display:inline-flex;align-items:center;padding:7px 13px;border-radius:9px;font-size:13px;
  font-weight:700;cursor:pointer;border:none;-webkit-appearance:none;}
.bo{background:#0d0015;border:1px solid #2a0a4a;color:#aa88cc;}
.bd{background:#1a0010;border:1px solid #4a001a;color:#ff3355;}

.empty{text-align:center;padding:50px 20px;color:#553366;}
.empty-i{font-size:36px;margin-bottom:10px;opacity:.5;}

.ov{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);backdrop-filter:blur(6px);
  z-index:200;align-items:center;justify-content:center;padding:16px;}
.ov.on{display:flex;}
.modal{background:#080010;border:1px solid #3a1a5a;border-radius:20px;padding:26px 22px;
  width:100%;max-width:420px;max-height:90vh;overflow-y:auto;}
.mh{font-size:19px;font-weight:800;color:#cc88ff;margin-bottom:18px;letter-spacing:1px;}
.fg{margin-bottom:13px;}
.fg label{font-size:10px;font-weight:700;color:#553366;text-transform:uppercase;
  letter-spacing:.08em;margin-bottom:6px;display:block;}
.fg input,.fg select{width:100%;background:#050010;border:1.5px solid #1a0a2a;border-radius:10px;
  color:#fff;font-size:15px;padding:12px 13px;outline:none;-webkit-appearance:none;}
.fg input:focus{border-color:#8833cc;}
.fg input::placeholder{color:#2a1a3a;}
.fgr{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.mac{display:flex;gap:10px;margin-top:18px;}
.mac .btn{flex:1;justify-content:center;padding:13px;font-size:15px;}
.bp{background:linear-gradient(135deg,#5500aa,#8833cc);color:#fff;}

#toast{position:fixed;top:16px;left:50%;transform:translateX(-50%) translateY(-70px);
  background:#0d0018;border:1px solid #3a1a5a;border-radius:12px;padding:11px 20px;font-size:14px;
  z-index:999;pointer-events:none;white-space:nowrap;box-shadow:0 4px 20px #00000088;
  transition:transform .3s cubic-bezier(.175,.885,.32,1.275);}
#toast.on{transform:translateX(-50%) translateY(0);}
</style>
</head>
<body>

<div id="login">
  <div class="lbox">
    <div class="logo">BS</div>
    <div class="brand">BRODIE SCRIPTS</div>
    <div class="sub">discord.gg/brodie · Admin Panel</div>
    <input class="inp" type="text" id="lu" placeholder="Admin Username" autocapitalize="off"/>
    <input class="inp" type="password" id="lp" placeholder="Admin Password"/>
    <button class="lbtn" id="lbtn">SIGN IN</button>
    <div class="lerr" id="lerr">Wrong username or password</div>
  </div>
</div>

<div id="app">
  <div class="hdr">
    <div class="hdr-ico">BS</div>
    <div>
      <div class="hdr-brand">BRODIE SCRIPTS</div>
      <div class="hdr-sub">discord.gg/brodie</div>
    </div>
    <button class="hdr-out" id="obtn">Sign Out</button>
  </div>

  <div class="wrap">
    <div class="ptitle">ACCOUNTS</div>
    <div class="psub" id="acc-sub">Manage member logins</div>

    <div class="stats">
      <div class="stat"><div class="sl">Total</div><div class="sv" id="s1">0</div></div>
      <div class="stat"><div class="sl">Active</div><div class="sv" id="s2">0</div></div>
      <div class="stat"><div class="sl">Expired</div><div class="sv" id="s3">0</div></div>
    </div>

    <button class="bigbtn" id="newBtn">＋ Create New Account</button>
    <input class="srch" placeholder="Search username…" id="srch"/>
    <div id="list"></div>
  </div>
</div>

<div class="ov" id="m-new">
  <div class="modal">
    <div class="mh">👤 CREATE ACCOUNT</div>
    <div class="fg"><label>Username</label><input id="n-u" placeholder="e.g. customer1" autocapitalize="off"/></div>
    <div class="fg"><label>Password</label><input id="n-p" type="text" placeholder="Password"/></div>
    <div class="fgr">
      <div class="fg"><label>Days (blank = lifetime)</label><input id="n-d" type="number" placeholder="30"/></div>
      <div class="fg"><label>Max Devices</label><input id="n-m" type="number" value="1" min="1"/></div>
    </div>
    <div class="fg"><label>Note (optional)</label><input id="n-note" placeholder="e.g. paid member"/></div>
    <div class="mac">
      <button class="btn bo" id="n-cancel">Cancel</button>
      <button class="btn bp" id="n-save">Create</button>
    </div>
  </div>
</div>

<div class="ov" id="m-edit">
  <div class="modal">
    <div class="mh">✏️ EDIT ACCOUNT</div>
    <input type="hidden" id="e-id"/>
    <div class="fg"><label>Username</label><input id="e-u" readonly style="opacity:.4"/></div>
    <div class="fg"><label>New Password (blank = keep)</label><input id="e-p" type="text" placeholder="Leave blank to keep"/></div>
    <div class="fgr">
      <div class="fg"><label>Add Days</label><input id="e-d" type="number" placeholder="0"/></div>
      <div class="fg"><label>Max Devices</label><input id="e-m" type="number" min="1"/></div>
    </div>
    <div class="fg"><label>Status</label>
      <select id="e-s"><option value="1">✅ Active</option><option value="0">🚫 Disabled</option></select>
    </div>
    <div class="mac">
      <button class="btn bo" id="e-cancel">Cancel</button>
      <button class="btn bp" id="e-save">Save</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script>
// ── SERVER URL — your Render server ──
var API = '';
var USER = '', PASS = '';

function hdr() {
  return { 'Content-Type':'application/json', 'username':USER, 'password':PASS };
}

// ── LOGIN ──
function doLogin() {
  var u = document.getElementById('lu').value.trim();
  var p = document.getElementById('lp').value.trim();
  fetch(API + '/admin/login', {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({username:u, password:p})
  }).then(function(r){ return r.json(); }).then(function(d){
    if(d.success){
      USER = u; PASS = p;
      sessionStorage.setItem('bsu', u);
      sessionStorage.setItem('bsp', p);
      document.getElementById('login').style.display='none';
      document.getElementById('app').style.display='block';
      loadAccounts();
    } else {
      document.getElementById('lerr').style.display='block';
    }
  }).catch(function(){
    document.getElementById('lerr').textContent = 'Cannot reach server';
    document.getElementById('lerr').style.display='block';
  });
}
document.getElementById('lbtn').addEventListener('click', doLogin);
document.getElementById('lp').addEventListener('keyup', function(e){ if(e.keyCode===13) doLogin(); });

document.getElementById('obtn').addEventListener('click', function(){
  sessionStorage.clear();
  location.reload();
});

// Auto login
var su = sessionStorage.getItem('bsu'), sp = sessionStorage.getItem('bsp');
if(su && sp){
  document.getElementById('lu').value = su;
  document.getElementById('lp').value = sp;
  doLogin();
}

// ── LOAD ACCOUNTS ──
var allAccounts = [];
function loadAccounts() {
  fetch(API + '/admin/accounts', { headers: hdr() })
    .then(function(r){ return r.json(); })
    .then(function(data){
      allAccounts = data || [];
      renderStats();
      render(allAccounts);
    }).catch(function(){ toast('⚠️ Connection error'); });
}

function renderStats() {
  var now = new Date();
  var active = allAccounts.filter(function(a){ return a.active && !(a.expiry_date && new Date(a.expiry_date)<now); }).length;
  var expired = allAccounts.filter(function(a){ return a.expiry_date && new Date(a.expiry_date)<now; }).length;
  document.getElementById('s1').textContent = allAccounts.length;
  document.getElementById('s2').textContent = active;
  document.getElementById('s3').textContent = expired;
  document.getElementById('acc-sub').textContent = allAccounts.length + ' total members';
}

function render(list) {
  var now = new Date();
  var el = document.getElementById('list');
  if(!list.length){ el.innerHTML = '<div class="empty"><div class="empty-i">👤</div>No accounts yet — create one!</div>'; return; }
  el.innerHTML = list.map(function(a){
    var exp = a.expiry_date && new Date(a.expiry_date)<now;
    var sc = !a.active?'bgr':exp?'bgy':'bga';
    var st = !a.active?'Disabled':exp?'Expired':'Active';
    return '<div class="card"><div class="ch"><div><div class="cn">'+a.username+'</div>'+(a.note?'<div class="cnote">'+a.note+'</div>':'')+'</div><span class="badge '+sc+'">'+st+'</span></div>'+
      '<div class="cb"><span class="cinfo">📱 <b>'+((a.hwids||[]).length)+'/'+(a.max_devices||1)+'</b> devices</span><span class="tchip">⏱ '+(a.expiry_date?cd(a.expiry_date):'∞ Lifetime')+'</span></div>'+
      '<div class="ca"><button class="btn bo" onclick=\'editAcc("'+a.id+'")\'>✏️ Edit</button><button class="btn bo" onclick=\'resetDev("'+a.id+'")\'>↺ Reset Device</button><button class="btn bd" onclick=\'delAcc("'+a.id+'")\'>✕ Delete</button></div></div>';
  }).join('');
}

document.getElementById('srch').addEventListener('input', function(){
  var q = this.value.toLowerCase();
  render(allAccounts.filter(function(a){ return a.username.toLowerCase().indexOf(q)!==-1; }));
});

// ── CREATE ──
document.getElementById('newBtn').addEventListener('click', function(){ openM('m-new'); });
document.getElementById('n-cancel').addEventListener('click', closeMs);
document.getElementById('n-save').addEventListener('click', function(){
  var u = document.getElementById('n-u').value.trim();
  var p = document.getElementById('n-p').value.trim();
  if(!u || !p){ toast('⚠️ Username and password required'); return; }
  var body = {
    username: u, password: p,
    days: document.getElementById('n-d').value || null,
    max_devices: parseInt(document.getElementById('n-m').value)||1,
    note: document.getElementById('n-note').value
  };
  fetch(API + '/admin/accounts', { method:'POST', headers:hdr(), body:JSON.stringify(body) })
    .then(function(r){ return r.json(); })
    .then(function(d){
      if(d.error){ toast('❌ '+d.error); return; }
      toast('✅ Account created: '+u);
      closeMs();
      document.getElementById('n-u').value='';
      document.getElementById('n-p').value='';
      document.getElementById('n-d').value='';
      document.getElementById('n-note').value='';
      loadAccounts();
    }).catch(function(){ toast('⚠️ Connection error'); });
});

// ── EDIT ──
function editAcc(id) {
  var a = allAccounts.find(function(x){ return x.id===id; });
  if(!a) return;
  document.getElementById('e-id').value = id;
  document.getElementById('e-u').value = a.username;
  document.getElementById('e-p').value = '';
  document.getElementById('e-m').value = a.max_devices||1;
  document.getElementById('e-s').value = a.active?'1':'0';
  document.getElementById('e-d').value = '';
  openM('m-edit');
}
document.getElementById('e-cancel').addEventListener('click', closeMs);
document.getElementById('e-save').addEventListener('click', function(){
  var id = document.getElementById('e-id').value;
  var body = {
    active: document.getElementById('e-s').value==='1',
    max_devices: parseInt(document.getElementById('e-m').value)||1
  };
  var p = document.getElementById('e-p').value.trim();
  if(p) body.password = p;
  var days = parseInt(document.getElementById('e-d').value);
  if(days>0){
    var a = allAccounts.find(function(x){ return x.id===id; });
    var base = a.expiry_date && new Date(a.expiry_date)>new Date() ? new Date(a.expiry_date) : new Date();
    body.expiry_date = new Date(base.getTime()+days*86400000).toISOString();
  }
  fetch(API + '/admin/accounts/' + id, { method:'PATCH', headers:hdr(), body:JSON.stringify(body) })
    .then(function(r){ return r.json(); })
    .then(function(){ toast('✅ Saved'); closeMs(); loadAccounts(); })
    .catch(function(){ toast('⚠️ Error'); });
});

function delAcc(id) {
  if(!confirm('Delete this account?')) return;
  fetch(API + '/admin/accounts/' + id, { method:'DELETE', headers:hdr() })
    .then(function(){ toast('🗑️ Deleted'); loadAccounts(); })
    .catch(function(){ toast('⚠️ Error'); });
}

function resetDev(id) {
  if(!confirm('Reset devices for this account?')) return;
  fetch(API + '/admin/accounts/' + id + '/reset', { method:'POST', headers:hdr() })
    .then(function(){ toast('↺ Devices reset'); loadAccounts(); })
    .catch(function(){ toast('⚠️ Error'); });
}

// ── UTILS ──
function openM(id){ document.getElementById(id).classList.add('on'); }
function closeMs(){ document.querySelectorAll('.ov').forEach(function(o){ o.classList.remove('on'); }); }
document.querySelectorAll('.ov').forEach(function(o){ o.addEventListener('click', function(e){ if(e.target===o) closeMs(); }); });
function cd(iso){ var s=Math.floor((new Date(iso)-new Date())/1000); if(s<=0)return'Expired'; var d=Math.floor(s/86400),h=Math.floor((s%86400)/3600); return d>0?d+'d '+h+'h':h+'h'; }
var _tt;
function toast(m){ var t=document.getElementById('toast'); t.textContent=m; t.classList.add('on'); clearTimeout(_tt); _tt=setTimeout(function(){ t.classList.remove('on'); },3000); }
</script>
</body>
</html>
`;

app.get('/', (req, res) => {
  res.send(DASHBOARD_HTML);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Brodie Key Server on port ${PORT}`));
