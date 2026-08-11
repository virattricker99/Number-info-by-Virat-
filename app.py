#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
============================================================
VIRAT FYTER - NUMBER INFO (LEGAL OSINT / CARRIER LOOKUP)
Flask backend with secure server-side Veriphone proxy
============================================================
"""
import os
import re
import time
import threading
from collections import OrderedDict, defaultdict

import requests
from flask import Flask, jsonify, render_template_string, request

# ------------------------------------------------------------------
# CONFIGURATION (all secrets come from environment variables)
# ------------------------------------------------------------------
APP_NAME = "VIRAT FYTER"
VERIPHONE_URL = "https://api.veriphone.io/v2/verify"
API_KEY = os.environ.get("VERIPHONE_API_KEY", "").strip()      # <-- set on Render
DEFAULT_COUNTRY = os.environ.get("DEFAULT_COUNTRY", "IN")
PORT = int(os.environ.get("PORT", 5000))
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", 10))             # requests / window
RATE_WINDOW = int(os.environ.get("RATE_WINDOW", 60))           # seconds
CACHE_TTL = int(os.environ.get("CACHE_TTL", 300))              # seconds

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ------------------------------------------------------------------
# SECURITY HEADERS
# ------------------------------------------------------------------
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["X-XSS-Protection"] = "1; mode=block"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data:; "
        "connect-src 'self'"
    )
    return resp

# ------------------------------------------------------------------
# RATE LIMITER (per-IP sliding window, thread-safe)
# ------------------------------------------------------------------
class RateLimiter:
    def __init__(self, limit, window):
        self.limit = limit
        self.window = window
        self.hits = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key):
        now = time.time()
        with self._lock:
            window_start = now - self.window
            self.hits[key] = [t for t in self.hits[key] if t > window_start]
            if len(self.hits[key]) >= self.limit:
                return False
            self.hits[key].append(now)
            return True

limiter = RateLimiter(RATE_LIMIT, RATE_WINDOW)

# ------------------------------------------------------------------
# TTL CACHE (avoids repeat API calls -> saves free quota)
# ------------------------------------------------------------------
class TTLCache:
    def __init__(self, ttl):
        self.ttl = ttl
        self.store = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            if key not in self.store:
                return None
            value, created = self.store[key]
            if time.time() - created > self.ttl:
                del self.store[key]
                return None
            self.store.move_to_end(key)
            return value

    def set(self, key, value):
        with self._lock:
            self.store[key] = (value, time.time())
            self.store.move_to_end(key)
            if len(self.store) > 1000:
                self.store.popitem(last=False)

cache = TTLCache(CACHE_TTL)

# ------------------------------------------------------------------
# NUMBER NORMALIZATION -> E.164  (e.g. "9876543210" -> "+919876543210")
# ------------------------------------------------------------------
def normalize_e164(raw):
    if not raw:
        return None
    cleaned = re.sub(r"[^\d+]", "", str(raw).strip())
    if cleaned.startswith("00"):            # 00 international prefix
        cleaned = "+" + cleaned[2:]
    if cleaned.startswith("+"):
        digits = cleaned[1:]
        if 8 <= len(digits) <= 15:
            return "+" + digits
        return None
    if len(cleaned) == 10:                  # local 10-digit -> default country
        return "+" + DEFAULT_COUNTRY + cleaned
    if 8 <= len(cleaned) <= 15:
        return "+" + cleaned
    return None

# ------------------------------------------------------------------
# HOME PAGE
# ------------------------------------------------------------------
@app.route("/")
def home():
    return render_template_string(HTML_TEMPLATE)

# ------------------------------------------------------------------
# HEALTH CHECK (used by Render)
# ------------------------------------------------------------------
@app.route("/health")
def health():
    return jsonify({"status": "ok", "app": APP_NAME})

# ------------------------------------------------------------------
# LOOKUP PROXY (secure server-side API call)
# ------------------------------------------------------------------
@app.route("/api/lookup", methods=["POST"])
def lookup():
    # 1) rate limit by client IP
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "?")
    ip = ip.split(",")[0].strip()
    if not limiter.allow(ip):
        return jsonify({"status": "error", "message": "RATE_LIMIT_EXCEEDED: try again in a minute."}), 429

    # 2) parse + validate input
    try:
        data = request.get_json(silent=True) or {}
    except Exception:
        data = {}
    raw = data.get("number", "")
    e164 = normalize_e164(raw)
    if not e164:
        return jsonify({"status": "error", "message": "INVALID_NUMBER: enter a 10-digit or +country number."}), 400

    # 3) serve from cache if fresh
    cached = cache.get(e164)
    if cached is not None:
        return jsonify({"status": "success", "cached": True, "result": cached})

    # 4) call Veriphone (key stays on the server)
    try:
        resp = requests.get(
            VERIPHONE_URL,
            params={"phone": e164, "key": API_KEY, "default_country": DEFAULT_COUNTRY},
            timeout=12,
        )
        resp.raise_for_status()
        api = resp.json()
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "UPSTREAM_TIMEOUT: API took too long."}), 504
    except requests.exceptions.RequestException as exc:
        return jsonify({"status": "error", "message": f"UPSTREAM_ERROR: {exc}"}), 502
    except ValueError:
        return jsonify({"status": "error", "message": "BAD_UPSTREAM_RESPONSE."}), 502

    if api.get("status") == "error":
        return jsonify({"status": "error", "message": api.get("error", "API_ERROR")}), 502

    # 5) build clean result
    result = {
        "msisdn": api.get("e164") or e164,
        "valid": bool(api.get("phone_valid")),
        "country": api.get("country") or "",
        "country_code": api.get("country_code") or "",
        "region": api.get("phone_region") or "",
        "carrier": api.get("carrier") or "",
        "line_type": api.get("phone_type") or "",
        "international": api.get("international_number") or "",
        "local": api.get("local_number") or "",
    }
    cache.set(e164, result)
    return jsonify({"status": "success", "cached": False, "result": result})

# ------------------------------------------------------------------
# ERROR HANDLERS
# ------------------------------------------------------------------
@app.errorhandler(404)
def not_found(_):
    return jsonify({"status": "error", "message": "NOT_FOUND"}), 404

@app.errorhandler(405)
def method_not_allowed(_):
    return jsonify({"status": "error", "message": "METHOD_NOT_ALLOWED"}), 405

@app.errorhandler(500)
def server_error(_):
    return jsonify({"status": "error", "message": "INTERNAL_ERROR"}), 500

# ------------------------------------------------------------------
# HTML TEMPLATE - VIRAT FYTER TERMINAL UI
# ------------------------------------------------------------------
HTML_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>VIRAT FYTER - NUMBER INFO</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
<style>
  :root{
    --grn:#00ff41; --drk:#0d0208; --blk:#000; --red:#ff003c;
    --glow:0 0 10px rgba(0,255,65,.5);
  }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{
    font-family:'Share Tech Mono',monospace;
    background:var(--blk);color:var(--grn);
    min-height:100vh;display:flex;flex-direction:column;align-items:center;
    text-transform:uppercase;overflow-x:hidden;
  }
  body::after{ /* CRT scanline */
    content:"";position:fixed;inset:0;pointer-events:none;z-index:2;
    background:linear-gradient(rgba(18,16,16,0) 50%,rgba(0,0,0,.25) 50%),
               linear-gradient(90deg,rgba(255,0,0,.06),rgba(0,255,0,.02),rgba(0,0,255,.06));
    background-size:100% 2px,3px 100%;
  }
  ::-webkit-scrollbar{width:8px;}
  ::-webkit-scrollbar-track{background:var(--blk);border-left:1px solid var(--grn);}
  ::-webkit-scrollbar-thumb{background:var(--grn);}
  .overlay{position:fixed;inset:0;background:rgba(0,0,0,.95);z-index:9999;
           display:flex;justify-content:center;align-items:center;transition:.5s;}
  .overlay.hidden{opacity:0;visibility:hidden;}
  .overlay.hide{display:none!important;}
  .box{background:var(--blk);border:2px solid var(--red);padding:40px;max-width:500px;
       width:90%;text-align:center;box-shadow:0 0 30px rgba(255,0,60,.3);}
  .box h2{color:var(--red);font-size:22px;margin-bottom:18px;text-shadow:0 0 10px var(--red);animation:blink 1s infinite;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.5}}
  .box .content{color:#fff;font-size:13px;line-height:1.9;margin-bottom:26px;}
  .btn-accept{background:transparent;border:2px solid var(--red);color:var(--red);
              padding:12px 30px;font-family:inherit;font-size:15px;cursor:pointer;transition:.3s;}
  .btn-accept:hover{background:var(--red);color:var(--blk);box-shadow:0 0 15px var(--red);}
  .top{width:100%;background:#001100;border-bottom:1px solid var(--grn);padding:8px 0;position:sticky;top:0;z-index:999;}
  .top .row{max-width:1200px;margin:auto;padding:0 20px;display:flex;justify-content:space-between;
            align-items:center;font-size:12px;letter-spacing:2px;}
  .main{max-width:650px;width:100%;padding:20px;margin:20px 0;}
  .card{background:rgba(0,15,0,.8);border:1px solid var(--grn);box-shadow:var(--glow);position:relative;}
  .card::before{content:"[ ROOT_TERMINAL ] - /usr/bin/virat_intel";
    display:block;background:var(--grn);color:var(--blk);padding:5px 15px;font-size:12px;font-weight:bold;letter-spacing:1px;}
  .card-body{padding:28px;}
  .h1{font-size:34px;letter-spacing:4px;text-shadow:var(--glow);text-align:center;margin:30px 0 4px;}
  .sub{color:#888;font-size:13px;letter-spacing:4px;text-align:center;}
  .lbl{display:block;font-size:13px;margin-bottom:10px;}
  .inp{display:flex;align-items:center;background:var(--blk);border:1px solid var(--grn);}
  .inp::before{content:">";color:var(--grn);padding-left:15px;font-size:18px;animation:blink 1s infinite;}
  .inp input{flex:1;padding:15px;background:transparent;border:none;color:var(--grn);
             font-size:18px;font-family:inherit;outline:none;letter-spacing:3px;text-transform:uppercase;}
  .inp input::placeholder{color:rgba(0,255,65,.3);}
  .status{font-size:12px;margin:15px 0;color:#888;}
  .status span{color:var(--grn);}
  .btn{width:100%;padding:15px;background:transparent;border:1px solid var(--grn);color:var(--grn);
       font-size:17px;font-family:inherit;cursor:pointer;letter-spacing:3px;transition:.2s;}
  .btn:hover:not(:disabled){background:var(--grn);color:var(--blk);box-shadow:var(--glow);}
  .btn:disabled{border-color:#555;color:#555;cursor:not-allowed;}
  .err{color:var(--red);font-size:12px;display:none;margin:10px 0;text-shadow:0 0 5px var(--red);}
  .err.show{display:block;}
  .res{margin-top:26px;border:1px dashed var(--grn);background:#000;display:none;}
  .res.show{display:block;}
  .res-h{background:rgba(0,255,65,.1);padding:10px;border-bottom:1px dashed var(--grn);
          display:flex;justify-content:space-between;font-size:12px;}
  .row-it{display:flex;padding:11px 15px;border-bottom:1px solid rgba(0,255,65,.2);}
  .row-it:last-child{border-bottom:none;}
  .row-it .l{color:#888;width:35%;}
  .row-it .l::before{content:"[+] ";color:var(--grn);}
  .row-it .v{color:#fff;width:65%;}
  .row-it .v.hl{color:var(--grn);font-weight:bold;}
  .json-btn{margin-top:18px;padding:10px;background:transparent;border:1px dashed #555;color:#888;
            width:100%;cursor:pointer;font-family:inherit;}
  .json-btn:hover{border-color:var(--grn);color:var(--grn);}
  .json-box{display:none;margin-top:10px;background:#000;padding:14px;font-size:11px;color:var(--grn);
            border:1px solid var(--grn);max-height:220px;overflow:auto;white-space:pre-wrap;word-break:break-all;}
  .json-box.show{display:block;}
  .foot{margin-top:auto;width:100%;text-align:center;padding:20px;border-top:1px solid var(--grn);
        font-size:12px;color:#555;background:#000;}
</style>
</head>
<body>

<div class="overlay" id="ov">
  <div class="box">
    <h2>WELCOME</h2>
    <div class="content">
      LEGAL NUMBER INTELLIGENCE TOOL.<br>
      RETURNS PUBLIC CARRIER &amp; LINE-TYPE DATA ONLY.<br>
      FOR EDUCATIONAL &amp; BUSINESS USE.<br><br>
      DEV BY <strong>VIRAT FYTER</strong>
    </div>
    <button class="btn-accept" onclick="accept()">[ INITIATE ]</button>
  </div>
</div>

<div class="top"><div class="row">
  <div><i class="fas fa-terminal"></i> VIRAT_FYTER // SECURE_NODE</div>
  <div>STATUS: <span style="color:#00ff41;">CONNECTED</span></div>
</div></div>

<div class="h1">VIRAT<span style="color:#fff;">_FYTER</span></div>
<div class="sub">== NUMBER INTELLIGENCE SUBSYSTEM ==</div>

<div class="main">
  <div class="card"><div class="card-body">
    <form id="f">
      <label class="lbl">ENTER TARGET NUMBER [10 DIGITS]:</label>
      <div class="inp"><input id="n" type="tel" placeholder="TARGET_NUMBER" maxlength="10" inputmode="numeric"></div>
      <div class="status">SYS_MSG: <span id="st">AWAITING INPUT...</span></div>
      <div class="err" id="err"></div>
      <button type="submit" class="btn" id="b"><i class="fas fa-satellite-dish"></i> EXECUTE LOOKUP</button>
    </form>

    <div class="res" id="res">
      <div class="res-h"><div><i class="fas fa-database"></i> DUMP_SUCCESS</div><div>SOURCE: VERIPHONE</div></div>
      <div id="rc"></div>
    </div>

    <button class="json-btn" onclick="document.getElementById('jb').classList.toggle('show')">[ VIEW_RAW_JSON ]</button>
    <div class="json-box" id="jb"></div>
  </div></div>
</div>

<div class="foot">(C) 2026 VIRAT FYTER - LEGAL NUMBER INFO // USE RESPONSIBLY</div>

<script>
function accept(){
  document.getElementById('ov').classList.add('hidden');
  setTimeout(()=>document.getElementById('ov').classList.add('hide'),500);
}
document.getElementById('f').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const num=document.getElementById('n').value.trim();
  const err=document.getElementById('err'), st=document.getElementById('st'), b=document.getElementById('b');
  err.classList.remove('show');
  if(!/^\d{10}$/.test(num)){err.textContent='ERR: INVALID NUMBER FORMAT (10 DIGITS).';err.classList.add('show');return;}
  b.disabled=true;b.innerHTML='CONNECTING...';st.textContent='QUERYING LIVE DATABASE...';
  try{
    const r=await fetch('/api/lookup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({number:num})});
    const d=await r.json();
    document.getElementById('jb').textContent=JSON.stringify(d,null,2);
    if(d.status!=='success'||!d.result){
      err.textContent='ERR: '+(d.message||'NOT FOUND.');err.classList.add('show');
      document.getElementById('res').classList.remove('show');
      st.textContent='LOOKUP FAILED.';
      return;
    }
    const x=d.result, box=document.getElementById('rc');
    const rows=[
      ['MSISDN',x.msisdn,true],['VALID',x.valid?'YES':'NO',x.valid],
      ['COUNTRY',x.country+' ('+x.country_code+')',false],
      ['REGION',x.region||'N/A',false],['CARRIER',x.carrier||'N/A',false],
      ['LINE_TYPE',x.line_type||'N/A',false],
      ['INTERNATIONAL',x.international||'N/A',false]
    ];
    box.innerHTML=rows.map(([l,v,hl])=>
      `<div class="row-it"><span class="l">${l}</span><span class="v${hl?' hl':''}">${v}</span></div>`).join('');
    document.getElementById('res').classList.add('show');
    st.textContent='LOOKUP COMPLETE'+(d.cached?' (CACHED)':' (LIVE)')+'.';
  }catch(e){
    err.textContent='ERR: NETWORK FAULT.';err.classList.add('show');
    st.textContent='LOOKUP FAILED.';
  }finally{
    b.disabled=false;b.innerHTML='<i class="fas fa-satellite-dish"></i> EXECUTE LOOKUP';
  }
});
document.getElementById('n').addEventListener('input',function(){this.value=this.value.replace(/\D/g,'');});
</script>
</body>
</html>
"""

# ------------------------------------------------------------------
# MAIN
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 55)
    print("  VIRAT FYTER - NUMBER INFO (LEGAL OSINT)")
    print("=" * 55)
    print(f"  Local:  http://127.0.0.1:{PORT}")
    print(f"  API OK: {'YES' if API_KEY else 'NO - set VERIPHONE_API_KEY'}")
    print("=" * 55)
    app.run(host="0.0.0.0", port=PORT, debug=False, threaded=True)