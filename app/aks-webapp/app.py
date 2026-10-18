"""aks-webapp: the public workload Flux deploys to AKS (Deployment `webapp`).

Deliberately small. It reads the synthetic "sensitive" blob through workload identity
(no key, no connection string) and renders it on one dashboard page - the internet-facing
workload that holds data an attacker would want. The lab cockpit is app/webapp (aca-webapp).

Background loops, both optional:
  blob       STORAGE_ACCOUNT_URL set by infra/postdeploy/configure-sensitive-storage.sh
  heartbeat  HEARTBEAT_URL from the Flux-managed panel-heartbeat ConfigMap (isolation drill)
"""
import hashlib
import json
import os
import threading
import time

from flask import Flask, jsonify

STORAGE_ACCOUNT_URL = os.environ.get("STORAGE_ACCOUNT_URL", "")
STORAGE_CONTAINER = os.environ.get("STORAGE_CONTAINER", "sensitive-data")
STORAGE_BLOB = os.environ.get("STORAGE_BLOB", "customers.json")
STORAGE_POLL_SECONDS = int(os.environ.get("STORAGE_POLL_SECONDS", "30"))

# Any HTTP answer counts as reachable - a 401 still proves the network path is open.
HEARTBEAT_URL = os.environ.get("HEARTBEAT_URL", "")
HEARTBEAT_SECONDS = int(os.environ.get("HEARTBEAT_SECONDS", "15"))

_state = {
    "pod": os.environ.get("HOSTNAME", "?"),
    "blob": {"configured": bool(STORAGE_ACCOUNT_URL),
             "status": "pending" if STORAGE_ACCOUNT_URL else "disabled",
             "target": f"{STORAGE_CONTAINER}/{STORAGE_BLOB}" if STORAGE_ACCOUNT_URL else "",
             "classification": "", "notice": "", "records": [], "bytes": 0, "sha256": "",
             "last_checked": "", "error": ""},
    "heartbeat": {"configured": bool(HEARTBEAT_URL),
                  "status": "pending" if HEARTBEAT_URL else "disabled",
                  "target": HEARTBEAT_URL, "last_checked": "", "detail": "", "error": ""},
}

app = Flask(__name__)


def _stamp():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _blob_loop():
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobClient

    blob = BlobClient(account_url=STORAGE_ACCOUNT_URL, container_name=STORAGE_CONTAINER,
                      blob_name=STORAGE_BLOB, credential=DefaultAzureCredential())
    print(f"[blob] started: GET {STORAGE_ACCOUNT_URL}/{STORAGE_CONTAINER}/{STORAGE_BLOB} "
          f"every {STORAGE_POLL_SECONDS}s using workload identity", flush=True)
    while True:
        stamp = _stamp()
        try:
            raw = blob.download_blob().readall()
            doc = json.loads(raw.decode("utf-8"))
            records = doc.get("records", [])
            if not isinstance(records, list):
                raise ValueError("records must be a JSON array")
            _state["blob"].update(
                status="ok", last_checked=stamp, error="", bytes=len(raw),
                sha256=hashlib.sha256(raw).hexdigest(),
                classification=str(doc.get("classification", "FAKE SENSITIVE DATA")),
                notice=str(doc.get("notice", "")), records=records,
            )
            print(f"{stamp} [blob] OK retrieved {len(records)} fake sensitive record(s) "
                  f"({len(raw)} bytes)", flush=True)
        except Exception as e:                               # noqa: BLE001
            _state["blob"].update(status="error", last_checked=stamp, records=[],
                                  error=f"{type(e).__name__}: {str(e)[:200]}")
            print(f"{stamp} [blob] ERROR {type(e).__name__}: {str(e)[:200]}", flush=True)
        time.sleep(max(5, STORAGE_POLL_SECONDS))


def _heartbeat_loop():
    import requests

    print(f"[heartbeat] started on {_state['pod']}: GET {HEARTBEAT_URL} "
          f"every {HEARTBEAT_SECONDS}s", flush=True)
    failed = 0
    while True:
        t0 = time.monotonic()
        stamp = _stamp()
        try:
            r = requests.get(HEARTBEAT_URL, timeout=(5, 5))
            ms = int((time.monotonic() - t0) * 1000)
            line = f"{stamp} [heartbeat] OK HTTP {r.status_code} in {ms}ms"
            if failed:
                line += f" - recovered after {failed} failed beat(s)"
            failed = 0
            _state["heartbeat"].update(status="ok", last_checked=stamp,
                                       detail=f"HTTP {r.status_code} in {ms}ms", error="")
        except Exception as e:                               # noqa: BLE001
            failed += 1
            line = (f"{stamp} [heartbeat] ERROR {type(e).__name__}: {str(e)[:200]} "
                    f"(failed {failed}x in a row - egress blocked, pod isolated?)")
            _state["heartbeat"].update(status="error", last_checked=stamp, detail="",
                                       error=f"{type(e).__name__}: {str(e)[:160]}")
        print(line, flush=True)
        time.sleep(max(0.0, HEARTBEAT_SECONDS - (time.monotonic() - t0)))


@app.route("/healthz")
def healthz():
    return "ok"


@app.route("/api/data")
def api_data():
    return jsonify(_state)


@app.route("/")
def home():
    return PAGE


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Customer Records</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1c2330;--muted:#5d6878;--line:#dfe3ea;
  --ok:#1a7f4b;--err:#b42318;--warn:#8a5a00;--accent:#2f5bd3}
@media (prefers-color-scheme:dark){:root{--bg:#11151c;--card:#1a202a;--fg:#e6e9ef;
  --muted:#98a2b3;--line:#2c3442;--ok:#4ade80;--err:#f87171;--warn:#fbbf24;--accent:#7aa2ff}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:960px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px;font-size:13px}
.banner{border:1px solid var(--warn);color:var(--warn);border-radius:8px;
  padding:8px 12px;margin-bottom:16px;font-weight:600}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin-bottom:16px}
.tile{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px}
.tile b{display:block;font-size:20px;font-variant-numeric:tabular-nums}
.tile span{color:var(--muted);font-size:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;overflow-x:auto}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.03em}
td.num{text-align:right;font-variant-numeric:tabular-nums}
tr:last-child td{border-bottom:0}
.ok{color:var(--ok)}.error{color:var(--err)}.pending,.disabled{color:var(--muted)}
.empty{padding:20px;color:var(--muted)}
footer{color:var(--muted);font-size:12px;margin-top:14px;word-break:break-all}
</style></head><body><main>
<h1>Customer Records</h1>
<p class="sub">Read from Azure Blob Storage by pod <span id="pod">-</span> via workload identity.</p>
<div id="banner" class="banner" hidden></div>
<div class="tiles">
  <div class="tile"><span>Storage</span><b id="blob-status">-</b><span id="blob-target"></span></div>
  <div class="tile"><span>Records</span><b id="count">-</b><span id="bytes"></span></div>
  <div class="tile"><span>Total balance</span><b id="total">-</b><span>EUR</span></div>
  <div class="tile"><span>Heartbeat</span><b id="hb-status">-</b><span id="hb-detail"></span></div>
</div>
<div class="card" id="table"><div class="empty">Loading...</div></div>
<footer id="footer"></footer>
</main>
<script>
const $=id=>document.getElementById(id);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const status=(el,s)=>{el.textContent=s;el.className=s};
async function refresh(){
  let d; try{d=await (await fetch('api/data',{cache:'no-store'})).json()}catch(e){return}
  const b=d.blob,h=d.heartbeat,recs=b.records||[];
  $('pod').textContent=d.pod;
  status($('blob-status'),b.status);
  $('blob-target').textContent=b.error||b.target||'STORAGE_ACCOUNT_URL not set';
  $('count').textContent=recs.length;
  $('bytes').textContent=b.bytes?b.bytes+' bytes':'';
  const total=recs.reduce((s,r)=>s+(Number(r.balanceEur)||0),0);
  $('total').textContent=recs.length?total.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):'-';
  status($('hb-status'),h.status);
  $('hb-detail').textContent=h.error||h.detail||(h.configured?'':'HEARTBEAT_URL not set');
  const banner=[b.classification,b.notice].filter(Boolean).join(' - ');
  $('banner').hidden=!banner; $('banner').textContent=banner;
  if(!recs.length){$('table').innerHTML='<div class="empty">'+esc(b.error||'No records yet.')+'</div>'}
  else{
    const cols=[...new Set(recs.flatMap(r=>Object.keys(r)))];
    const num=c=>recs.every(r=>r[c]===undefined||typeof r[c]==='number');
    $('table').innerHTML='<table><thead><tr>'+cols.map(c=>'<th'+(num(c)?' style="text-align:right"':'')+'>'+esc(c)+'</th>').join('')
      +'</tr></thead><tbody>'+recs.map(r=>'<tr>'+cols.map(c=>num(c)
        ?'<td class="num">'+esc(typeof r[c]==='number'?r[c].toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}):'')+'</td>'
        :'<td>'+esc(r[c])+'</td>').join('')+'</tr>').join('')+'</tbody></table>';
  }
  $('footer').textContent=b.last_checked?'Last read '+b.last_checked+(b.sha256?' - sha256 '+b.sha256:''):'';
}
refresh(); setInterval(refresh,10000);
</script></body></html>"""


if __name__ == "__main__":
    if STORAGE_ACCOUNT_URL:
        threading.Thread(target=_blob_loop, name="blob", daemon=True).start()
    if HEARTBEAT_URL:
        threading.Thread(target=_heartbeat_loop, name="heartbeat", daemon=True).start()
    app.run(host="0.0.0.0", port=8080)
