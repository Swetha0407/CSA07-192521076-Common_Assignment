from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from pathlib import Path
from datetime import datetime
import random, ipaddress
from firewall_engine import FirewallEngine
from storage import Store
BASE=Path(__file__).resolve().parent
app=Flask(__name__); app.secret_key="local-demo-key-change-before-deployment"
store=Store(BASE/"data"); engine=FirewallEngine(store)
@app.context_processor
def globals_(): return {"now":datetime.now().strftime("%d %b %Y, %H:%M:%S")}
@app.get("/")
def home(): return render_template("dashboard.html",stats=store.stats(),events=store.recent_events(12),alerts=store.recent_alerts(6),rules=store.rules())
@app.get("/traffic")
def traffic(): return render_template("traffic.html",events=store.recent_events(200))
@app.route("/rules",methods=["GET","POST"])
def rules():
 if request.method=="POST":
  r={k:request.form.get(k,"*").strip() or "*" for k in ("source_ip","destination_ip","port")}
  r.update(name=request.form.get("name","").strip(),protocol=request.form.get("protocol","ANY"),action=request.form.get("action","BLOCK"),enabled=True)
  try: engine.validate_rule(r); store.add_rule(r); flash("Rule added.","success")
  except ValueError as e: flash(str(e),"danger")
  return redirect(url_for("rules"))
 return render_template("rules.html",rules=store.rules())
@app.post("/rules/<int:i>/toggle")
def toggle(i): store.toggle_rule(i); return redirect(url_for("rules"))
@app.post("/rules/<int:i>/delete")
def delete(i): store.delete_rule(i); return redirect(url_for("rules"))
@app.get("/alerts")
def alerts(): return render_template("alerts.html",alerts=store.recent_alerts(200))
@app.get("/monitor")
def monitor(): return render_template("monitor.html")
@app.post("/api/evaluate")
def evaluate():
 p=request.get_json(silent=True) or request.form.to_dict()
 return jsonify(engine.evaluate(p,"MANUAL"))
@app.post("/api/simulate")
def simulate():
 p=request.get_json(silent=True) or {}; n=max(1,min(int(p.get("count",20)),250))
 for _ in range(n):
  engine.evaluate({"source_ip":random.choice(["192.168.1.10","192.168.1.25","10.0.0.8","203.0.113.45"]),
   "destination_ip":random.choice(["192.168.1.1","10.0.0.20","198.51.100.10"]),
   "port":random.choice([22,23,53,80,443,445,3306,8080]),"protocol":random.choice(["TCP","UDP"]),
   "bytes":random.randint(64,6000),"traffic_type":random.choice(["Web","DNS","Remote access","File transfer","Unknown"])},"SIMULATOR")
 return jsonify({"generated":n,"stats":store.stats()})
@app.post("/api/sniff")
def sniff():
 p=request.get_json(silent=True) or {}; iface=p.get("interface") or None; secs=max(1,min(int(p.get("seconds",5)),20))
 try: from scapy.all import sniff,IP,TCP,UDP
 except ImportError: return jsonify(error="Scapy missing. Install requirements first."),400
 captured=[]
 def cb(pkt):
  if IP not in pkt:return
  proto="TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
  port=int(pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0))
  captured.append({"source_ip":pkt[IP].src,"destination_ip":pkt[IP].dst,"port":port,"protocol":proto,"bytes":len(pkt),"traffic_type":"Live capture"})
 try:
  sniff(iface=iface,prn=cb,timeout=secs,store=False)
  for x in captured: engine.evaluate(x,"LIVE CAPTURE")
  return jsonify(captured=len(captured),events=captured[:20])
 except Exception as e:return jsonify(error=str(e)),400
@app.get("/health")
def health():return jsonify(status="ok")
if __name__=="__main__":app.run(host="127.0.0.1",port=5000,debug=False)
