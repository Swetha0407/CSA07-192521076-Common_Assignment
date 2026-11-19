from pathlib import Path
import json,threading
from collections import Counter
DEFAULT=[{"name":"Allow local web traffic","source_ip":"192.168.1.0/24","destination_ip":"*","port":"80","protocol":"TCP","action":"ALLOW","enabled":True,"id":1},{"name":"Allow secure web traffic","source_ip":"*","destination_ip":"*","port":"443","protocol":"TCP","action":"ALLOW","enabled":True,"id":2},{"name":"Block Telnet","source_ip":"*","destination_ip":"*","port":"23","protocol":"TCP","action":"BLOCK","enabled":True,"id":3}]
class Store:
 def __init__(self,d):
  self.d=Path(d);self.d.mkdir(parents=True,exist_ok=True);self.rf=self.d/"rules.json";self.ef=self.d/"events.json";self.lock=threading.RLock()
  if not self.rf.exists():self.write(self.rf,DEFAULT)
  if not self.ef.exists():self.write(self.ef,[])
 def read(self,p,default):
  try:return json.loads(p.read_text())
  except:return default
 def write(self,p,x):p.write_text(json.dumps(x,indent=2))
 def rules(self):
  with self.lock:return self.read(self.rf,[])
 def add_rule(self,r):
  with self.lock:
   a=self.rules();r["id"]=max([x.get("id",0) for x in a]+[0])+1;a.append(r);self.write(self.rf,a)
 def toggle_rule(self,i):
  a=self.rules()
  for x in a:
   if x["id"]==i:x["enabled"]=not x.get("enabled",True)
  self.write(self.rf,a)
 def delete_rule(self,i):self.write(self.rf,[x for x in self.rules() if x["id"]!=i])
 def add_event(self,e):
  with self.lock:a=self.read(self.ef,[]);a.append(e);self.write(self.ef,a[-5000:])
 def recent_events(self,n=100):return list(reversed(self.read(self.ef,[])[-n:]))
 def recent_alerts(self,n=100):return [x for x in self.recent_events(5000) if x.get("suspicious")][:n]
 def stats(self):
  a=self.recent_events(5000);c=Counter(x.get("status") for x in a)
  return {"total":len(a),"allowed":c["ALLOW"],"blocked":c["BLOCK"],"alerts":sum(x.get("suspicious",False) for x in a),"bytes":sum(x.get("bytes",0) for x in a)}
 def clear_events(self):self.write(self.ef,[])
