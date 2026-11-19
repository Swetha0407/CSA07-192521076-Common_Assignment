import ipaddress
class FirewallEngine:
 def __init__(self,store):self.store=store
 @staticmethod
 def validate_rule(r):
  for k in ("source_ip","destination_ip"):
   if r.get(k,"*")!="*":
    try:ipaddress.ip_network(r[k],strict=False)
    except ValueError:raise ValueError("Invalid IP address or CIDR range.")
  p=str(r.get("port","*"))
  if p!="*" and not(p.isdigit() and 1<=int(p)<=65535):raise ValueError("Port must be * or 1–65535.")
  if r.get("protocol") not in ("ANY","TCP","UDP"):raise ValueError("Protocol must be ANY, TCP or UDP.")
  if r.get("action") not in ("ALLOW","BLOCK"):raise ValueError("Action must be ALLOW or BLOCK.")
 def match_ip(self,ip,rule):
  if rule=="*":return True
  try:return ipaddress.ip_address(ip) in ipaddress.ip_network(rule,strict=False)
  except ValueError:return False
 def evaluate(self,p,source="MANUAL"):
  try:
   s=str(p["source_ip"]);d=str(p["destination_ip"]);ipaddress.ip_address(s);ipaddress.ip_address(d)
   port=int(p["port"]);proto=str(p.get("protocol","TCP")).upper()
   if not 0<=port<=65535 or proto not in ("TCP","UDP","OTHER"):raise ValueError()
  except (KeyError,ValueError,TypeError):return {"error":"Enter valid source/destination IPs, port 0–65535 and protocol."}
  decision,matched="BLOCK","Default deny"
  for r in self.store.rules():
   if r.get("enabled",True) and self.match_ip(s,r["source_ip"]) and self.match_ip(d,r["destination_ip"]) and (r["port"]=="*" or int(r["port"])==port) and (r["protocol"]=="ANY" or r["protocol"]==proto):
    decision,matched=r["action"],r["name"];break
  suspicious=port in (23,445,3389) or proto=="OTHER"
  reason=(f"Sensitive service port {port} observed" if port in (23,445,3389) else "Non-TCP/UDP traffic observed") if suspicious else ""
  event={"timestamp":__import__("datetime").datetime.now().isoformat(timespec="seconds"),"source_ip":s,"destination_ip":d,"port":port,"protocol":proto,"traffic_type":p.get("traffic_type","Unclassified"),"bytes":int(p.get("bytes",0) or 0),"status":decision,"matched_rule":matched,"suspicious":suspicious,"alert":reason,"source":source}
  self.store.add_event(event);return event
