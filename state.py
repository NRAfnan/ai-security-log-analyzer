import re
from collections import defaultdict

SQLI  = re.compile(r"union(%20|\+|\s)+select|(%27|')(%20|\s)*(or|and)\b|sleep(%28|\()|(;|%3b)\s*select|1(%3d|=)1", re.I)
TRAV  = re.compile(r"\.\.(%2f|/)|%252e%252e|%2e%2e", re.I)
SCAN  = (".env", ".git", "wp-admin", "phpmyadmin", "actuator", "server-status", "backup", "config.json")

class State:
    def __init__(self):
        self.ips = defaultdict(lambda: {"fail": [], "ok": [], "sqli": [], "scan": [], "trav": [],
                                        "post": [], "times": [], "n429": 0, "r429": [], "n403": 0})

    def update(self, r):
        if not r.get("ip"): return
        s, p, st = self.ips[r["ip"]], r["path"].lower(), r["status"]
        s["times"].append(r["ts"])
        if "login" in p and st == 401: s["fail"].append(r["n"])
        if "login" in p and st == 200 and s["fail"]: s["ok"].append(r["n"])
        if SQLI.search(p): s["sqli"].append(r["n"])
        if TRAV.search(p): s["trav"].append(r["n"])
        if any(x in p for x in SCAN): s["scan"].append(r["n"])
        if s["ok"] and ("admin" in p or "export" in p): s["post"].append(r["n"])
        if st == 429:
            s["n429"] += 1
            s["r429"].append(r["n"])
        if st == 403: s["n403"] += 1

    def supports(self, ip, attack_type):
        evidence = self.ips.get(ip)
        if not evidence:
            return False
        return {
            "brute_force": len(evidence["fail"]) >= 3,
            "account_compromise": bool(evidence["ok"]) and len(evidence["fail"]) >= 3,
            "sql_injection": bool(evidence["sqli"]),
            "scanning": len(evidence["scan"]) >= 3,
            "path_traversal": bool(evidence["trav"]),
            "rate_abuse": self.peak_rate(ip) >= 8 or evidence["n429"] >= 3,
            "unauthorized_access": evidence["n403"] >= 3,
        }.get(attack_type, False)

    def candidates(self):
        candidates = []
        for ip, evidence in self.ips.items():
            failed = evidence["fail"]
            if evidence["ok"] and len(failed) >= 3:
                lines = failed[:2] + failed[-2:] + evidence["ok"][:1] + evidence["post"][:3]
                facts = f"{len(failed)} failed logins L{failed[0]}..L{failed[-1]}, then success L{evidence['ok'][0]}"
                if evidence["post"]:
                    facts += ", then admin/export access " + ",".join(
                        f"L{line}" for line in evidence["post"][:3]
                    )
                candidates.append({
                    "ip": ip, "attack_type": "account_compromise",
                    "severity": "Critical" if evidence["post"] else "High",
                    "lines": lines, "facts": facts,
                })
            elif len(failed) >= 3:
                candidates.append({
                    "ip": ip, "attack_type": "brute_force", "severity": "Medium",
                    "lines": failed[:3] + failed[-2:],
                    "facts": f"{len(failed)} failed logins L{failed[0]}..L{failed[-1]}, no success",
                })
            if evidence["sqli"]:
                candidates.append({
                    "ip": ip, "attack_type": "sql_injection", "severity": "High",
                    "lines": evidence["sqli"][:5],
                    "facts": f"{len(evidence['sqli'])} requests with SQL syntax in parameters",
                })
            if len(evidence["scan"]) >= 3:
                candidates.append({
                    "ip": ip, "attack_type": "scanning", "severity": "Medium",
                    "lines": evidence["scan"][:6],
                    "facts": f"{len(evidence['scan'])} probes of sensitive paths",
                })
            if evidence["trav"]:
                candidates.append({
                    "ip": ip, "attack_type": "path_traversal", "severity": "High",
                    "lines": evidence["trav"][:4],
                    "facts": f"{len(evidence['trav'])} path traversal attempts",
                })
            peak = self.peak_rate(ip)
            if peak >= 8 or evidence["n429"] >= 3:
                candidates.append({
                    "ip": ip, "attack_type": "rate_abuse", "severity": "Medium",
                    "lines": evidence["r429"][:4] or evidence["times"][:4],
                    "facts": f"{peak} requests in 5 s, {evidence['n429']} rate-limited (429)",
                })
        return candidates

    def peak_rate(self, ip, window=5.0):
        t, best, j = self.ips[ip]["times"], 0, 0
        for i in range(len(t)):
            while t[i] - t[j] > window: j += 1
            best = max(best, i - j + 1)
        return best

    def summary(self, only=None, cap=6):
        rows = []
        for ip, s in self.ips.items():
            if only and ip not in only: continue
            peak = self.peak_rate(ip)
            if not (len(s["fail"]) >= 3 or s["sqli"] or s["scan"] or s["trav"] or s["post"] or peak >= 8): continue
            bits = []
            if s["fail"]: bits.append(f"failed_logins={len(s['fail'])} L{s['fail'][0]}..L{s['fail'][-1]}")
            if s["ok"]:   bits.append(f"login_success=L{s['ok'][0]}")
            if s["post"]: bits.append(f"admin/export_after_login=L{s['post'][:3]}")
            if s["sqli"]: bits.append(f"sqli_like=L{s['sqli'][:4]}")
            if s["scan"]: bits.append(f"sensitive_paths={len(s['scan'])} L{s['scan'][:3]}")
            if s["trav"]: bits.append(f"traversal=L{s['trav'][:3]}")
            if peak >= 8: bits.append(f"peak_{peak}_req_per_5s n429={s['n429']}")
            rows.append(f"{ip}: " + "; ".join(bits))
        return "\n".join(rows[:cap]) or "none"