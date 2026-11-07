import json
from datetime import datetime
from tokenizers import Tokenizer

_tok = None
def count_tokens(text):
    global _tok
    if _tok is None:
        try: _tok = Tokenizer.from_file("tokenizer.json")
        except Exception: _tok = False
    return len(_tok.encode(text).ids) if _tok else len(text) // 3 + 1

def parse_line(n, raw):
    raw = raw.rstrip("\n")
    try:
        d = json.loads(raw)
        assert isinstance(d, dict)
    except Exception:                       # non-JSON line: keep it, truncated
        return {"n": n, "ip": None, "text": f"L{n}| {raw[:300]}"}
    t = d.get("time", "")
    try: ts = datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
    except ValueError: ts = 0.0
    rec = {"n": n, "ts": ts, "ip": d.get("client_ip"), "method": d.get("method", ""),
           "path": str(d.get("path", ""))[:160], "status": d.get("status"),
           "user": d.get("username"), "auth": d.get("auth_result")}
    if rec["ip"]:
        ua = str(d.get("user_agent", ""))
        ua = "browser" if ua.startswith("Mozilla") else ua[:30]
        parts = [t[11:19], rec["ip"], rec["method"], rec["path"], str(rec["status"])]
        parts += [f"{k}={v}" for k, v in (("ua", ua), ("user", rec["user"]), ("auth", rec["auth"])) if v]
    else:
        parts = [t[11:19], d.get("level", ""), d.get("service", ""), str(d.get("message", ""))[:120]]
    rec["text"] = f"L{n}| " + " ".join(parts)
    return rec

def split_log_file(path, budget=1000):
    chunks, cur, used = [], [], 0
    def flush():
        chunks.append({"start_line": cur[0]["n"], "end_line": cur[-1]["n"], "records": cur[:],
                       "text": "\n".join(r["text"] for r in cur), "tokens": used})
    with open(path, encoding="utf-8", errors="replace") as f:
        for n, raw in enumerate(f, 1):
            if not raw.strip(): continue
            rec = parse_line(n, raw)
            cost = count_tokens(rec["text"]) + 1
            if cur and used + cost > budget:
                flush(); cur, used = [], 0
            cur.append(rec); used += cost
    if cur: flush()
    return chunks