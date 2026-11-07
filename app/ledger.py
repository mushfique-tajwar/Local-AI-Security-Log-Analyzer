# Cross-chunk evidence ledger
import re
from collections import defaultdict
from urllib.parse import unquote

from .parser import parse_line

SQLI = re.compile(r"(\bunion\b.+\bselect\b|\bor\b\s+1\s*=\s*1|;\s*select\b|sleep\s*\(|--\s*$|'\s*or\s*')", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.%2f|%2e%2e)", re.I)
SCAN_PATHS = ("/.env", "/.git", "/wp-admin", "/phpmyadmin", "/actuator", "/server-status",
              "/backup", "/config.json", "/admin", "/etc/passwd")
INJECT_TEXT = re.compile(r"(ignore (all |the )?(previous|prior) instructions|system prompt|disregard)", re.I)


def _new_entity():
    return {
        "first_line": None, "last_line": None, "events": 0,
        "failed_logins": 0, "fail_users": {}, "fail_lines": [],
        "success_lines": [], "success_users": [],
        "sqli_lines": [], "traversal_lines": [], "scan_lines": [], "scan_paths": [],
        "denied_lines": [], "status_4xx": 0, "status_5xx": 0,
        "burst_lines": [], "max_rate": 0, "rate_window_s": 0,
        "inject_lines": [], "big_export_lines": [], "admin_lines": [],
        "ua": "", "chunks": [],
    }

def _cap(lst, n=8):
    return lst[:n]

class Ledger:
    def __init__(self):
        self.entities: dict[str, dict] = defaultdict(_new_entity)
        self.chunk_notes: list[dict] = []   # {chunk, lines, note}
        self.total_lines = 0

    # ---- persistence -------------------------------------------------
    def to_dict(self):
        return {"entities": self.entities, "chunk_notes": self.chunk_notes, "total_lines": self.total_lines}

    @classmethod
    def from_dict(cls, d):
        l = cls()
        for k, v in d.get("entities", {}).items():
            e = _new_entity()
            e.update(v)
            l.entities[k] = e
        l.chunk_notes = d.get("chunk_notes", [])
        l.total_lines = d.get("total_lines", 0)
        return l

    # ---- updating ----------------------------------------------------
    def update(self, chunk_index: int, numbered_raw: list[tuple[int, str]]):
        for n, raw in numbered_raw:
            self.total_lines = max(self.total_lines, n)
            d = parse_line(raw)
            if not d:
                continue
            ip = d.get("client_ip")
            if not ip:
                continue
            e = self.entities[ip]
            e["events"] += 1
            e["first_line"] = n if e["first_line"] is None else e["first_line"]
            e["last_line"] = n
            if chunk_index not in e["chunks"]:
                e["chunks"].append(chunk_index)
            ua = str(d.get("user_agent", ""))
            if ua and not e["ua"]:
                e["ua"] = ua.split(" ")[0][:30]
            path = unquote(unquote(str(d.get("path", ""))))
            status = d.get("status")
            try:
                status = int(status)
            except (TypeError, ValueError):
                status = 0
            if 400 <= status < 500:
                e["status_4xx"] += 1
            elif status >= 500:
                e["status_5xx"] += 1
            auth = d.get("auth_result")
            if auth == "invalid_password":
                e["failed_logins"] += 1
                u = str(d.get("username", "?"))
                e["fail_users"][u] = e["fail_users"].get(u, 0) + 1
                e["fail_lines"].append(n)
            elif auth == "success":
                e["success_lines"].append(n)
                u = str(d.get("username", "?"))
                if u not in e["success_users"]:
                    e["success_users"].append(u)
            if SQLI.search(path):
                e["sqli_lines"].append(n)
            if TRAVERSAL.search(path):
                e["traversal_lines"].append(n)
            if any(path.lower().startswith(p) or p in path.lower() for p in SCAN_PATHS) and status in (401, 403, 404):
                e["scan_lines"].append(n)
                p0 = path.split("?")[0]
                if p0 not in e["scan_paths"]:
                    e["scan_paths"].append(p0)
            if d.get("security_rule") == "access_denied" or status == 403:
                e["denied_lines"].append(n)
            if d.get("requests_in_window"):
                e["burst_lines"].append(n)
                e["max_rate"] = max(e["max_rate"], int(d["requests_in_window"]))
                e["rate_window_s"] = int(d.get("window_seconds", 0))
            if status == 429 and n not in e["burst_lines"]:
                e["burst_lines"].append(n)
            if INJECT_TEXT.search(str(d.get("submitted_text", ""))):
                e["inject_lines"].append(n)
            if "/export" in path and isinstance(d.get("response_bytes"), int) and d["response_bytes"] > 1_000_000:
                e["big_export_lines"].append(n)
            if "/admin" in path and status == 200:
                e["admin_lines"].append(n)

    def add_note(self, chunk_index: int, start: int, end: int, note: str):
        if note:
            self.chunk_notes.append({"chunk": chunk_index, "lines": f"{start}-{end}", "note": note[:160]})

    # ---- querying ----------------------------------------------------
    @staticmethod
    def suspicion(e: dict) -> int:
        s = 0
        s += 3 if e["failed_logins"] >= 3 else e["failed_logins"]
        s += 4 * bool(e["sqli_lines"]) + 4 * bool(e["traversal_lines"])
        s += 3 if len(e["scan_lines"]) >= 3 else len(e["scan_lines"])
        s += 3 * bool(e["burst_lines"]) + 5 * bool(e["inject_lines"])
        s += 2 * bool(e["denied_lines"])
        if e["failed_logins"] and e["success_lines"]:
            s += 5
        return s

    def suspicious_entities(self, min_score: int = 2):
        items = [(self.suspicion(e), ip, e) for ip, e in self.entities.items()]
        return [(ip, e) for sc, ip, e in sorted(items, key=lambda x: -x[0]) if sc >= min_score]

    def entity_line(self, ip: str, e: dict) -> str:
        bits = [f"{ip}: lines {e['first_line']}-{e['last_line']}"]
        if e["failed_logins"]:
            us = ",".join(f"{u}x{c}" for u, c in list(e["fail_users"].items())[:2])
            bits.append(f"failed_logins={e['failed_logins']}({us}) at L{','.join(map(str, _cap(e['fail_lines'], 3)))}..L{e['fail_lines'][-1]}")
        if e["success_lines"]:
            bits.append(f"login_success L{e['success_lines'][0]}({','.join(e['success_users'][:2])})")
        if e["sqli_lines"]:
            bits.append(f"sqli_like L{','.join(map(str, _cap(e['sqli_lines'], 3)))}")
        if e["traversal_lines"]:
            bits.append(f"traversal L{','.join(map(str, _cap(e['traversal_lines'], 2)))}")
        if e["scan_lines"]:
            bits.append(f"probe_paths={len(e['scan_paths'])} L{e['scan_lines'][0]}..L{e['scan_lines'][-1]}")
        if e["burst_lines"]:
            bits.append(f"burst max {e['max_rate']}/{e['rate_window_s']}s L{e['burst_lines'][0]}")
        if e["inject_lines"]:
            bits.append(f"instruction_text_in_payload L{e['inject_lines'][0]}")
        if e["big_export_lines"]:
            bits.append(f"large_export L{e['big_export_lines'][0]}")
        if e["admin_lines"]:
            bits.append(f"admin_access L{e['admin_lines'][0]}")
        return "; ".join(bits)

    def render_for_prompt(self, count_tokens, budget: int, current_ips: set[str]) -> str:
        """Compact ledger summary under a token budget. Prioritises entities active in this chunk."""
        ents = self.suspicious_entities()
        ents.sort(key=lambda x: (x[0] not in current_ips, -self.suspicion(x[1])))
        out: list[str] = []
        used = 0
        for ip, e in ents:
            line = self.entity_line(ip, e)
            t = count_tokens(line) + 1
            if used + t > budget:
                break
            out.append(line)
            used += t
        if not out:
            return "(nothing suspicious so far)"
        return "\n".join(out)

    def all_event_lines(self) -> set:
        keys = ("fail_lines", "success_lines", "sqli_lines", "traversal_lines", "scan_lines",
                "denied_lines", "burst_lines", "inject_lines", "big_export_lines", "admin_lines")
        s = set()
        for e in self.entities.values():
            for k in keys:
                s.update(e[k])
        return s
