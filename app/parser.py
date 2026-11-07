"""Light log-line parsing used for (a) compact prompt digests and (b) the cross-chunk ledger.

Parsing never decides what an attack is; it only extracts facts (counts, first/last line
numbers) that are handed to the local model as context and used to validate its output.
Supports JSON-lines logs and common/combined access-log lines; unknown lines pass through.
"""
import json
import re
from typing import Optional

_ACCESS = re.compile(
    r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" (?P<status>\d{3}) (?P<bytes>\S+)'
)
_SYSLOG_FAIL = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)')
_SYSLOG_OK = re.compile(r'Accepted \w+ for (?P<user>\S+) from (?P<ip>\S+)')

# keys worth keeping in the prompt digest, in order
_KEEP = ["service", "level", "client_ip", "method", "path", "status", "username",
         "auth_result", "security_rule", "message", "exception", "procedure", "location",
         "upstream", "http_status", "user_agent_short", "requests_in_window", "window_seconds",
         "submitted_text", "validation_error", "upstream_error", "session_id", "release",
         "items_failed", "response_bytes_big"]


def parse_line(raw: str) -> Optional[dict]:
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            d = json.loads(raw)
            if isinstance(d, dict):
                return d
        except json.JSONDecodeError:
            pass
    m = _ACCESS.match(raw)
    if m:
        d = m.groupdict()
        d["client_ip"] = d.pop("ip")
        d["status"] = int(d["status"])
        d["path"] = d["path"]
        return d
    m = _SYSLOG_FAIL.search(raw)
    if m:
        return {"client_ip": m["ip"], "username": m["user"], "auth_result": "invalid_password",
                "path": "/ssh", "method": "AUTH", "status": 401, "message": raw[:120]}
    m = _SYSLOG_OK.search(raw)
    if m:
        return {"client_ip": m["ip"], "username": m["user"], "auth_result": "success",
                "path": "/ssh", "method": "AUTH", "status": 200, "message": raw[:120]}
    return None


def _short_ua(ua: str) -> str:
    if not ua:
        return ""
    if ua.startswith("Mozilla/"):
        return "browser"
    return ua.split(" ")[0][:24]


def digest(raw: str, max_text: int = 110) -> str:
    """Compact, token-cheap rendering of one log line. Falls back to the raw text."""
    d = parse_line(raw)
    if d is None:
        return raw.strip()[: 240]
    d = dict(d)
    t = str(d.get("time", ""))
    short_t = t[11:19] if len(t) >= 19 else t
    app = str(d.get("app", ""))
    ua = _short_ua(str(d.get("user_agent", "")))
    if ua and ua != "browser":
        d["user_agent_short"] = ua
    if isinstance(d.get("response_bytes"), int) and d["response_bytes"] > 1_000_000:
        d["response_bytes_big"] = d["response_bytes"]
    parts = [short_t, app.replace("cultive8 workspace", "ws")]
    for k in _KEEP:
        if k in d and d[k] not in (None, ""):
            v = str(d[k])
            if k in ("submitted_text", "message"):
                v = v[:max_text]
            elif k == "path":
                v = v[:90]
            parts.append(f"{k.replace('client_ip','ip')}={v}")
    return " ".join(p for p in parts if p)
