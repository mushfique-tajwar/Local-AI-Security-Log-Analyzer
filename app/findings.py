"""Normalisation, validation, fact-checking and merging of model findings.

The model proposes; this module disposes. A finding survives only if it has a valid type,
severity, an entity and at least one evidence line that exists in the log. Findings whose
claim is not supported by the ledger facts are capped at Low and marked unverified, so
normal errors cannot become 'confirmed attacks'.
"""
import re

from .prompts import ATTACK_TYPES

SEVERITIES = ["Low", "Medium", "High", "Critical"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

_ALIASES = {
    "bruteforce": "brute_force", "brute force": "brute_force", "credential_stuffing": "brute_force",
    "repeated_login_attempts": "brute_force", "password_guessing": "brute_force",
    "account_takeover": "account_compromise", "account compromise": "account_compromise",
    "compromised_account": "account_compromise", "successful_login_after_failures": "account_compromise",
    "sqli": "sql_injection", "sql injection": "sql_injection", "sql-injection": "sql_injection",
    "directory_traversal": "path_traversal", "path traversal": "path_traversal", "lfi": "path_traversal",
    "port_scan": "scanning", "recon": "scanning", "reconnaissance": "scanning", "vulnerability_scan": "scanning",
    "ddos": "rate_abuse", "dos": "rate_abuse", "rate_limit_abuse": "rate_abuse", "unusual_request_rate": "rate_abuse",
    "request_flood": "rate_abuse", "scraping": "rate_abuse",
    "unauthorised_access": "unauthorized_access", "unauthorized access": "unauthorized_access",
    "privilege_escalation": "unauthorized_access", "forbidden_access": "unauthorized_access",
    "exfiltration": "data_exfiltration", "data_theft": "data_exfiltration", "bulk_export": "data_exfiltration",
    "prompt injection": "prompt_injection", "llm_injection": "prompt_injection",
}


def norm_type(t) -> str:
    t = str(t or "").strip().lower().replace("-", "_")
    t = re.sub(r"\s+", "_", t) if t not in _ALIASES else t
    if t in ATTACK_TYPES:
        return t
    if t in _ALIASES:
        return _ALIASES[t]
    t2 = t.replace("_", " ")
    if t2 in _ALIASES:
        return _ALIASES[t2]
    return "other"


def norm_sev(s) -> str:
    s = str(s or "").strip().capitalize()
    if s in _SEV_RANK:
        return s
    return {"Info": "Low", "Informational": "Low", "Moderate": "Medium", "Severe": "High", "Crit": "Critical"}.get(s, "Low")


def _ints(v) -> list[int]:
    out = []
    if isinstance(v, (int, str)):
        v = [v]
    if not isinstance(v, list):
        return out
    for x in v:
        if isinstance(x, int):
            out.append(x)
        elif isinstance(x, str):
            for m in re.finditer(r"\d+", x):
                out.append(int(m.group(0)))
    return out


def normalise(raw: dict, valid_lines: set[int], chunk_index: int | None = None) -> dict | None:
    """Return a clean finding or None if it fails validation."""
    entity = str(raw.get("entity") or raw.get("ip") or "").strip()
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", entity)
    entity = m.group(0) if m else entity[:60]
    lines = sorted({n for n in _ints(raw.get("lines") or raw.get("evidence")) if n in valid_lines})
    if not entity or not lines:
        return None
    return {
        "attack_type": norm_type(raw.get("attack_type") or raw.get("type")),
        "severity": norm_sev(raw.get("severity")),
        "entity": entity,
        "lines": lines[:12],
        "reason": str(raw.get("reason") or "")[:240],
        "action": str(raw.get("action") or raw.get("suggested_action") or "")[:160],
        "chunks": [chunk_index] if chunk_index is not None else [],
    }


def _support(f: dict, e: dict | None) -> tuple[bool, list[int]]:
    """Does the ledger back this claim? Also returns ledger evidence lines for that claim."""
    if not e:
        return False, []
    t = f["attack_type"]
    if t == "brute_force":
        return e["failed_logins"] >= 3, e["fail_lines"]
    if t == "account_compromise":
        ok = e["failed_logins"] >= 1 and bool(e["success_lines"])
        return ok, e["fail_lines"][-2:] + e["success_lines"][:2]
    if t == "sql_injection":
        return bool(e["sqli_lines"]), e["sqli_lines"]
    if t == "path_traversal":
        return bool(e["traversal_lines"]), e["traversal_lines"]
    if t == "scanning":
        return len(e["scan_lines"]) >= 3 or len(e["scan_paths"]) >= 2, e["scan_lines"]
    if t == "rate_abuse":
        return bool(e["burst_lines"]), e["burst_lines"]
    if t == "unauthorized_access":
        return bool(e["denied_lines"] or e["admin_lines"]), e["denied_lines"] + e["admin_lines"]
    if t == "data_exfiltration":
        return bool(e["big_export_lines"]), e["big_export_lines"]
    if t == "prompt_injection":
        return bool(e["inject_lines"]), e["inject_lines"]
    return False, []


def fact_check(f: dict, ledger) -> dict:
    e = ledger.entities.get(f["entity"])
    ok, lines = _support(f, e)
    f["verified"] = ok
    if ok:
        f["lines"] = sorted(set(f["lines"]) | set(_compress(lines)))[:14]
        if f["attack_type"] == "account_compromise" and _SEV_RANK[f["severity"]] < _SEV_RANK["High"]:
            f["severity"] = "High"
    else:
        # a claim the facts don't back is never more than a Low lead
        f["severity"] = "Low"
        f["reason"] = ("[unverified by log facts] " + f["reason"])[:260]
    return f


def _compress(lines: list[int], keep: int = 6) -> list[int]:
    """Keep first/last few lines of a long list so evidence stays readable."""
    if len(lines) <= keep:
        return lines
    h = keep // 2
    return lines[:h] + lines[-h:]


def merge(findings: list[dict]) -> list[dict]:
    """Combine duplicate (type, entity) findings from different chunks into one."""
    groups: dict[tuple, dict] = {}
    for f in findings:
        k = (f["attack_type"], f["entity"])
        g = groups.get(k)
        if g is None:
            groups[k] = dict(f, lines=list(f["lines"]), chunks=list(f["chunks"]))
            continue
        g["lines"] = sorted(set(g["lines"]) | set(f["lines"]))[:14]
        g["chunks"] = sorted(set(g["chunks"]) | set(f["chunks"]))
        if _SEV_RANK[f["severity"]] > _SEV_RANK[g["severity"]]:
            g["severity"] = f["severity"]
        if len(f["reason"]) > len(g["reason"]):
            g["reason"] = f["reason"]
        if not g["action"]:
            g["action"] = f["action"]
    out = list(groups.values())
    out.sort(key=lambda f: (-_SEV_RANK[f["severity"]], f["lines"][0] if f["lines"] else 0))
    return out


def sev_rank(s: str) -> int:
    return _SEV_RANK.get(s, 0)
