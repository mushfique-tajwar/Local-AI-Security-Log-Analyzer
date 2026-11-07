"""Tolerant JSON extraction for small-model output. Never raises."""
import json
import re

_FENCE = re.compile(r"```(?:json)?|```", re.I)


def _close(s: str) -> str:
    """Close unterminated strings/brackets in truncated JSON."""
    stack, in_str, esc = [], False, False
    out = []
    for ch in s:
        out.append(ch)
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch in "{[":
            stack.append("}" if ch == "{" else "]")
        elif ch in "}]" and stack:
            stack.pop()
    text = "".join(out)
    if in_str:
        text += '"'
    text = re.sub(r",\s*$", "", text)
    return text + "".join(reversed(stack))


def parse_model_json(text: str) -> tuple[dict, bool]:
    """Return (data, clean). clean=False means repaired/salvaged. data always has 'findings' list."""
    empty = {"findings": [], "note": ""}
    if not text:
        return empty, False
    t = _FENCE.sub("", text).strip()
    i = t.find("{")
    if i < 0:
        return empty, False
    t = t[i:]
    try:
        d = json.loads(t)
        return _norm(d), True
    except json.JSONDecodeError:
        pass
    try:
        return _norm(json.loads(_close(t))), False
    except json.JSONDecodeError:
        pass
    # last resort: salvage individual flat objects that look like findings
    found = []
    for m in re.finditer(r"\{[^{}]*\}", t):
        try:
            o = json.loads(m.group(0))
            if isinstance(o, dict) and "attack_type" in o:
                found.append(o)
        except json.JSONDecodeError:
            continue
    return ({"findings": found, "note": ""}, False) if found else (empty, False)


def _norm(d) -> dict:
    if isinstance(d, list):
        d = {"findings": d}
    if not isinstance(d, dict):
        return {"findings": [], "note": ""}
    f = d.get("findings", [])
    if not isinstance(f, list):
        f = []
    note = d.get("note", "")
    return {"findings": [x for x in f if isinstance(x, dict)], "note": note if isinstance(note, str) else ""}
