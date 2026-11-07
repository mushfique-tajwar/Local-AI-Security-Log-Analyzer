# Multi-call analysis pipeline: chunk -> ledger -> model call -> validate -> checkpoint -> link -> report
import json
import os
import threading
import time
import uuid
from pathlib import Path

import psutil

from . import config, prompts
from .chunker import Chunk, split_lines
from .findings import fact_check, merge, normalise, sev_rank
from .jsonrepair import parse_model_json
from .ledger import Ledger
from .llm import LLMError, LLMTimeout
from .parser import digest

_proc = psutil.Process(os.getpid())


def rss_mb() -> float:
    """Resident memory of this process (backend + model)."""
    return round(_proc.memory_info().rss / 1048576, 1)


def _read_lines(path: Path):
    # streamed; never loads the whole file
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            yield line


class Job:
    """Persistent job state. Saved atomically after every chunk so a restart can resume."""

    def __init__(self, job_id: str, filename: str, path: Path):
        self.d = {
            "id": job_id, "filename": filename, "path": str(path), "status": "queued",
            "created": time.time(), "started": None, "finished": None,
            "total_chunks": 0, "chunks": [], "findings": [], "ledger": None, "ledger_upto": -1,
            "report": None, "error": None, "events": [], "peak_rss_mb": 0.0, "cancel": False,
            "stats": {"model_calls": 0, "retries": 0, "model_seconds": 0.0, "prompt_tokens": 0,
                      "invalid_json": 0, "timeouts": 0, "splits": 0},
            "phase": "queued",
        }
        self.lock = threading.Lock()

    @property
    def id(self):
        return self.d["id"]

    def event(self, msg: str):
        ev = self.d["events"]
        ev.append({"t": round(time.time(), 1), "msg": msg})
        del ev[:-80]

    def save(self):
        config.JOB_DIR.mkdir(parents=True, exist_ok=True)
        p = config.JOB_DIR / f"{self.id}.json"
        tmp = p.with_suffix(".tmp")
        with self.lock:
            tmp.write_text(json.dumps(self.d))
            os.replace(tmp, p)

    @classmethod
    def load(cls, p: Path):
        d = json.loads(p.read_text())
        j = cls(d["id"], d["filename"], Path(d["path"]))
        j.d = d
        return j

    def public(self) -> dict:
        d = self.d
        done = sum(1 for c in d["chunks"] if c["status"] in ("done", "failed"))
        return {
            "id": d["id"], "filename": d["filename"], "status": d["status"], "phase": d["phase"],
            "total_chunks": d["total_chunks"], "done_chunks": done,
            "chunks": d["chunks"], "stats": d["stats"], "error": d["error"],
            "events": d["events"][-12:], "rss_mb": rss_mb(), "peak_rss_mb": d["peak_rss_mb"],
            "elapsed_s": round((d["finished"] or time.time()) - d["started"], 1) if d["started"] else 0,
            "has_report": d["report"] is not None,
        }


class Analyzer:
    def __init__(self, llm):
        self.llm = llm
        self._sys_tokens = None
        self._wrapper_tokens = None

    # ------------------------------------------------------------ budget
    def budgets(self):
        """Token budget plan. prompt(system+ledger+log+wrapper) + output + margin <= N_CTX."""
        if self._sys_tokens is None:
            self._sys_tokens = self.llm.count_messages([{"role": "system", "content": prompts.CHUNK_SYSTEM}])
            self._wrapper_tokens = self.llm.count_tokens(prompts.chunk_user("", 99999, 99999, ""))
        log_budget = (config.N_CTX - config.MAX_OUTPUT_TOKENS - config.SAFETY_MARGIN
                      - self._sys_tokens - self._wrapper_tokens - config.LEDGER_BUDGET - 8)
        if log_budget < 200:
            raise RuntimeError(f"Token budget too small for log text ({log_budget}); lower LEDGER_BUDGET/MAX_OUTPUT_TOKENS")
        return {"context": config.N_CTX, "system": self._sys_tokens, "wrapper": self._wrapper_tokens,
                "ledger": config.LEDGER_BUDGET, "output": config.MAX_OUTPUT_TOKENS,
                "margin": config.SAFETY_MARGIN, "log": log_budget}

    def iter_chunks(self, path: Path):
        b = self.budgets()["log"]
        return split_lines(_read_lines(path), self.llm.count_tokens, b, render=digest)

    # ------------------------------------------------------------ run
    def run(self, job: Job):
        d = job.d
        try:
            d["status"], d["phase"] = "running", "planning"
            d["started"] = d["started"] or time.time()
            job.save()
            path = Path(d["path"])
            self.llm.load()
            job.event(f"Model {self.llm.name} ready (load {self.llm.load_seconds}s)")
            plan = [(c.index, c.start_line, c.end_line, c.tokens) for c in self.iter_chunks(path)]
            d["total_chunks"] = len(plan)
            if not d["chunks"]:
                d["chunks"] = [{"index": i, "lines": f"{s}-{e}", "tokens": t, "status": "pending", "attempts": 0,
                                "ms": 0, "findings": 0, "note": "", "error": None} for i, s, e, t in plan]
            job.event(f"Split into {len(plan)} chunks within a {self.budgets()['log']}-token log budget")
            job.save()

            ledger = Ledger.from_dict(d["ledger"]) if d["ledger"] else Ledger()
            d["phase"] = "analyzing"
            for ch in self.iter_chunks(path):
                if d["cancel"]:
                    d["status"], d["phase"] = "cancelled", "cancelled"
                    job.save()
                    return
                meta = d["chunks"][ch.index]
                if ch.index > d["ledger_upto"]:
                    ledger.update(ch.index, ch.raw)
                    d["ledger_upto"] = ch.index
                if meta["status"] == "done":
                    continue
                self._process_chunk(job, ledger, ch, meta)
                d["ledger"] = ledger.to_dict()
                d["peak_rss_mb"] = max(d["peak_rss_mb"], rss_mb())
                job.save()

            d["phase"] = "linking"
            job.event("Linking findings across chunks")
            job.save()
            summary = self._link(job, ledger)
            d["phase"] = "reporting"
            d["report"] = self._report(job, ledger, summary, path)
            failed = [c for c in d["chunks"] if c["status"] == "failed"]
            d["status"] = "partial" if failed else "done"
            d["phase"] = "finished"
            d["finished"] = time.time()
            job.event(f"Finished: {len(d['report']['findings'])} findings" + (f", {len(failed)} chunks failed" if failed else ""))
        except Exception as e:  # never crash the worker; keep what is saved
            d["status"], d["phase"], d["error"] = "failed", "failed", f"{type(e).__name__}: {e}"
            d["finished"] = time.time()
            job.event(f"Job failed: {d['error']}")
        finally:
            d["peak_rss_mb"] = max(d["peak_rss_mb"], rss_mb())
            job.save()

    # ------------------------------------------------------------ one chunk
    def _build(self, ledger: Ledger, start: int, end: int, lines: list[str], ips: set, ledger_budget: int):
        ltxt = ledger.render_for_prompt(self.llm.count_tokens, ledger_budget, ips)
        msgs = [{"role": "system", "content": prompts.CHUNK_SYSTEM},
                {"role": "user", "content": prompts.chunk_user(ltxt, start, end, "\n".join(lines))}]
        return msgs

    def _call(self, job: Job, ledger: Ledger, start, end, lines, raws, meta) -> tuple[list[dict], str]:
        """One bounded model call with retries. Raises LLMError if it ultimately fails."""
        d = job.d
        ips = set()
        for _, r in raws:
            from .parser import parse_line
            p = parse_line(r)
            if p and p.get("client_ip"):
                ips.add(p["client_ip"])
        lb = config.LEDGER_BUDGET
        msgs = self._build(ledger, start, end, lines, ips, lb)
        used = self.llm.count_messages(msgs)
        while used + config.MAX_OUTPUT_TOKENS + config.SAFETY_MARGIN > config.N_CTX and lb > 40:
            lb //= 2
            msgs = self._build(ledger, start, end, lines, ips, lb)
            used = self.llm.count_messages(msgs)
        if used + config.MAX_OUTPUT_TOKENS + config.SAFETY_MARGIN > config.N_CTX:
            raise LLMError(f"prompt of {used} tokens does not fit the {config.N_CTX}-token context")
        d["stats"]["prompt_tokens"] += used
        meta["prompt_tokens"] = used
        last = ""
        for attempt in range(config.MAX_RETRIES + 1):
            meta["attempts"] += 1
            if attempt:
                d["stats"]["retries"] += 1
                msgs = [msgs[0], {"role": "user", "content": msgs[1]["content"].replace(prompts.NOTHINK, "") + prompts.RETRY_NUDGE + prompts.NOTHINK}]
            t0 = time.time()
            try:
                text = self.llm.chat(msgs, config.MAX_OUTPUT_TOKENS, config.LLM_TIMEOUT_S)
                d["stats"]["model_calls"] += 1
                d["stats"]["model_seconds"] = round(d["stats"]["model_seconds"] + time.time() - t0, 2)
            except LLMTimeout as e:
                d["stats"]["timeouts"] += 1
                last = str(e)
                job.event(f"Chunk {meta['index']}: timeout (attempt {attempt + 1})")
                continue
            except LLMError as e:
                last = str(e)
                job.event(f"Chunk {meta['index']}: model error (attempt {attempt + 1}): {last[:80]}")
                time.sleep(0.5)
                continue
            data, clean = parse_model_json(text)
            if not clean:
                d["stats"]["invalid_json"] += 1
            if clean or data["findings"]:
                return data["findings"], data["note"]
            last = "unparseable model output"
            job.event(f"Chunk {meta['index']}: invalid JSON (attempt {attempt + 1})")
        raise LLMError(last or "model call failed")

    def _process_chunk(self, job: Job, ledger: Ledger, ch: Chunk, meta: dict):
        d = job.d
        meta["status"] = "running"
        t0 = time.time()
        lines = ch.text.split("\n")
        try:
            raw_findings, note = self._run_range(job, ledger, ch.start_line, ch.end_line, lines, ch.raw, meta, depth=0)
            valid = {n for n, _ in ch.raw} | ledger.all_event_lines()
            n_ok = 0
            for rf in raw_findings:
                f = normalise(rf, valid, ch.index)
                if f:
                    d["findings"].append(f)
                    n_ok += 1
            meta.update(status="done", findings=n_ok, note=note[:160], error=None)
            ledger.add_note(ch.index, ch.start_line, ch.end_line, note)
        except Exception as e:
            meta.update(status="failed", error=f"{type(e).__name__}: {str(e)[:160]}")
            job.event(f"Chunk {ch.index} failed after retries: {meta['error']}")
        meta["ms"] = int((time.time() - t0) * 1000)

    def _run_range(self, job, ledger, start, end, lines, raws, meta, depth):
        """Try the range; on repeated failure split it in half (up to 2 levels) so a bad call
        costs less and completed halves are kept."""
        try:
            return self._call(job, ledger, start, end, lines, raws, meta)
        except (LLMError, LLMTimeout):
            if depth >= 2 or len(lines) < 2:
                raise
            job.d["stats"]["splits"] += 1
            job.event(f"Chunk {meta['index']}: splitting {start}-{end} after failures")
            k = len(lines) // 2
            a = self._run_range(job, ledger, raws[0][0], raws[k - 1][0], lines[:k], raws[:k], meta, depth + 1)
            b = self._run_range(job, ledger, raws[k][0], raws[-1][0], lines[k:], raws[k:], meta, depth + 1)
            return a[0] + b[0], (a[1] + " " + b[1]).strip()

    # ------------------------------------------------------------ link + report
    def _link(self, job: Job, ledger: Ledger) -> str:
        d = job.d
        base = merge([fact_check(dict(f), ledger) for f in d["findings"]])
        lines = [f"- {f['attack_type']} {f['entity']} {f['severity']} L{','.join(map(str, f['lines'][:4]))}" for f in base]
        ftxt = "\n".join(lines[:14]) or "(none)"
        ents = set(f["entity"] for f in base)
        ledger_txt = ledger.render_for_prompt(self.llm.count_tokens, 520, ents)
        msgs = [{"role": "system", "content": prompts.LINK_SYSTEM},
                {"role": "user", "content": prompts.link_user(ftxt, ledger_txt)}]
        while self.llm.count_messages(msgs) + config.MAX_OUTPUT_TOKENS + config.SAFETY_MARGIN > config.N_CTX and len(lines) > 3:
            lines = lines[:-2]
            msgs[1]["content"] = prompts.link_user("\n".join(lines), ledger_txt)
        try:
            text = self.llm.chat(msgs, config.MAX_OUTPUT_TOKENS, config.LLM_TIMEOUT_S)
            d["stats"]["model_calls"] += 1
            data, _ = parse_model_json(text)
            valid = ledger.all_event_lines()
            for rf in data["findings"]:
                f = normalise(rf, valid, None)
                if f:
                    d["findings"].append(f)
            return data["note"]
        except (LLMError, LLMTimeout) as e:
            job.event(f"Linking call failed ({e}); report built from per-chunk findings")
            return ""

    def _report(self, job: Job, ledger: Ledger, summary: str, path: Path) -> dict:
        d = job.d
        final = merge([fact_check(dict(f), ledger) for f in d["findings"]])
        need = {n for f in final for n in f["lines"]}
        text = {}
        for n, raw in enumerate(_read_lines(path), start=1):
            if n in need:
                text[n] = digest(raw.rstrip("\n"))[:260]
        out = []
        for i, f in enumerate(final, 1):
            e = ledger.entities.get(f["entity"], {})
            out.append({
                "id": i, "attack_type": f["attack_type"], "severity": f["severity"], "entity": f["entity"],
                "accounts": sorted(set((e.get("fail_users") or {}).keys()) | set(e.get("success_users") or []))[:4]
                if f["attack_type"] in ("brute_force", "account_compromise") else [],
                "evidence": [{"line": n, "text": text.get(n, "")} for n in f["lines"]],
                "reason": f["reason"], "action": f["action"], "chunks": f["chunks"],
                "verified_by_log_facts": f.get("verified", False), "source": "local-model",
            })
        # leads the rules saw but the model did not report (kept separate, clearly labelled)
        reported = {(f["entity"]) for f in final if f["severity"] != "Low" or f.get("verified")}
        signals = []
        for ip, e in ledger.suspicious_entities(min_score=4):
            if ip not in reported:
                signals.append({"entity": ip, "summary": ledger.entity_line(ip, e), "source": "rule-counted facts (not AI)"})
        stats = d["stats"]
        calls = max(1, stats["model_calls"])
        return {
            "job_id": d["id"], "file": d["filename"], "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summary or "",
            "counts": {s: sum(1 for f in out if f["severity"] == s) for s in ("Critical", "High", "Medium", "Low")},
            "findings": out, "unconfirmed_signals": signals[:8],
            "notes_per_chunk": ledger.chunk_notes,
            "stats": {
                "lines": ledger.total_lines, "chunks": d["total_chunks"],
                "failed_chunks": sum(1 for c in d["chunks"] if c["status"] == "failed"),
                "model": self.llm.name, "model_calls": stats["model_calls"], "retries": stats["retries"],
                "timeouts": stats["timeouts"], "invalid_json": stats["invalid_json"], "splits": stats["splits"],
                "avg_call_s": round(stats["model_seconds"] / calls, 2),
                "peak_rss_mb": d["peak_rss_mb"], "ram_limit_mb": config.RAM_LIMIT_MB,
                "token_budget": self.budgets(),
            },
        }


def new_job(filename: str, path: Path) -> Job:
    return Job(uuid.uuid4().hex[:12], filename, path)
