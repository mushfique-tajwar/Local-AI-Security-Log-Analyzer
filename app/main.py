"""FastAPI backend: upload, queue (one job at a time), progress, report."""
import queue
import re
import threading
from pathlib import Path

from contextlib import asynccontextmanager

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .analyzer import Analyzer, Job, new_job, rss_mb
from .llm import get_llm

STATIC = Path(__file__).resolve().parent.parent / "static"
llm = get_llm()
analyzer = Analyzer(llm)
jobs: dict[str, Job] = {}
q: "queue.Queue[str]" = queue.Queue()
ALLOWED_EXT = {".log", ".txt"}

def _worker():
    while True:
        jid = q.get()
        job = jobs.get(jid)
        if job and job.d["status"] in ("queued", "running", "failed", "partial") and not job.d["cancel"]:
            analyzer.run(job)
        q.task_done()

@asynccontextmanager
async def lifespan(_app):
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    config.JOB_DIR.mkdir(parents=True, exist_ok=True)
    for p in sorted(config.JOB_DIR.glob("*.json")):
        try:
            j = Job.load(p)
        except Exception:
            continue
        jobs[j.id] = j
        if j.d["status"] == "running":      # interrupted by restart -> resume from checkpoint
            j.d["status"] = "queued"
            j.event("Server restarted; resuming from last completed chunk")
            q.put(j.id)
    threading.Thread(target=_worker, daemon=True).start()
    yield

app = FastAPI(title="Local AI Security Log Analyzer", lifespan=lifespan)

def _validate_upload(name: str, head: bytes, size: int):
    ext = Path(name or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(400, "Only .log or .txt files are accepted.")
    if size == 0 or not head.strip():
        raise HTTPException(400, "The file is empty.")
    if b"\x00" in head:
        raise HTTPException(400, "This looks like a binary file, not a text log.")

@app.post("/api/upload")
async def upload(file: UploadFile = File(...)):
    name = re.sub(r"[^A-Za-z0-9._-]", "_", file.filename or "upload.log")[:80]
    job = new_job(name, config.UPLOAD_DIR / "pending")
    dest = config.UPLOAD_DIR / f"{job.id}_{name}"
    size, head = 0, b""
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    try:
        with open(dest, "wb") as out:
            while True:
                buf = await file.read(1 << 20)
                if not buf:
                    break
                if not head:
                    head = buf[:8192]
                size += len(buf)
                if size > config.MAX_UPLOAD_BYTES:
                    raise HTTPException(413, f"File too large (limit {config.MAX_UPLOAD_BYTES // 1048576} MB).")
                out.write(buf)
        _validate_upload(name, head, size)
    except HTTPException:
        dest.unlink(missing_ok=True)
        raise
    job.d["path"] = str(dest)
    job.d["size_bytes"] = size
    jobs[job.id] = job
    job.save()
    return {"job_id": job.id, "filename": name, "size_bytes": size}

def _get(job_id: str) -> Job:
    j = jobs.get(job_id)
    if not j:
        raise HTTPException(404, "Unknown job.")
    return j

@app.post("/api/jobs/{job_id}/start")
def start(job_id: str):
    j = _get(job_id)
    if j.d["status"] in ("running",):
        raise HTTPException(409, "Already running.")
    if j.d["status"] in ("done",):
        raise HTTPException(409, "Already finished.")
    j.d["cancel"] = False
    j.d["status"] = "queued"
    j.event("Queued")
    j.save()
    q.put(j.id)
    return j.public()

@app.post("/api/jobs/{job_id}/resume")
def resume(job_id: str):
    return start(job_id)

@app.post("/api/jobs/{job_id}/cancel")
def cancel(job_id: str):
    j = _get(job_id)
    j.d["cancel"] = True
    j.event("Cancel requested")
    j.save()
    return j.public()

@app.get("/api/jobs/{job_id}")
def status(job_id: str):
    return _get(job_id).public()

@app.get("/api/jobs")
def list_jobs():
    return [{"id": j.id, "filename": j.d["filename"], "status": j.d["status"], "created": j.d["created"]}
            for j in sorted(jobs.values(), key=lambda x: -x.d["created"])][:20]

@app.get("/api/jobs/{job_id}/report")
def report(job_id: str, format: str = "json"):
    j = _get(job_id)
    r = j.d["report"]
    if r is None:
        raise HTTPException(409, "Report not ready yet.")
    if format == "md":
        return PlainTextResponse(to_markdown(r), media_type="text/markdown")
    return JSONResponse(r)

@app.get("/api/status")
def system_status():
    return {"model": llm.name, "model_present": llm.available(), "engine": llm.kind, "rss_mb": rss_mb(),
            "ram_limit_mb": config.RAM_LIMIT_MB, "context": config.N_CTX, "max_upload_mb": config.MAX_UPLOAD_BYTES // 1048576}

def to_markdown(r: dict) -> str:
    L = [f"# Security log report: {r['file']}", "", r.get("summary", ""), ""]
    c = r["counts"]
    L.append(f"**Findings:** Critical {c['Critical']} · High {c['High']} · Medium {c['Medium']} · Low {c['Low']}\n")
    for f in r["findings"]:
        L += [f"## [{f['severity']}] {f['attack_type']} - {f['entity']}", f"- Reason: {f['reason']}",
              f"- Action: {f['action']}", f"- Verified by log facts: {f['verified_by_log_facts']}", "- Evidence:"]
        L += [f"  - L{e['line']}: `{e['text']}`" for e in f["evidence"]]
        L.append("")
    if r["unconfirmed_signals"]:
        L.append("## Unconfirmed rule signals (not AI)")
        L += [f"- {s['summary']}" for s in r["unconfirmed_signals"]]
    s = r["stats"]
    L += ["", f"_Model {s['model']}: {s['model_calls']} calls over {s['chunks']} chunks, peak RSS {s['peak_rss_mb']} MB_"]
    return "\n".join(L)

@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")

app.mount("/static", StaticFiles(directory=STATIC), name="static")
