# Local AI Security Log Analyzer

A web app that finds possible attacks in server logs using a local language model (llama.cpp, CPU only, no cloud AI APIs). Logs larger than the model's 2,048-token context are split, analysed in several calls, linked across parts, and merged into one final report.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate # for Linux users
#python -m venv .venv && source .venv/bin/activate # for Windows users
pip install -r requirements.txt
python scripts/download_model.py --size 0.8b    # Smaller, Faster, Less accurate
#python scripts/download_model.py          # Larger, Slower, More accurate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Open http://localhost:8000, upload a `.log`/`.txt` file, press **Start analysis**. Once a model is downloaded the app works fully offline, no internet connection is needed and no need to re-download.


## Model details

| Item | Value |
|---|---|
| Runtime | llama.cpp through `llama-cpp-python`, CPU only |
| Default model | Qwen3.5 0.8B, GGUF Q4_K_M (`unsloth/Qwen3.5-0.8B-GGUF`); Qwen3.5 2B also supported |
| Context | `n_ctx=2048`, `n_threads=2`, `n_batch=256`, mmap on |
| Decoding | temperature 0, JSON-grammar-constrained output (`response_format=json_object`) |

RAM: only one model instance exists and calls run one at a time. The log is streamed line by line, so only the current chunk (about 900 tokens) is held in memory. The job page shows live and peak RSS against the 4 GB limit.

## Token budget (per call, 2,048 tokens)

Computed at startup from the model's own tokenizer (`GET /api/status`, `stats.token_budget` in the report):

| Part | Tokens |
|---|---|
| System prompt | measured (~280) |
| User wrapper | measured (~40) |
| Carried ledger ("KNOWN FACTS") | up to 260 |
| **Log text** | **remainder (~900)** |
| Model reply | 450 max |
| Safety margin | 64 |

Before every call the real prompt is re-counted; if it would overflow, the ledger is halved until it fits.

## Log splitting method

1. The file is streamed. One non-empty line = one log entry, so entries are never cut. Chunks are made of whole lines only.
2. Each line is rendered as `L<original line number>|<compact digest>`. The digest keeps security-relevant fields (time, ip, method, path, status, user, auth result, error text) and drops noise (user-agent strings, byte counts, durations). This is how about 20k tokens of raw JSON fits in far fewer calls without losing evidence.
3. Chunks are filled to the log-token budget. A single oversized line is truncated with a marker but keeps its line number.
4. Line numbers are original, so evidence is traceable.

## Linking events across parts

After each chunk, a **ledger** is updated with counted facts per IP: failed logins (and users), successes, SQLi-looking and traversal strings, probe paths, 403s, burst rates, instruction-like text, large exports, admin access, with first/last line numbers. The ledger is **facts, not verdicts**. For every later call, the most relevant entries (IPs in the current chunk first) are rendered into a compact budgeted block, so a successful login in chunk 5 is seen next to the failures from chunks 1-3.

After all chunks, one final model call receives the merged findings plus whole-file facts and may add cross-chunk findings (for example brute force followed by account compromise) and write the summary. Duplicates `(attack_type, IP)` are merged into one finding with combined evidence lines and the highest severity.

## Accuracy safeguards

- Model output is validated: attack type and severity normalised, evidence lines must exist in the log, entity required. Invented line numbers drop the finding.
- **Fact check:** a finding the ledger facts do not support is capped at *Low* and labelled "unverified". Normal errors (timeouts, 500/502/503, deploy downtime, retries, health checks) are told to the model as non-attacks, and cannot become confirmed attacks without evidence.
- "Unconfirmed rule signals" lists entities the counters flagged but the model did not report. They are clearly labelled **not AI** and are never counted as findings.
- Log text is wrapped in delimiters, delimiter strings inside logs are neutralised, and the system prompt says logs are data. Instruction-like text in a log is reported as `prompt_injection`, never obeyed. Nothing in a log is executed.

## Reliability

- Upload checks: extension `.log`/`.txt`, non-empty, no NUL bytes (binary), size limit (default 5 MB), streamed to disk.
- Per call: wall-clock timeout (default 180 s), up to 2 retries, then the chunk is split in half (two levels) so a bad call costs less. Chunks that still fail are marked failed and the job finishes as `partial` with everything else kept.
- Broken or truncated JSON is repaired (close brackets, salvage individual findings); unparseable output counts as a failed attempt, never a crash.
- Every chunk result is checkpointed to `data/jobs/<id>.json`. If the server restarts, running jobs resume from the last completed chunk (the model is not re-run for finished chunks).
- One job runs at a time through a queue, which bounds RAM.

## API

`POST /api/upload`

`POST /api/jobs/{id}/start|cancel|resume`

`GET /api/jobs/{id}`

`GET /api/jobs/{id}/report?format=json|md`

`GET /api/status`

## Known limits

- Accuracy depends on the small model. The ledger and fact check reduce misses and false alarms, but a 0.8B-2B model can still mis-rank severity or write weak reasons.
- Detection of attack kinds is tuned to the listed categories (brute force, account compromise, SQLi, traversal, scanning, rate abuse, unauthorised access, exfiltration, prompt injection). Other attack kinds depend on the model alone.
- The ledger parser understands JSON-lines logs, combined/common access logs and sshd auth lines; other formats are passed to the model as plain digests without ledger facts.
- CPU generation speed: expect several seconds to tens of seconds per call on 2 vCPU; a ~200-line log takes a few minutes.
- Upload limit is 5 MB by default (`MAX_UPLOAD_BYTES`).
- Models can only be switched from the terminal.
