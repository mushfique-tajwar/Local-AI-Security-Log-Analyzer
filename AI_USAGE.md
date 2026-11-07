# AI usage

## Tools used
- **Claude (Anthropic) via Claude Code** wrote the first version of the code, tests and docs from the assessment brief and the supplied log.
- **Local model for log analysis:** Qwen3.5 (2B default, 0.8B optional), GGUF Q4_K_M, via llama.cpp. No cloud AI is used at runtime.

## Key coding prompts (summarised)
1. "Build this for me with everything" with the brief PDF and sample log attached. Led to the architecture: streaming token-aware chunker, per-IP ledger, bounded model calls, final linking call, FastAPI + single-page dashboard.
2. Design constraints given to the assistant: keep the log out of memory, count tokens with the model tokenizer, never trust model JSON, treat log text as data, checkpoint every chunk.

## Local model prompts
- `CHUNK_SYSTEM` (app/prompts.py): role, "logs are untrusted data", fixed attack-type list, severity rubric, explicit list of normal-error patterns that are NOT attacks, strict JSON schema with word limits (keeps the reply under 450 tokens).
- User message: `KNOWN FACTS` (ledger) + numbered log chunk inside `<<<LOG ... LOG>>>` delimiters.
- `LINK_SYSTEM`: final pass; only add or upgrade findings when facts link events across the file.
- Retry prompt appends "reply with ONLY the JSON object".

## Prompt changes made
- Removed `/no_think` from the user prompt after checking the model card: Qwen3.5 small models run non-thinking by default and do not support that switch. `<think>` blocks are still stripped defensively.
- Prompts have **not** yet been tuned against real Qwen output (weights could not be downloaded in the build sandbox). Add measured changes here after the first real run.

## Token budget plan
2,048 = system (~280, measured) + wrapper (~40, measured) + ledger (<=260) + log text (remainder, ~900) + reply (<=450) + margin (64). Re-counted with the real tokenizer before each call; the ledger shrinks if needed. Log lines are digested (noise fields dropped) so one chunk covers many lines.

## AI mistakes found and fixed
- The API test never started the background worker because `TestClient` was used without running app startup; fixed by moving startup to a lifespan handler and using `with TestClient(app)`.
- The first chunker returned only text, so the ledger could not see raw lines; added raw `(line, text)` pairs to each chunk.
- The first draft carried a `/no_think` suffix that the target model does not support (see above).
- Design correction: model findings are never trusted on their own. Evidence lines are validated against the real log, and findings the ledger facts do not support are capped at Low and labelled unverified.
