"""Local model wrapper (llama.cpp via llama-cpp-python). No network calls at runtime.

- One model instance, one call at a time (lock) -> bounded RAM (<= ~2 GB for a 2B Q4 model).
- Token counting uses the model's own tokenizer.
- Streaming generation with a wall-clock deadline so a stuck call cannot hang the job.
- MockLLM exists only for tests / CI (MOCK_LLM=1); it never runs in normal use.
"""
import json
import re
import threading
import time
from pathlib import Path

from . import config


class LLMTimeout(Exception):
    pass


class LLMError(Exception):
    pass


_THINK = re.compile(r"<think>.*?</think>", re.S)


class LocalLLM:
    kind = "llama.cpp"

    def __init__(self, model_path: Path = config.MODEL_PATH):
        self.model_path = Path(model_path)
        self._llm = None
        self._lock = threading.Lock()
        self.load_seconds = 0.0

    @property
    def name(self) -> str:
        return self.model_path.name

    def available(self) -> bool:
        return self.model_path.exists()

    def load(self):
        if self._llm is not None:
            return
        if not self.model_path.exists():
            raise LLMError(f"Model file not found: {self.model_path}. Run: python scripts/download_model.py")
        from llama_cpp import Llama  # imported lazily so tests can run without it
        t0 = time.time()
        self._llm = Llama(
            model_path=str(self.model_path),
            n_ctx=config.N_CTX,
            n_threads=config.N_THREADS,
            n_batch=256,
            n_gpu_layers=0,
            use_mmap=True,
            use_mlock=False,
            verbose=False,
        )
        self.load_seconds = round(time.time() - t0, 1)

    def count_tokens(self, text: str) -> int:
        self.load()
        return len(self._llm.tokenize(text.encode("utf-8"), add_bos=False, special=False))

    def count_messages(self, messages: list[dict]) -> int:
        # ChatML-style overhead ~ 4 tokens/message + 3 for the assistant primer
        return sum(self.count_tokens(m["content"]) + 4 for m in messages) + 3

    def chat(self, messages: list[dict], max_tokens: int, timeout_s: int = config.LLM_TIMEOUT_S) -> str:
        self.load()
        with self._lock:
            deadline = time.time() + timeout_s
            parts: list[str] = []
            try:
                stream = self._llm.create_chat_completion(
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=0.0,
                    top_p=1.0,
                    repeat_penalty=1.05,
                    response_format={"type": "json_object"},
                    stream=True,
                )
                for part in stream:
                    delta = part["choices"][0].get("delta", {}).get("content")
                    if delta:
                        parts.append(delta)
                    if time.time() > deadline:
                        stream.close()
                        raise LLMTimeout(f"model call exceeded {timeout_s}s")
            except LLMTimeout:
                raise
            except Exception as e:  # llama.cpp errors (e.g. context overflow)
                raise LLMError(str(e)) from e
            # reset KV cache between independent calls
            try:
                self._llm.reset()
            except Exception:
                pass
            return _THINK.sub("", "".join(parts)).strip()


class MockLLM:
    """Deterministic stub for unit tests only. Reads the KNOWN FACTS block and echoes a finding."""
    kind = "mock"
    name = "mock-llm"
    load_seconds = 0.0

    def __init__(self):
        self.calls = 0
        self.fail_next = 0

    def available(self):
        return True

    def load(self):
        pass

    def count_tokens(self, text: str) -> int:
        return max(1, len(text) // 3)

    def count_messages(self, messages):
        return sum(self.count_tokens(m["content"]) + 4 for m in messages) + 3

    def chat(self, messages, max_tokens, timeout_s=0):
        self.calls += 1
        if self.fail_next > 0:
            self.fail_next -= 1
            raise LLMTimeout("mock timeout")
        user = messages[-1]["content"]
        findings = []
        for m in re.finditer(r"^(\d+\.\d+\.\d+\.\d+): lines .*failed_logins=(\d+).*$", user, re.M):
            ip, n = m.group(1), int(m.group(2))
            ln = re.findall(r"L(\d+)", m.group(0))
            if n >= 3:
                findings.append({"attack_type": "brute_force", "severity": "Medium", "entity": ip,
                                 "lines": [int(x) for x in ln[:3]], "reason": "repeated failed logins",
                                 "action": "block ip"})
        return json.dumps({"findings": findings, "note": "mock"})


def get_llm():
    if config.MOCK_LLM:
        return MockLLM()
    return LocalLLM()
