"""Central configuration. Everything is overridable with environment variables."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = Path(os.getenv("MODEL_DIR", ROOT / "models"))
MODEL_PATH = Path(os.getenv("MODEL_PATH", MODEL_DIR / "model.gguf"))
DATA_DIR = Path(os.getenv("DATA_DIR", ROOT / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
JOB_DIR = DATA_DIR / "jobs"

# Hard limits from the assessment brief
N_CTX = int(os.getenv("N_CTX", 2048))            # tokens per model call (prompt + output)
N_THREADS = int(os.getenv("N_THREADS", 2))       # 2 vCPU
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", 5 * 1024 * 1024))
RAM_LIMIT_MB = int(os.getenv("RAM_LIMIT_MB", 4096))

# Token budget plan (sums to <= N_CTX)
MAX_OUTPUT_TOKENS = int(os.getenv("MAX_OUTPUT_TOKENS", 450))    # reply
SAFETY_MARGIN = 64                                              # chat template overhead / tokenizer drift
SYSTEM_PROMPT_BUDGET = 330                                      # measured at startup, checked by test
LEDGER_BUDGET = int(os.getenv("LEDGER_BUDGET", 260))            # carried context
# Remaining space goes to log text (~1000 tokens)

LLM_TIMEOUT_S = int(os.getenv("LLM_TIMEOUT_S", 180))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", 2))
MOCK_LLM = os.getenv("MOCK_LLM", "0") == "1"      # tests only: skips the model, uses a stub
