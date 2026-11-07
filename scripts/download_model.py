"""One-time model download (needs internet). After this the app runs fully offline.

  python scripts/download_model.py                       # Qwen3.5 2B, Q4_K_M (default)
  python scripts/download_model.py --size 0.8b           # smaller/faster
  python scripts/download_model.py --repo unsloth/Qwen3.5-2B-GGUF --file Qwen3.5-2B-Q4_K_M.gguf
"""
import argparse
import shutil
from pathlib import Path

from huggingface_hub import hf_hub_download

PRESETS = {
    "0.8b": ("unsloth/Qwen3.5-0.8B-GGUF", "Qwen3.5-0.8B-Q4_K_M.gguf"),   # ~533 MB
    "2b": ("unsloth/Qwen3.5-2B-GGUF", "Qwen3.5-2B-Q4_K_M.gguf"),
}

ap = argparse.ArgumentParser()
ap.add_argument("--size", choices=PRESETS, default="2b")
ap.add_argument("--repo")
ap.add_argument("--file")
ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "models"))
a = ap.parse_args()
repo, fname = (a.repo, a.file) if a.repo and a.file else PRESETS[a.size]
out = Path(a.out)
out.mkdir(parents=True, exist_ok=True)
print(f"Downloading {repo}/{fname} ...")
p = hf_hub_download(repo_id=repo, filename=fname, local_dir=str(out))
dest = out / "model.gguf"
shutil.copyfile(p, dest) if Path(p) != dest else None
print(f"Ready: {dest}  ({dest.stat().st_size / 1048576:.0f} MB)")
