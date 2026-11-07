"""Token-aware, line-preserving log splitter.

Every log line is one entry (JSON-lines or plain). Chunks are built from whole lines
only, so entries are never cut. A single line that alone exceeds the budget is
truncated with a marker (its line number is kept). Original line numbers are
preserved by prefixing each line with `L<n>|`.

The file is streamed; only the current chunk is held in memory.
"""
from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator


@dataclass
class Chunk:
    index: int
    start_line: int
    end_line: int
    text: str           # numbered text ready for the prompt
    tokens: int
    raw: list = field(default_factory=list)   # [(line_no, raw_line)] for ledger/validation


def _compact(line: str) -> str:
    """Whitespace-compact a line without changing its content."""
    return " ".join(line.split())


def split_lines(
    lines: Iterable[str],
    count_tokens: Callable[[str], int],
    budget: int,
    render: Callable[[str], str] = _compact,
) -> Iterator[Chunk]:
    """Yield Chunks whose numbered text is <= `budget` tokens."""
    buf: list[str] = []
    raws: list = []
    buf_tokens = 0
    start = None
    idx = 0
    last_n = 0

    def flush(end_line: int):
        nonlocal buf, buf_tokens, start, idx, raws
        if not buf:
            return None
        ch = Chunk(idx, start, end_line, "\n".join(buf), buf_tokens, raws)
        idx += 1
        buf, buf_tokens, start, raws = [], 0, None, []
        return ch

    for n, raw in enumerate(lines, start=1):
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue
        entry = f"L{n}|{render(line)}"
        t = count_tokens(entry) + 1  # +1 for newline
        if t > budget:
            # Oversized single entry: truncate by characters until it fits.
            while t > budget and len(entry) > 40:
                entry = entry[: int(len(entry) * 0.8)]
                t = count_tokens(entry) + 1
            entry += "…[truncated]"
        if buf and buf_tokens + t > budget:
            ch = flush(last_n)
            if ch:
                yield ch
        if start is None:
            start = n
        buf.append(entry)
        raws.append((n, line))
        buf_tokens += t
        last_n = n
    ch = flush(last_n)
    if ch:
        yield ch
