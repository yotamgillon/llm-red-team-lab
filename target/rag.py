"""Tiny deterministic keyword/TF-IDF retriever over the synthetic knowledge base.

No embeddings, no extra dependencies. The vulnerable build is deliberately naive: every
document is retrievable regardless of ``visibility`` and content is passed on verbatim (planted
LLM01/LLM08 weaknesses). SECURE_MODE adds, in code: a visibility filter applied before ranking
(``allow_internal``), an ingestion check (``find_injection``) and ``sanitize_untrusted``, which
strips instruction-like text and neutralises delimiter breakouts before a doc reaches the prompt.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

KB_DIR = Path(__file__).parent / "data" / "kb"
COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
TOKEN_RE = re.compile(r"[a-z0-9]+")
STOPWORDS = frozenset(
    "a an and are as at be by can do for from has have how i in is it me my of on or the to "
    "what when where which who will with you your please tell about now".split()
)


# Instruction-like text inside a retrieved document. Documents are data; none of this belongs.
INSTRUCTION_RES: tuple[re.Pattern[str], ...] = (
    re.compile(r"ai-assistant-instruction|assistant-instruction", re.IGNORECASE),
    re.compile(
        r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:instructions|rules|prompts?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:you must|you should|you are required to) (?:call|run|execute|invoke)\b", re.I
    ),
    re.compile(r"\b(?:call|invoke|execute)\s+(?:refund_customer|lookup_account)\b", re.I),
    re.compile(r"</?\s*(?:untrusted_data|system|assistant)\s*>|\[/?inst\]|<\|im_\w+\|>", re.I),
)
REMOVED = "[removed: instruction-like text]"


@dataclass(frozen=True)
class Doc:
    """One knowledge-base document."""

    id: str
    title: str
    visibility: str
    body: str


def tokenize(text: str) -> list[str]:
    """Lowercase word tokens without stopwords."""
    return [t for t in TOKEN_RE.findall(text.lower()) if t not in STOPWORDS]


def parse_doc(raw: str) -> Doc:
    """Parse a markdown file with a simple ``---`` front matter block."""
    _, front, body = raw.split("---", 2)
    meta = dict(
        line.split(":", 1) for line in front.strip().splitlines() if ":" in line
    )  # fmt: skip
    meta = {k.strip(): v.strip() for k, v in meta.items()}
    return Doc(meta["id"], meta["title"], meta.get("visibility", "public"), body.strip())


def find_injection(body: str) -> list[str]:
    """Ingestion check: return the patterns of instruction-like text found in ``body``.

    Looks at the raw body, hidden HTML comments included, because that is where a poisoned
    document hides its payload. An empty list means the document looks clean.
    """
    return [p.pattern for p in INSTRUCTION_RES if p.search(body)]


def sanitize_untrusted(body: str) -> str:
    """Make a document body safe to show the model as data.

    Removes HTML comments (hidden text), then every line that still contains instruction-like
    text, and finally any delimiter tags so a document cannot close its own untrusted wrapper.
    """
    body = COMMENT_RE.sub("", body)
    kept: list[str] = []
    for line in body.splitlines():
        if any(p.search(line) for p in INSTRUCTION_RES):
            kept.append(REMOVED)
        else:
            kept.append(line)
    text = "\n".join(kept)
    return re.sub(r"</?\s*untrusted_data\s*>", "", text, flags=re.IGNORECASE).strip()


def load_docs(directory: Path = KB_DIR) -> list[Doc]:
    """Load all ``*.md`` docs from ``directory`` in filename order."""
    return [parse_doc(p.read_text(encoding="utf-8")) for p in sorted(directory.glob("*.md"))]


class Retriever:
    """TF-IDF scorer: sum over query terms of tf * idf, title counted twice.

    HTML comments are not indexed, so hidden text never influences ranking.
    """

    def __init__(self, docs: list[Doc]) -> None:
        self.docs = docs
        self._tf = [
            Counter(tokenize(d.title) * 2 + tokenize(COMMENT_RE.sub("", d.body))) for d in docs
        ]
        df: Counter[str] = Counter()
        for tf in self._tf:
            df.update(tf.keys())
        n = len(docs)
        self._idf = {t: math.log((n + 1) / (c + 0.5)) + 1 for t, c in df.items()}

    def search(self, query: str, top_k: int = 3, *, allow_internal: bool = True) -> list[Doc]:
        """Return up to ``top_k`` docs with a positive score, best first (ties by doc order).

        With ``allow_internal=False`` documents whose visibility is not ``public`` are excluded
        before ranking, so they can neither be returned nor crowd out public documents.
        """
        terms = tokenize(query)
        scored: list[tuple[float, int]] = []
        for i, tf in enumerate(self._tf):
            if not allow_internal and self.docs[i].visibility != "public":
                continue
            score = sum(tf[t] * self._idf.get(t, 0.0) for t in terms)
            if score > 0:
                scored.append((score, i))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return [self.docs[i] for _, i in scored[:top_k]]
