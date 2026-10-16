"""Tiny deterministic keyword/TF-IDF retriever over the synthetic knowledge base.

No embeddings, no extra dependencies. M1 behaviour is deliberately naive: every document is
retrievable regardless of ``visibility`` and content is passed on verbatim (planted
LLM01/LLM08 weaknesses). M5 adds visibility filtering and untrusted-data wrapping.
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

    def search(self, query: str, top_k: int = 3) -> list[Doc]:
        """Return up to ``top_k`` docs with a positive score, best first (ties by doc order)."""
        terms = tokenize(query)
        scored: list[tuple[float, int]] = []
        for i, tf in enumerate(self._tf):
            score = sum(tf[t] * self._idf.get(t, 0.0) for t in terms)
            if score > 0:
                scored.append((score, i))
        scored.sort(key=lambda s: (-s[0], s[1]))
        return [self.docs[i] for _, i in scored[:top_k]]
