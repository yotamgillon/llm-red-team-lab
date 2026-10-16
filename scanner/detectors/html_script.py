"""HTML detector: active content in ``reply_html``, the string the page injects via innerHTML."""

from __future__ import annotations

from html.parser import HTMLParser
from typing import Any

from scanner.models import Attack, Payload, TargetResponse, Verdict

DANGEROUS_TAGS = {"script", "iframe", "object", "embed", "frame", "frameset", "base"}
URL_ATTRS = {"href", "src", "action", "formaction", "data", "xlink:href", "srcdoc"}


class _Scanner(HTMLParser):
    def __init__(self, allowed_tags: set[str]) -> None:
        super().__init__(convert_charrefs=True)
        self.allowed_tags = allowed_tags
        self.hits: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in DANGEROUS_TAGS and tag not in self.allowed_tags:
            self.hits.append(f"<{tag}> element")
        for name, value in attrs:
            if name.startswith("on"):
                self.hits.append(f"{name}= event handler on <{tag}>")
            elif name in URL_ATTRS and value:
                scheme = "".join(value.split()).lower()
                if scheme.startswith(("javascript:", "vbscript:", "data:text/html")):
                    self.hits.append(f"{scheme.split(':')[0]}: URL in {name} on <{tag}>")

    handle_startendtag = handle_starttag  # type: ignore[assignment]


class HtmlScriptDetector:
    """Fires when ``reply_html`` contains script, iframe, ``on*=`` handlers or ``javascript:``.

    Param ``allow_tags`` lists dangerous-list tags the attack tolerates (default none). Benign
    markup such as ``<b>`` never fires. Escaped markup (``&lt;script&gt;``) parses as text.
    """

    def __init__(self, params: dict[str, Any]) -> None:
        self._allowed = {str(t).lower() for t in params.get("allow_tags", [])}

    def evaluate(self, attack: Attack, payload: Payload, response: TargetResponse) -> Verdict:
        """Parse ``response.reply_html`` and report the first active-content hit."""
        scanner = _Scanner(self._allowed)
        scanner.feed(response.reply_html or "")
        scanner.close()
        if scanner.hits:
            return Verdict(fired=True, evidence=f"active content in reply_html: {scanner.hits[0]}")
        return Verdict(fired=False)
