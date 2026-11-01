"""Guardrails for UNTRUSTED alert text.

Layer 1 (this file): detect and strip prompt-injection attempts, including simple
obfuscation (leetspeak, Cyrillic look-alikes, base64).
Layer 2 (pipeline.py): the verdict (technique, severity) is decided by deterministic
code, never by the LLM, so a missed injection cannot downgrade an alert.
Layer 3 (pipeline.py): the LLM only sees the alert as quoted data, plus KB text.

Known gaps (measured in evaluate.py): non-English attacks and instructions split
across fields are not caught by the regex layer.
"""
import re, base64, unicodedata

PATTERNS = [
    r"(ignore|disregard|forget|override)\W+(all\W+|any\W+|the\W+|your\W+|everything\W+)?(previous|prior|above|earlier|preceding)\W+(instructions?|rules?|prompts?|context|guidelines?)",
    r"(forget|ignore|disregard)\W+(everything|all)\W+(above|before|previously)",
    r"you\W*(are|re)\W+now\b",
    r"\[/?inst\]",
    r"</?\s*(alert|system|instructions?|assistant)\s*>",
    r"new\W+instructions?\s*:",
    r"(mark|classify|label|report|set|treat|consider)\W+(this|it|the)\W+(alert\W+|event\W+|log\W+)?(as\W+)?(a\W+)?(benign|safe|false\W+positive|informational|low|test)",
    r"(do\W*not|don\W*t|never)\W+(flag|report|alert|escalate|raise)",
    r"skip\W+(the\W+)?(analysis|triage|review)",
    r"severity\s*[=:]\s*(low|none|info\w*)",
    r"classification\s*[=:]\s*none",
    r"override\s*:",
    r"i\W+authori[sz]e\W+you",
    r"(^|\n)\s*(assistant|system)\s*:",
]
# Short lead-in labels ("Note to analyst-bot:") are removed together with the instruction they introduce.
_LEAD = r"(?:\b(?:note|attention|important|reminder|message|comment|instruction)\b[\w\s\-]{0,25}:\s*)?"
_COMPILED = [re.compile(_LEAD + "(?:" + p + ")", re.I) for p in PATTERNS]

# 1:1 character maps keep string length unchanged, so match spans map back to the original.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "і": "i", "у": "y",
    "Α": "A", "Ε": "E", "Ο": "O", "ο": "o",
    "0": "o", "1": "i", "3": "e", "@": "a", "$": "s",
})

def _detection_view(text: str) -> str:
    return text.translate(_CONFUSABLES)

def _strip_spans(original: str, view: str):
    found, clean = False, original
    for rx in _COMPILED:
        for m in reversed(list(rx.finditer(view))):
            found = True
            end = m.end()
            while end < len(view) and view[end] not in ".\n":
                end += 1
            clean = clean[:m.start()] + "[***]" + clean[end:]
            view = view[:m.start()] + "[***]" + view[end:]
    return clean, found

_B64 = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

def _strip_encoded(text: str):
    found = False
    def repl(m):
        nonlocal found
        try:
            dec = base64.b64decode(m.group(0) + "=" * (-len(m.group(0)) % 4), validate=False).decode("utf-8", "ignore")
        except Exception:
            return m.group(0)
        if any(rx.search(_detection_view(dec)) for rx in _COMPILED):
            found = True
            return "[***]"
        return m.group(0)
    return _B64.sub(repl, text), found

def sanitize(text: str):
    """Return (clean_text, flagged). Never raises."""
    text = unicodedata.normalize("NFKC", text or "")
    text, enc_found = _strip_encoded(text)
    clean, found = _strip_spans(text, _detection_view(text))
    return clean, (found or enc_found)
