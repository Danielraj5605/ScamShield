"""Text normalisation: undo the obfuscation tricks scammers use before any model sees the text."""
from __future__ import annotations

import re
import unicodedata

# Look-alike characters that NFKC does not fold (Cyrillic/Greek letters that render like Latin).
_CONFUSABLES = str.maketrans({
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p",
    "с": "c", "т": "t", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d",
    "ɡ": "g", "ӏ": "l", "ο": "o", "α": "a", "ν": "v", "ρ": "p", "τ": "t", "ι": "i",
    "κ": "k", "υ": "u", "χ": "x", "ε": "e",
})
_ZERO_WIDTH = re.compile("[​-‏⁠﻿­]")
_REFANG = [
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
]
_SPACES = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Canonical lower-case form used by rules and models. The original text is kept for display."""
    text = unicodedata.normalize("NFKC", text)
    text = _ZERO_WIDTH.sub("", text)
    text = text.casefold().translate(_CONFUSABLES)
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return _SPACES.sub(" ", text).strip()


# Placeholders let the models learn patterns ("asks you to call a number") instead of
# memorising specific numbers, amounts or domains.
_URL_RE = re.compile(r"(?:https?://|www\.)\S+")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
_PHONE_CANDIDATE = re.compile(r"(?<![\w])\+?\d[\dx\s-]{7,16}[\dx](?![\w])")


def _phone_sub(m: re.Match) -> str:
    # Phone-like: 10-13 digits/masking x's (covers "9XXXXX1234", "+91 98765 43210", "1800-xxx-xxxx").
    core = re.sub(r"[\s+-]", "", m.group(0))
    return " __phone__ " if 10 <= len(core) <= 13 else m.group(0)
_AMOUNT_RE = re.compile(r"(?:rs\.?|inr|₹|£|\$|€)\s?\d[\d,]*(?:\.\d+)?|\d[\d,]*(?:\.\d+)?\s?(?:rs|inr|rupees|/-)")
_NUM_RE = re.compile(r"\d+")


def placeholderize(norm_text: str, bare_urls: list[str] | None = None) -> str:
    """Replace URLs/emails/phones/amounts/numbers with tokens. Expects normalize() output."""
    text = norm_text
    for u in bare_urls or []:
        text = text.replace(u, " __url__ ")
    text = _URL_RE.sub(" __url__ ", text)
    text = _EMAIL_RE.sub(" __email__ ", text)
    text = _AMOUNT_RE.sub(" __amt__ ", text)
    text = _PHONE_CANDIDATE.sub(_phone_sub, text)
    text = _NUM_RE.sub(" __num__ ", text)
    return _SPACES.sub(" ", text).strip()
