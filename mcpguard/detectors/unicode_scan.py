from __future__ import annotations

import unicodedata
from dataclasses import dataclass

_INVISIBLE_RANGES = [
    (0x200B, 0x200F),  # zero-width space, joiners, direction marks
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # directional isolates
    (0xFEFF, 0xFEFF),  # byte order mark / zero-width no-break space
    (0xE0000, 0xE007F),  # Unicode tag characters — most dangerous
    (0x202A, 0x202E),  # embedding and override marks (includes RTL override)
    (0x115F, 0x115F),  # Hangul choseong filler
    (0x1160, 0x1160),  # Hangul jungseong filler
    (0x3164, 0x3164),  # Hangul filler
    (0xFFA0, 0xFFA0),  # halfwidth Hangul filler
]

_HOMOGLYPH_PAIRS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "υ": "u",
}


@dataclass
class UnicodeHit:
    char: str
    codepoint: int
    position: int
    category: str
    description: str


def scan_text(text: str) -> list[UnicodeHit]:
    hits: list[UnicodeHit] = []
    for pos, char in enumerate(text):
        cp = ord(char)
        for start, end in _INVISIBLE_RANGES:
            if start <= cp <= end:
                hits.append(UnicodeHit(
                    char=char,
                    codepoint=cp,
                    position=pos,
                    category="invisible",
                    description=f"Invisible/control Unicode U+{cp:04X} ({unicodedata.name(char, 'UNKNOWN')})",
                ))
                break
    return hits


def has_invisible_chars(text: str) -> bool:
    return bool(scan_text(text))


def strip_invisible(text: str) -> str:
    return "".join(
        ch for ch in text
        if not any(start <= ord(ch) <= end for start, end in _INVISIBLE_RANGES)
    )


def summarize(hits: list[UnicodeHit]) -> str:
    if not hits:
        return ""
    unique = {h.codepoint for h in hits}
    return f"{len(hits)} invisible character(s) at positions {[h.position for h in hits[:5]]}... " \
           f"Codepoints: {[f'U+{cp:04X}' for cp in sorted(unique)]}"
