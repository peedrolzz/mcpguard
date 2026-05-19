from __future__ import annotations

import re
from dataclasses import dataclass

_INJECTION_KEYWORDS = re.compile(
    r"(?i)("
    r"<IMPORTANT>|</IMPORTANT>|"
    r"\[CRITICAL\]|\[SYSTEM\]|"
    r"SYSTEM:|IGNORE PREVIOUS|IGNORE ALL PREVIOUS|"
    r"do not (tell|mention|inform|reveal|say) (this|the user|anyone)|"
    r"without (telling|mentioning|notifying|informing) the user|"
    r"the user (must not|should not|cannot) (know|see|notice)|"
    r"read (the file|file|~\/|\/etc\/|\/home\/|C:\\\\Users\\\\)|"
    r"pass (it|this|the content|its content) (to|as)|"
    r"exfiltrate|send to (attacker|external|remote)|"
    r"base64 encode|base64\.b64encode|"
    r"maintenance mode|override mode|"
    r"new instruction|updated instruction|"
    r"you are now|from now on you|"
    r"<\/?INST>|<\/?SYS>|\[\/INST\]"
    r")"
)

_FILE_PATH_RE = re.compile(
    r"(~/\.|~\/[a-zA-Z]|\/etc\/|\/home\/|\/root\/|C:\\\\Users\\\\|%APPDATA%|%USERPROFILE%)"
)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_LONG_DESCRIPTION_THRESHOLD = 500

_SUSPICIOUS_PARAM_RE = re.compile(
    r"(?i)(ssh_key|private_key|secret|token|password|credential|"
    r"content_from_file|read_from|file_content|exfil)"
)


@dataclass
class PatternHit:
    pattern_name: str
    matched_text: str
    context: str


def scan_description(text: str) -> list[PatternHit]:
    hits: list[PatternHit] = []

    for m in _INJECTION_KEYWORDS.finditer(text):
        start = max(0, m.start() - 30)
        end = min(len(text), m.end() + 30)
        hits.append(PatternHit(
            pattern_name="injection_keyword",
            matched_text=m.group(),
            context=text[start:end],
        ))

    for m in _FILE_PATH_RE.finditer(text):
        start = max(0, m.start() - 20)
        end = min(len(text), m.end() + 20)
        hits.append(PatternHit(
            pattern_name="file_path_reference",
            matched_text=m.group(),
            context=text[start:end],
        ))

    for m in _BASE64_RE.finditer(text):
        hits.append(PatternHit(
            pattern_name="base64_blob",
            matched_text=m.group()[:40] + "...",
            context="Possible encoded payload",
        ))

    if len(text) > _LONG_DESCRIPTION_THRESHOLD:
        hits.append(PatternHit(
            pattern_name="long_description",
            matched_text=f"{len(text)} chars",
            context="Description exceeds threshold — may hide instructions past UI truncation point",
        ))

    return hits


def scan_param_name(name: str) -> PatternHit | None:
    m = _SUSPICIOUS_PARAM_RE.search(name)
    if m:
        return PatternHit(
            pattern_name="suspicious_param_name",
            matched_text=name,
            context=f"Parameter name '{name}' suggests credential extraction",
        )
    return None
