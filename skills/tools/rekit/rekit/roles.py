from __future__ import annotations

import re

DANGEROUS_PLT: dict[str, str] = {
    "strcpy": "unbounded copy",
    "strcat": "unbounded concat",
    "sprintf": "unbounded format write",
    "vsprintf": "unbounded format write",
    "gets": "unbounded input",
    "scanf": "unbounded input",
    "sscanf": "unbounded input parse",
    "fscanf": "unbounded input",
    "system": "command exec",
    "popen": "command exec",
    "execl": "process exec",
    "execle": "process exec",
    "execvp": "process exec",
    "execvpe": "process exec",
    "mprotect": "memory permission change",
    "dlopen": "dynamic loading",
    "dlsym": "dynamic loading",
}

_PAT_SOURCES: list[str] = [
    "%n",
    r"passw(or)?d",
    r"\bsecret\b",
    r"\btoken\b",
    r"\bapi[_-]?key\b",
    r"/bin/(ba)?sh",
    r"https?://",
    r"\bcmd\b",
]

SUSPICIOUS_STRING_PATS: list[re.Pattern[str]] = [re.compile(p, re.IGNORECASE) for p in _PAT_SOURCES]

_CRYPTO_CALLEE = re.compile(r"EVP_|AES|SHA|MD5|RC4")
_CRYPTO_STRING = re.compile(r"BEGIN.*KEY")


def is_suspicious(text: str) -> bool:
    return any(p.search(text) for p in SUSPICIOUS_STRING_PATS)


def _has_any(names: set[str], tokens: tuple[str, ...]) -> bool:
    return any(tok in name for name in names for tok in tokens)


def role_for(callees: list[str], strings: list[str]) -> str:
    names = {c.lower() for c in callees}
    if _has_any(names, ("recv", "send", "socket", "connect")):
        return "NETWORK_IO"
    if _has_any(names, ("open", "read", "fread", "fopen")):
        return "FILE_IO"
    if _has_any(names, ("strcpy", "sprintf", "memcpy")):
        return "MEM_OPS"
    if _has_any(names, ("system", "popen", "exec")):
        return "PROC_EXEC"
    if any(_CRYPTO_CALLEE.search(c) for c in callees) or any(_CRYPTO_STRING.search(s) for s in strings):
        return "CRYPTO"
    if _has_any(names, ("printf", "fprintf", "puts", "syslog")):
        return "FORMAT_OUT"
    if _has_any(names, ("sscanf", "strtok", "strtol", "json")):
        return "PARSER"
    return "UNKNOWN"
