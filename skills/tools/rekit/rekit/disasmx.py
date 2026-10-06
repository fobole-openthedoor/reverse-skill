from __future__ import annotations

from capstone import (
    CS_ARCH_ARM,
    CS_ARCH_ARM64,
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    Cs,
)

_ZERO_RUN = b"\x00" * 8


def make_cs(arch: str) -> Cs | None:
    if arch == "x86-64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "arm64":
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    elif arch == "arm32":
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    else:
        return None
    md.detail = False
    return md


def linear_disasm(arch: str, code: bytes, va: int, max_insns: int = 40) -> list[tuple[int, str, str]]:
    md = make_cs(arch)
    if md is None or not code or max_insns <= 0:
        return []
    stop = code.find(_ZERO_RUN)
    if stop >= 0:
        code = code[:stop]
    out: list[tuple[int, str, str]] = []
    for insn in md.disasm(code, va):
        out.append((insn.address, insn.mnemonic, insn.op_str))
        if len(out) >= max_insns:
            break
    return out
