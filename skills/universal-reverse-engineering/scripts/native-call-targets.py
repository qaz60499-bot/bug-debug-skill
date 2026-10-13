#!/usr/bin/env python3
"""Bounded MIPS32 ELF GOT/stub call-link evidence; stdlib-only, read-only.

Supports little/big-endian and ELF32 without section headers via PT_LOAD,
PT_DYNAMIC and PT_MIPS_REGINFO. Identifies strict MIPS lazy PLT stubs and their
symbol names, never infers reachability, inter-block data flow, or runtime GOT.
Not a generic disassembler/CFG/decompiler; unsupported cases fail explicitly.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import struct
import sys
from pathlib import Path

MAX_FILE = 128 * 1024 * 1024
MAX_SCAN_BYTES = 8 * 1024 * 1024
MAX_SYMBOLS = 120_000
MAX_ITEMS = 128


class EvidenceError(ValueError):
    pass


def unpack(buf: bytes, fmt: str, at: int):
    sz = struct.calcsize(fmt)
    if at < 0 or at > len(buf) - sz:
        raise EvidenceError("truncated structure")
    return struct.unpack_from(fmt, buf, at)


def signed16(u):
    v = u & 0xffff
    return v - 0x10000 if v & 0x8000 else v


def lw_t9_gp(word):
    if word >> 26 == 0x23 and (word >> 21) & 31 == 28 and (word >> 16) & 31 == 25:
        return signed16(word)
    return None


def jalr_t9(word):
    return (word >> 26 == 0 and (word & 63) == 9 and
            (word >> 21) & 31 == 25 and
            (word >> 16) & 31 == 0 and
            (word >> 11) & 31 in (0, 31) and
            (word >> 6) & 31 == 0)


def move_t7_ra(word):
    # move t7,ra is addu/or t7,ra,zero (or with zero as first operand).
    if word >> 26 or (word & 63) not in (0x21, 0x25):
        return False
    if (word >> 11) & 31 != 15 or (word >> 6) & 31:
        return False
    return {(word >> 21) & 31, (word >> 16) & 31} == {0, 31}


def addiu_t8_zero(word):
    if (word >> 26) == 9 and (word >> 21) & 31 == 0 and (word >> 16) & 31 == 24:
        return signed16(word)
    return None


def barrier(word):
    op = word >> 26
    if op in (2, 3, 4, 5, 6, 7, 1):  # jump/branch
        return True
    if op == 0 and (word & 63) in (8, 9):  # jr/jalr
        return True
    return False


def changes_gp_or_t9(word):
    op = word >> 26
    # All register-writing ordinary I-class ops and explicit R-class destinations.
    if op == 0 and (word & 63) in (0, 2, 3, 4, 6, 7, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x2a, 0x2b):
        return (word >> 11) & 31 in (25, 28)
    if op in (8, 9, 10, 11, 12, 13, 14, 15, 0x23):
        return (word >> 16) & 31 in (25, 28)
    # Unrecognized opcodes cannot be safely traced across.
    return op not in (0, 2, 3, 4, 5, 6, 7, 1, 0x2b, 0x20, 0x21, 0x24, 0x25)


def inspect(data: bytes, limit: int = 16, scan_bytes: int = MAX_SCAN_BYTES, callsite: int | None = None) -> dict:
    if callsite is not None and (callsite < 0 or callsite > 0xffffffff or callsite % 4):
        raise EvidenceError("callsite must be aligned 32-bit MIPS virtual address")
    if not 1 <= limit <= MAX_ITEMS or not 4 <= scan_bytes <= MAX_SCAN_BYTES:
        raise EvidenceError("invalid analysis budget")
    if len(data) > MAX_FILE:
        raise EvidenceError("file too large")
    digest = hashlib.sha256(data).hexdigest()
    result = {"artifact_sha256": digest, "size_bytes": len(data), "executed_target": False,
              "read_only": True, "status": "UNSUPPORTED", "evidence_level": "static_candidate"}
    if len(data) < 52 or data[:5] != b"\x7fELF\x01" or data[5] not in (1, 2):
        result["reason"] = "requires ELF32 MIPS little/big endian"
        return result
    endian = "<" if data[5] == 1 else ">"
    e_type, machine = unpack(data, endian + "HH", 16)
    result.update({"format": "ELF32-" + ("LE" if endian == "<" else "BE"),
                   "arch": hex(machine)})
    if machine != 8:
        result["reason"] = "not MIPS"
        return result
    if e_type != 2:
        result["reason"] = "only non-PIE ET_EXEC with known GP is supported"
        return result
    poff = unpack(data, endian + "I", 28)[0]
    pentsize, pnum = unpack(data, endian + "HH", 42)
    if pentsize < 32 or pnum == 0 or pnum > 256 or poff > len(data) or pentsize * pnum > len(data) - poff:
        raise EvidenceError("invalid program header directory")
    loads = []
    dynamic = None
    gp = None
    for i in range(pnum):
        kind, off, va, _, size, memsz, flags, _ = unpack(data, endian + "8I", poff + i * pentsize)
        if off > len(data) or size > len(data) - off or (kind == 1 and size > memsz):
            raise EvidenceError("invalid program segment bounds")
        if kind == 1 and size:
            loads.append((va, off, size, flags))
        if kind == 2:
            dynamic = (off, size)
        if kind == 0x70000000:
            if size < 24:
                raise EvidenceError("invalid MIPS reginfo")
            gp = unpack(data, endian + "I", off + 20)[0]
    result["program_loads"] = len(loads)
    result["gp"] = hex(gp) if gp is not None else None
    if gp is None or dynamic is None or not loads:
        result["reason"] = "missing PT_MIPS_REGINFO GP, PT_DYNAMIC or PT_LOAD"
        return result

    def vaddr_to_offset(va, length, executable=None):
        for a, off, n, flags in loads:
            if executable is not None and bool(flags & 1) != executable:
                continue
            if va >= a and length <= n and va - a <= n - length:
                return off + va - a
        return None

    dyn = {}
    doff, dsz = dynamic
    if dsz < 8:
        raise EvidenceError("truncated dynamic table")
    # Some firmware PT_DYNAMIC extents contain padding after the mandatory DT_NULL.
    # Never read partial entries; require an in-bounds DT_NULL before the extent ends.
    found_end = False
    for i in range(min(dsz // 8, 8192)):
        kind, value = unpack(data, endian + "II", doff + 8 * i)
        if kind == 0:
            found_end = True
            break
        if kind not in dyn:
            dyn[kind] = value
    if not found_end:
        raise EvidenceError("unbounded dynamic table")
    mandatory = (3, 5, 6, 10, 11, 0x7000000a, 0x70000011, 0x70000013)
    if any(k not in dyn for k in mandatory):
        result["reason"] = "missing MIPS PLTGOT/SYMTABNO/GOTSYM/LOCAL_GOTNO or dynsym"
        return result
    got_addr, strings_addr, sym_addr = dyn[3], dyn[5], dyn[6]
    strsz, syment = dyn[10], dyn[11]
    locals_no, symbol_no, global_start = dyn[0x7000000a], dyn[0x70000011], dyn[0x70000013]
    if (syment != 16 or not 0 < symbol_no <= MAX_SYMBOLS or
            strsz > 16 * 1024 * 1024 or strsz == 0 or global_start > symbol_no or locals_no > MAX_SYMBOLS):
        raise EvidenceError("invalid dynamic MIPS table limits")
    got_entries = locals_no + symbol_no - global_start
    if got_entries <= 0 or got_entries > MAX_SYMBOLS:
        raise EvidenceError("invalid MIPS GOT size")
    symoff = vaddr_to_offset(sym_addr, symbol_no * syment)
    stroff = vaddr_to_offset(strings_addr, strsz)
    gotoff = vaddr_to_offset(got_addr, got_entries * 4)
    if any(x is None for x in (symoff, stroff, gotoff)):
        result["reason"] = "dynamic tables not fully file-backed PT_LOAD"
        return result
    strs = data[stroff:stroff + strsz]
    names = []
    for i in range(symbol_no):
        st_name, st_value, st_size, info, other, shndx = unpack(data, endian + "IIIBBH", symoff + i * 16)
        label = ""
        if 0 < st_name < strsz:
            stop = strs.find(b"\0", st_name, min(strsz, st_name + 257))
            if stop >= 0:
                label = strs[st_name:stop].decode("utf8", "replace")
        names.append({"name": label, "va": st_value, "size": st_size, "type": info & 15,
                      "defined": shndx != 0})
    result.update({"dynsym_count": symbol_no, "got_entries": got_entries,
                   "got_va": hex(got_addr), "gp": hex(gp)})

    def word(va, executable=None):
        ofs = vaddr_to_offset(va, 4, executable)
        return unpack(data, endian + "I", ofs)[0] if ofs is not None else None

    def symbol_stub(address):
        words = [word(address + 4 * i, executable=True) for i in range(4)]
        if any(v is None for v in words):
            return None
        idx = addiu_t8_zero(words[3])
        if (lw_t9_gp(words[0]) is None or not move_t7_ra(words[1]) or
                not jalr_t9(words[2]) or idx is None or not (0 <= idx < symbol_no)):
            return None
        # Dynamic resolver trampoline source usually takes t9 from gp - 0x7ff0.
        if lw_t9_gp(words[0]) != -0x7ff0:
            return None
        info = names[idx]
        if info["name"] and info["va"] == address and info["type"] == 2:
            return idx, info["name"]
        return None

    # Match exact MIPS32 instructions, never scan writable/data regions as code.
    sites = 0
    accepted = []
    candidates = 0
    scanned_bytes = 0
    truncated = False
    # Bound each scan, aligned to instruction width. Counts are measured candidates, not reachability.
    for va, off, n, flags in loads:
        if not (flags & 1):
            continue
        avail = min(n, max(0, scan_bytes - scanned_bytes))
        if avail < 4:
            truncated = True
            break
        start = (4 - va % 4) % 4
        end = avail - 3
        for j in range(start, end, 4):
            x = unpack(data, endian + "I", off + j)[0]
            if not jalr_t9(x):
                continue
            if callsite is not None and va + j != callsite:
                continue
            # The PLT resolver's own jalr lives at stub+8; it is not an
            # application-to-import call and must not inflate caller coverage.
            if j >= 8 and symbol_stub(va + j - 8) is not None:
                continue
            sites += 1
            # Look back only up to eight aligned words, stopping at branches and writes to t9/gp.
            preceding = None
            for back in range(1, 9):
                pos = j - 4 * back
                if pos < 0:
                    break
                prev = unpack(data, endian + "I", off + pos)[0]
                rel = lw_t9_gp(prev)
                if rel is not None:
                    preceding = (va + pos, rel)
                    break
                if barrier(prev) or changes_gp_or_t9(prev):
                    break
            if preceding is None:
                continue
            candidates += 1
            load_va, rel = preceding
            slot = (gp + rel) & 0xffffffff
            if slot < got_addr or slot + 4 > got_addr + got_entries * 4:
                continue
            target = word(slot)
            if target is None:
                continue
            resolved = symbol_stub(target)
            if resolved is None:
                continue
            idx, name = resolved
            accepted.append({"callsite": hex(va + j), "load": hex(load_va),
                             "got": hex(slot), "stub": hex(target),
                             "dynsym_index": idx, "target_symbol": name,
                             "method": "MIPS32-GP-GOT-PLT-DYNSYM",
                             "assumptions": ["static GOT bytes", "gp from PT_MIPS_REGINFO",
                                             "no intervening t9/gp overwrite in local window"]})
        scanned_bytes += avail
        if avail < n:
            truncated = True
            break
    result.update({"status": "STATIC_MATCHES" if accepted else "NO_MATCHES",
                   "jalr_t9_sites": sites,
                   "focus_callsite": hex(callsite) if callsite is not None else None,
                   "gp_relative_load_candidates": candidates,
                   "resolved_import_calls": len(accepted),
                   "unique_import_symbols": len({e["target_symbol"] for e in accepted}),
                   "calls": accepted[:limit], "calls_truncated": len(accepted) > limit,
                   "scan_bytes": scanned_bytes, "scan_truncated": truncated,
                   "unknown_jalr": sites - len(accepted),
                   "source_caveat": "Static ELF/GOT/PLT/dynsym linkage, NOT runtime call reachability, CFG, or function-level proof. "
                                    "GP use across calls and dynamic relocation may invalidate edges; unknown calls stay unknown."})
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", help="ELF32 MIPS binary or GitHub .b64 snapshot")
    p.add_argument("--max-items", type=int, default=16)
    p.add_argument("--max-scan-bytes", type=int, default=MAX_SCAN_BYTES)
    p.add_argument("--callsite", type=lambda v: int(v, 0), default=None,
                   help="Optional exact aligned MIPS VA for one static indirect-call edge")
    a = p.parse_args()
    try:
        if not 1 <= a.max_items <= MAX_ITEMS or not 4 <= a.max_scan_bytes <= MAX_SCAN_BYTES:
            raise EvidenceError("invalid CLI budget")
        path = Path(a.input)
        if path.stat().st_size > 180 * 1024 * 1024:
            raise EvidenceError("input exceeds encoded size limit")
        source = path.read_bytes()
        data = base64.b64decode(source.translate(None, b" \t\r\n"), validate=True) if path.suffix.lower() == ".b64" else source
        result = inspect(data, a.max_items, a.max_scan_bytes, a.callsite)
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (EvidenceError, OSError, ValueError) as e:
        print(json.dumps({"status": "REJECTED", "reason": str(e)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
