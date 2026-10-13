#!/usr/bin/env python3
"""Opt-in bounded WebAssembly call linkage. Static candidates, NOT runtime proof or a full validator."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

MAX_INPUT = 128 * 1024 * 1024
MAX_BODY = 128 * 1024
MAX_COUNT = 200000
MAX_INSTRUCTIONS = 20000


class Unsupported(ValueError):
    pass


def required(b, p, n, end):
    if p < 0 or n < 0 or p + n > end:
        raise Unsupported("truncated or out-of-range WASM field")


def u(b, p, end):
    value = 0
    for i in range(5):
        required(b, p, 1, end)
        c = b[p]
        p += 1
        if i == 4 and (c & 0xf0):
            raise Unsupported("u32 LEB overflow")
        value |= (c & 127) << (7 * i)
        if not (c & 128):
            # WASM permits bounded padded u32 LEB forms; reject overflow, not padding.
            return value, p
    raise Unsupported("overlong u32 LEB")


def s(b, p, end, maxbytes=5):
    value = 0
    shift = 0
    for _ in range(maxbytes):
        required(b, p, 1, end)
        c = b[p]
        p += 1
        value |= (c & 127) << shift
        shift += 7
        if not (c & 128):
            if c & 64:
                value -= 1 << shift
            return value, p
    raise Unsupported("overlong signed LEB")


def string(b, p, end):
    n, p = u(b, p, end)
    if n > 4096:
        raise Unsupported("unbounded string")
    required(b, p, n, end)
    return b[p:p + n].decode("utf-8"), p + n


def vector_len(b, p, end):
    n, p = u(b, p, end)
    if n > MAX_COUNT:
        raise Unsupported("unbounded vector")
    return n, p


def limits(b, p, end):
    flags, p = u(b, p, end)
    if flags not in (0, 1):
        raise Unsupported("unsupported limits flags")
    minimum, p = u(b, p, end)
    maximum = None
    if flags == 1:
        maximum, p = u(b, p, end)
        if maximum < minimum:
            raise Unsupported("invalid table limits")
    return minimum, p


def sections(b):
    if len(b) < 8 or b[:8] != b"\0asm\x01\0\0\0":
        raise Unsupported("not a WASM v1 module")
    d = {}
    p = 8
    seen = 0
    last_standard_order = 0
    section_order = {**{i: i for i in range(1, 10)}, 12: 10, 10: 11, 11: 12}
    while p < len(b):
        if seen >= 128:
            raise Unsupported("too many sections")
        seen += 1
        sid = b[p]
        p += 1
        n, p = u(b, p, len(b))
        required(b, p, n, len(b))
        if sid > 12:
            raise Unsupported("unrecognized standard section id")
        if sid != 0:
            if sid in d:
                raise Unsupported("duplicate standard WASM section")
            ordinal = section_order[sid]
            if ordinal <= last_standard_order:
                raise Unsupported("out-of-order standard WASM section")
            last_standard_order = ordinal
            d[sid] = b[p:p+n]
        p += n
    return d


def metadata(parts):
    types = []
    b = parts.get(1, b"")
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            required(b, p, 1, len(b))
            if b[p] != 0x60:
                raise Unsupported("unsupported type form")
            p += 1
            argc, p = vector_len(b, p, len(b))
            required(b, p, argc, len(b))
            args = list(b[p:p+argc])
            p += argc
            retc, p = vector_len(b, p, len(b))
            required(b, p, retc, len(b))
            rets = list(b[p:p+retc])
            p += retc
            types.append({"params":args, "results":rets})
        if p != len(b):
            raise Unsupported("type trailing bytes")

    imported_types, imported_names, tables = [], [], []
    b = parts.get(2, b"")
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            module, p = string(b, p, len(b))
            field, p = string(b, p, len(b))
            required(b, p, 1, len(b))
            kind = b[p]
            p += 1
            if kind == 0:
                typ, p = u(b, p, len(b))
                if typ >= len(types):
                    raise Unsupported("function import type out of range")
                imported_types.append(typ)
                imported_names.append(module + "." + field)
            elif kind == 1:
                required(b, p, 1, len(b))
                if b[p] != 0x70:
                    raise Unsupported("unsupported imported table reference type")
                p += 1
                minimum, p = limits(b, p, len(b))
                tables.append(minimum)
            elif kind == 2:
                _, p = limits(b, p, len(b))
            elif kind == 3:
                required(b, p, 2, len(b))
                p += 2
            elif kind == 4:
                _, p = u(b, p, len(b))
                _, p = u(b, p, len(b))
            else:
                raise Unsupported("unsupported import kind")
        if p != len(b):
            raise Unsupported("import trailing bytes")

    b = parts.get(3, b"")
    local_types = []
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            typ, p = u(b, p, len(b))
            if typ >= len(types):
                raise Unsupported("local function type out of range")
            local_types.append(typ)
        if p != len(b):
            raise Unsupported("function trailing bytes")

    b = parts.get(4, b"")
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            required(b, p, 1, len(b))
            if b[p] != 0x70:
                raise Unsupported("unsupported table reference type")
            p += 1
            minimum, p = limits(b, p, len(b))
            tables.append(minimum)
        if p != len(b):
            raise Unsupported("table trailing bytes")

    elements = {}
    b = parts.get(9, b"")
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            flags, p = u(b, p, len(b))
            if flags not in (0, 2):
                raise Unsupported("unsupported element segment encoding; no static target assertion")
            table = 0
            if flags == 2:
                table, p = u(b, p, len(b))
            required(b, p, 1, len(b))
            if b[p] != 0x41:
                raise Unsupported("nonconstant element offset")
            offset, p = s(b, p + 1, len(b))
            required(b, p, 1, len(b))
            if b[p] != 0x0b:
                raise Unsupported("unclosed element offset")
            p += 1
            if flags == 2:
                required(b, p, 1, len(b))
                if b[p] != 0:
                    raise Unsupported("unsupported element function kind")
                p += 1
            count, p = vector_len(b, p, len(b))
            if table >= len(tables) or offset < 0 or offset + count > tables[table]:
                raise Unsupported("element outside static table limits")
            for i in range(count):
                function, p = u(b, p, len(b))
                if function >= len(imported_types) + len(local_types):
                    raise Unsupported("element function out of range")
                key = (table, offset + i)
                if key in elements:
                    # Overlapping segment initialization is order-dependent, not one immutable mapping.
                    elements[key] = None
                else:
                    elements[key] = function
        if p != len(b):
            raise Unsupported("element trailing bytes")

    b = parts.get(10, b"")
    bodies = []
    if b:
        n, p = vector_len(b, 0, len(b))
        for _ in range(n):
            sz, p = u(b, p, len(b))
            required(b, p, sz, len(b))
            bodies.append(b[p:p+sz])
            p += sz
        if p != len(b):
            raise Unsupported("code trailing bytes")
    if len(local_types) != len(bodies):
        raise Unsupported("function/code counts mismatch")
    return types, imported_types, imported_names, local_types, tables, elements, bodies


def decode(b, types, import_types, import_names, local_types, tables, elements, max_instructions):
    p = 0
    n, p = vector_len(b, p, len(b))
    for _ in range(n):
        _, p = u(b, p, len(b))
        required(b, p, 1, len(b))
        p += 1

    instructions, calls, stack, last = 0, [], [], None
    function_end = False
    while p < len(b):
        if instructions >= max_instructions:
            raise Unsupported("instruction limit exceeded")
        pc = p
        op = b[p]
        p += 1
        instructions += 1
        imm = None
        if op in (2, 3, 4):
            # Block type is a signed LEB33; value types and type indices both fit this decoder.
            _, p = s(b, p, len(b), 5)
            stack.append(op)
        elif op == 5:
            if not stack or stack[-1] != 4:
                raise Unsupported("else without if")
        elif op == 11:
            if stack:
                stack.pop()
            elif p == len(b):
                function_end = True
            else:
                raise Unsupported("function end before last body byte")
        elif op == 0x26:
            # A write in this focused function invalidates immutable table assumptions.
            raise Unsupported("table.set in focused body: static table candidate not reliable")
        elif op in (12, 13, 16, 32, 33, 34, 35, 36, 37):
            imm, p = u(b, p, len(b))
        elif op == 14:
            count, p = vector_len(b, p, len(b))
            for _ in range(count + 1):
                _, p = u(b, p, len(b))
        elif op == 17:
            typ, p = u(b, p, len(b))
            table, p = u(b, p, len(b))
            if typ >= len(types) or table >= len(tables):
                raise Unsupported("invalid call_indirect type/table")
            entry = {"offset": pc, "op": "call_indirect", "type_index": typ,
                     "table_index": table, "slot": None, "target_candidates": []}
            if last is not None and last[0] == 0x41 and last[1] is not None and last[1] >= 0:
                slot = last[1]
                entry["slot"] = slot
                fn = elements.get((table, slot))
                if fn is not None:
                    callee_type = (import_types + local_types)[fn]
                    if callee_type == typ:
                        entry["target_candidates"] = [fn]
            calls.append(entry)
        elif 0x28 <= op <= 0x3e:
            _, p = u(b, p, len(b))
            _, p = u(b, p, len(b))
        elif op in (0x3f, 0x40):
            _, p = u(b, p, len(b))
        elif op in (0x41, 0x42):
            imm, p = s(b, p, len(b), 5 if op == 0x41 else 10)
        elif op in (0x43, 0x44):
            width = 4 if op == 0x43 else 8
            required(b, p, width, len(b))
            p += width
        elif op in (0, 1, 15, 26, 27) or 0x45 <= op <= 0xc4:
            pass
        else:
            raise Unsupported(f"unsupported opcode 0x{op:02x} at offset {pc}")
        if op == 16:
            total = import_types + local_types
            if imm >= len(total):
                raise Unsupported("direct call out of bounds")
            item = {"offset": pc, "op": "call", "target_function_index": imm,
                    "type_index": total[imm]}
            if imm < len(import_names):
                item["import"] = import_names[imm]
            calls.append(item)
        last = (op, imm)

    if not function_end or stack:
        raise Unsupported("unclosed function")
    return instructions, calls


def analyze(blob: bytes, local_function: int, max_instructions: int = 8192):
    if len(blob) > MAX_INPUT or local_function < 0 or not 1 <= max_instructions <= MAX_INSTRUCTIONS:
        raise Unsupported("input or limits out of range")
    parts = sections(blob)
    types, imported, names, local, tables, elements, bodies = metadata(parts)
    if local_function >= len(bodies):
        raise Unsupported("function index outside defined function body count")
    body = bodies[local_function]
    if len(body) > MAX_BODY:
        raise Unsupported("function body exceeds 128 KiB focus cap")
    n, calls = decode(body, types, imported, names, local, tables, elements, max_instructions)
    return {"status": "static_candidates", "sha256": hashlib.sha256(blob).hexdigest(),
            "format": "WASM", "read_only": True, "executed_target": False,
            "function_import_count": len(imported), "local_function_index": local_function,
            "absolute_function_index": len(imported) + local_function,
            "body_bytes": len(body), "decoded_instructions": n, "calls": calls,
            "calls_truncated": False,
            "verification": "whole focused body opcode-decode; module-wide semantics not validated",
            "limits": "candidate table links depend on init bytes; runtime table mutation and reachability UNKNOWN"}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("file")
    ap.add_argument("--local-function", type=int, required=True)
    ap.add_argument("--max-instructions", type=int, default=8192)
    a = ap.parse_args()
    try:
        p = Path(a.file)
        if p.stat().st_size > 180 * 1024 * 1024:
            raise Unsupported("input file too large")
        blob = p.read_bytes()
        if p.suffix.lower() == ".b64":
            blob = base64.b64decode(blob.translate(None, b" \t\r\n"), validate=True)
        print(json.dumps(analyze(blob, a.local_function, a.max_instructions), indent=2))
    except (OSError, ValueError, UnicodeError) as e:
        print(json.dumps({"status": "unsupported", "reason": str(e)}), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
