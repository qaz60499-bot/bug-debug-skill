"""Portable fail-closed WASM call linkage checks; public compiled fixture on Canonical only."""
import base64
import importlib.util
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/wasm-call-targets.py"
RESEARCH = ROOT / "research/live-tests/20261009-cross-platform"
spec = importlib.util.spec_from_file_location("wasm_call_targets", SCRIPT)
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)


def leb(n):
    result = []
    while True:
        c = n & 127
        n >>= 7
        result.append(c | (128 if n else 0))
        if not n:
            return bytes(result)


def sec(tag, payload):
    return bytes([tag]) + leb(len(payload)) + payload


def sample(*, typemismatch=False, slot=0, two_tables=False, dynamic=False):
    # Two real function bodies, with table[0] = function index 0.
    # Caller: call 0; i32.const(slot); call_indirect(type=0, table=0)
    types = sec(1, bytes.fromhex("02 60 00 00 60 01 7f 00") if typemismatch else bytes.fromhex("01 60 00 00"))
    functypes = sec(3, bytes([2, 1 if typemismatch else 0, 0]))
    table_count = 2 if two_tables else 1
    tables = sec(4, bytes([table_count]) + bytes.fromhex("70 00 01") * table_count)
    elements = sec(9, bytes.fromhex("01 00 41 00 0b 01 00"))
    target = bytes.fromhex("00 0b")
    caller = bytes.fromhex("00 10 00 41") + leb(slot) + bytes.fromhex("11 00 00 0b")
    if dynamic:
        caller = bytes.fromhex("00 41 00 41 00 26 00 10 00 41 00 11 00 00 0b")
    code = sec(10, bytes([2]) + leb(len(target)) + target + leb(len(caller)) + caller)
    return bytes.fromhex("00 61 73 6d 01 00 00 00") + types + functypes + tables + elements + code


class Portable(unittest.TestCase):
    def test_real_byte_linkage_and_direct_call(self):
        r = W.analyze(sample(), 1)
        self.assertEqual(r["status"], "static_candidates")
        self.assertFalse(r["executed_target"])
        self.assertEqual(r["decoded_instructions"], 4)
        self.assertEqual(r["calls"][0]["target_function_index"], 0)
        self.assertEqual(r["calls"][1]["slot"], 0)
        self.assertEqual(r["calls"][1]["target_candidates"], [0])
        self.assertEqual(r["calls"][1]["type_index"], 0)

    def test_absent_and_type_mismatched_candidates_fail_closed(self):
        no_slot = W.analyze(sample(slot=1), 1)
        self.assertEqual(no_slot["calls"][1]["target_candidates"], [])
        mismatched = W.analyze(sample(typemismatch=True), 1)
        self.assertEqual(mismatched["calls"][1]["target_candidates"], [])
        with self.assertRaises(W.Unsupported):
            W.analyze(sample(dynamic=True), 1)

    def test_duplicate_and_out_of_order_sections_rejected(self):
        blob = sample()
        extra = sec(1, bytes.fromhex("01 60 00 00"))
        with self.assertRaises(W.Unsupported):
            W.analyze(blob + extra, 1)
        head = blob[:8]
        parts = W.sections(blob)
        reordered = head + sec(3, parts[3]) + sec(1, parts[1]) + sec(4, parts[4]) + sec(9, parts[9]) + sec(10, parts[10])
        with self.assertRaises(W.Unsupported):
            W.analyze(reordered, 1)

    def test_bad_bounds_and_instruction_budget(self):
        with self.assertRaises(W.Unsupported):
            W.analyze(sample(), 7)
        with self.assertRaises(W.Unsupported):
            W.analyze(sample(), 1, 2)
        with self.assertRaises(W.Unsupported):
            W.analyze(sample()[:-1], 1)
        with self.assertRaises(W.Unsupported):
            W.analyze(sample()[:8] + bytes.fromhex("01 80 80 80 80 10"), 0)


@unittest.skipUnless((RESEARCH / "wordle-public-c2a5c5.wasm.b64").exists(), "Canonical-only real compiled fixture")
class RealCompiledWasm(unittest.TestCase):
    def test_wordle_pinned_indirect_table(self):
        buf = base64.b64decode(b"".join((RESEARCH / "wordle-public-c2a5c5.wasm.b64").read_bytes().split()), validate=True)
        r = W.analyze(buf, 2)
        self.assertEqual(r["sha256"], "d3042f57f24d9a2a2e7e0753cbb9a7fa04e222c5a7f43b1e8c50229b7ce31a79")
        self.assertEqual(r["decoded_instructions"], 48)
        self.assertEqual(r["calls"][0]["offset"], 38)
        self.assertEqual(r["calls"][0]["target_candidates"], [10])
        self.assertEqual(r["calls"][0]["slot"], 1)


if __name__ == "__main__":
    unittest.main()
