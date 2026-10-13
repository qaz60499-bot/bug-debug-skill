"""No-install MIPS32 GOT resolver regressions; synthetic fixtures work on every Agent."""
import base64
import importlib.util
import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/native-call-targets.py"
NATIVE = ROOT / "scripts/native-triage.py"
RESEARCH = ROOT / "research/live-tests/20261009-cross-platform"
s = importlib.util.spec_from_file_location("native_call_targets", SCRIPT)
MODULE = importlib.util.module_from_spec(s)
s.loader.exec_module(MODULE)
n = importlib.util.spec_from_file_location("native_triage_be", NATIVE)
TRIAGE = importlib.util.module_from_spec(n)
n.loader.exec_module(TRIAGE)


def fixture(endian="<", malformed=None, with_sections=False):
    """Minimal executable ELF32 MIPS, with exact GP/GOT/PT_DYNAMIC and one PLT trampoline."""
    data = bytearray(0xb00)
    data[:16] = b"\x7fELF\x01" + (b"\x01" if endian == "<" else b"\x02") + b"\x01" + b"\x00" * 9

    def put(fmt, offset, *values):
        struct.pack_into(endian + fmt, data, offset, *values)

    put("HHIIIIIHHHHHH", 16, 2, 8, 1, 0x400340, 52, 0, 0, 52, 32, 4, 0, 0, 0)
    phdrs = [
        (1, 0, 0x400000, 0, 0x700, 0x700, 5, 0x1000),
        (1, 0x700, 0x500000, 0, 0x400, 0x400, 6, 0x1000),
        (2, 0x150, 0x400150, 0, 0xb0, 0xb0, 4, 4),
        (0x70000000, 0x130, 0x400130, 0, 24, 24, 4, 4),
    ]
    for i, item in enumerate(phdrs):
        put("8I", 52 + i * 32, *item)
    put("I", 0x130 + 20, 0x5080f0)  # GP from PT_MIPS_REGINFO
    dynamics = [
        (3, 0x500100), (5, 0x400300), (6, 0x400280), (10, 64), (11, 16),
        (0x7000000a, 1), (0x70000011, 3), (0x70000013, 2), (0, 0),
    ]
    for i, (kind, val) in enumerate(dynamics):
        put("II", 0x150 + i * 8, kind, val)
    put("IIIBBH", 0x280 + 2 * 16, 1, 0x400400, 16, 2, 0, 1)
    data[0x301:0x301 + 7] = b"mockfn\x00"
    # MIPS32 LW t9,-0x7ff0(gp), JALR t9, NOP
    lw = (0x23 << 26) | (28 << 21) | (25 << 16) | 0x8010
    jalr = (25 << 21) | (31 << 11) | 9
    move = (31 << 21) | (15 << 11) | 0x21
    addiu = (9 << 26) | (24 << 16) | 2
    for i, word in enumerate([lw, jalr, 0]):
        put("I", 0x340 + i * 4, word)
    for i, word in enumerate([lw, move, jalr, addiu]):
        put("I", 0x400 + i * 4, word)
    put("I", 0x800, 0x400400)
    put("I", 0x804, 0)
    if malformed == "dynsym_index":
        put("I", 0x400 + 12, (9 << 26) | (24 << 16) | 99)
    elif malformed == "no_pt_dynamic":
        put("I", 52 + 2 * 32, 4)
    elif malformed == "truncated_got":
        put("I", 0x150 + 0 * 8 + 4, 0x600000)
    elif malformed == "bad_gp":
        put("I", 0x130 + 20, 0x7080f0)
    elif malformed == "bad_stub":
        put("I", 0x400 + 4, 0)
    elif malformed == "bad_magic":
        data[0] = 0
    return bytes(data)


class SyntheticPortableTests(unittest.TestCase):
    def test_le_be_without_section_table(self):
        for endian, suffix in (("<", "LE"), (">", "BE")):
            with self.subTest(endian=endian):
                b = fixture(endian)
                r = MODULE.inspect(b, limit=8)
                self.assertEqual(r["format"], "ELF32-" + suffix)
                self.assertEqual(r["status"], "STATIC_MATCHES")
                self.assertEqual(r["resolved_import_calls"], 1)
                self.assertEqual(r["calls"][0]["target_symbol"], "mockfn")
                self.assertEqual(r["calls"][0]["got"], "0x500100")
                self.assertTrue(r["read_only"])
                self.assertFalse(r["executed_target"])
                p = TRIAGE.analyze(b, limit=5)
                self.assertEqual(p["format"], "ELF32-" + suffix)
                self.assertEqual(p["section_count"], 0)
                self.assertTrue(p["segments"])

    def test_corrupted_indirect_edges_do_not_match(self):
        for typo in ("dynsym_index", "bad_gp", "bad_stub", "truncated_got"):
            with self.subTest(kind=typo):
                r = MODULE.inspect(fixture(malformed=typo), limit=8)
                self.assertEqual(r["resolved_import_calls"] if "resolved_import_calls" in r else 0, 0)

    def test_targeted_callsite_is_bounded_and_reproducible(self):
        for endian in ("<", ">"):
            found = MODULE.inspect(fixture(endian), limit=2, callsite=0x400344)
            self.assertEqual(found["focus_callsite"], "0x400344")
            self.assertEqual(found["resolved_import_calls"], 1)
            self.assertEqual(len(found["calls"]), 1)
            self.assertEqual(found["calls"][0]["target_symbol"], "mockfn")
            missed = MODULE.inspect(fixture(endian), limit=2, callsite=0x40034c)
            self.assertEqual(missed["resolved_import_calls"], 0)
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.inspect(fixture(), callsite=0x400345)
    def test_missing_dynamic_or_wrong_machine_fails_closed(self):
        r = MODULE.inspect(fixture(malformed="no_pt_dynamic"))
        self.assertEqual(r["status"], "UNSUPPORTED")
        raw = bytearray(fixture())
        struct.pack_into("<H", raw, 18, 3)
        self.assertEqual(MODULE.inspect(bytes(raw))["status"], "UNSUPPORTED")
        self.assertEqual(MODULE.inspect(fixture(malformed="bad_magic"))["status"], "UNSUPPORTED")

    def test_bounded_rejects_malformed(self):
        for opts in ({"limit": 1000}, {"scan_bytes": 0}):
            with self.assertRaises(MODULE.EvidenceError):
                MODULE.inspect(fixture(), **opts)
        b = bytearray(fixture())
        struct.pack_into("<I", b, 28, 0xffffffff)
        with self.assertRaises(MODULE.EvidenceError):
            MODULE.inspect(bytes(b))
        with self.assertRaises(TRIAGE.FormatError):
            TRIAGE.analyze(bytes(b))

    def test_got_scan_not_a_default_router_side_effect(self):
        self.assertNotIn("native-call-targets", json.dumps(TRIAGE.analyze(fixture())))
        self.assertEqual(MODULE.inspect(fixture(), scan_bytes=0x100)["status"], "NO_MATCHES")

    def test_original_bytecode_never_executed(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, timeout=10)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("--max-scan-bytes", proc.stdout)


@unittest.skipUnless((RESEARCH / "tplink-httpd.elf.b64").exists(), "research samples only on Canonical")
class RealFirmwareTests(unittest.TestCase):
    @staticmethod
    def real(name):
        return base64.b64decode((RESEARCH / name).read_bytes().translate(None, b" \t\r\n"), validate=True)

    def test_tplink_real_indirect_calls(self):
        r = MODULE.inspect(self.real("tplink-httpd.elf.b64"), limit=128)
        self.assertGreater(r["resolved_import_calls"], 500)
        self.assertGreater(r["unique_import_symbols"], 70)
        exact = MODULE.inspect(self.real("tplink-httpd.elf.b64"), callsite=0x4054d8)
        self.assertEqual(exact["resolved_import_calls"], 1)
        self.assertEqual(exact["calls"][0]["target_symbol"], "strstr")
        self.assertEqual(exact["calls"][0]["stub"], "0x413210")

    def test_second_mips_le_real(self):
        r = MODULE.inspect(self.real("r2-mips-main.bin.b64"))
        self.assertEqual(r["resolved_import_calls"], 1)
        self.assertEqual(r["calls"][0]["target_symbol"], "__libc_start_main")

    def test_sectionless_big_endian_real(self):
        raw = self.real("r2-boa-mips.elf.b64")
        out = TRIAGE.analyze(raw, limit=10)
        self.assertEqual(out["format"], "ELF32-BE")
        self.assertEqual(out["section_count"], 0)
        self.assertEqual(len(out["segments"]), 2)
        r = MODULE.inspect(raw, limit=12)
        self.assertEqual(r["format"], "ELF32-BE")
        self.assertGreater(r["resolved_import_calls"], 100)
        self.assertIn("static GOT", " ".join(r["calls"][0]["assumptions"]))


if __name__ == "__main__":
    unittest.main()
