"""Bounded container triage tests; official binaries remain in Canonical research only."""
import base64
import importlib.util
import io
import json
import struct
import subprocess
import sys
import unittest
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SCRIPT=ROOT/"scripts/container-triage.py"
SPEC=importlib.util.spec_from_file_location("container_triage",SCRIPT)
M=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
FIX=ROOT/"research/live-tests/20261009-diverse"


class SyntheticSafetyTests(unittest.TestCase):
    def test_minimal_wasm_does_not_instantiate(self):
        out=M.analyze(b"\x00asm\x01\x00\x00\x00")
        self.assertEqual(out["format"],"WASM")
        self.assertEqual(out["section_count"],0)
        self.assertFalse(out["executed_target"])

    def test_malformed_wasm_rejected(self):
        for sample in (b"\x00asm\x01\x00\x00\x00\x0a\x02\x01",b"\x00asm\x01\x00\x00\x00\x0a\x03\x01\xff\x7f"):
            with self.assertRaises(M.TriageError):
                M.analyze(sample)

    def test_wasm_function_code_section_consistency(self):
        hdr=b"\x00asm\x01\x00\x00\x00"
        cases=(
            hdr+b"\x03\x01\x01",  # one function declared, no code section
            hdr+b"\x01\x01\x00\x01\x01\x00",  # duplicate type section
            hdr+b"\x0a\x04\x01\x02\x00\x0b",  # code body with no function section
        )
        for bad in cases:
            with self.subTest(bad=bad.hex()), self.assertRaises(M.TriageError):
                M.analyze(bad)
        good=hdr+b"\x01\x04\x01\x60\x00\x00\x03\x02\x01\x00\x0a\x04\x01\x02\x00\x0b"
        self.assertEqual(M.analyze(good)["code_bodies"]["count"],1)
        self.assertIn("not full",M.analyze(good)["validation_scope"])

    def test_wasm_u32_leb_overflow(self):
        with self.assertRaises(M.TriageError):
            M.uleb(b"\xff\xff\xff\xff\x7f",0)

    def test_asar_padded_header_offsets_and_tampering(self):
        payload=b'{"files":{"main.js":{"size":2,"offset":"0"}}}'
        padded=payload+b"\x00"*(4+(-len(payload)%4))
        outer=len(padded)+4
        fake=bytearray(struct.pack("<IIII",4,outer,len(padded),len(payload))+padded)
        fake[8+outer:10+outer]=b"OK"
        asar=bytes(fake)
        out=M.analyze(asar)
        self.assertEqual(out["format"],"ASAR")
        self.assertEqual(out["data_start"],8+outer)
        self.assertEqual(out["entries_count"],1)
        self.assertFalse(out["executed_target"])
        with self.assertRaises(M.TriageError):
            M.analyze(asar[:-3])
        bad=payload.replace(b"main.js",b"../pwn?")
        badpad=bad+b"\x00"*(4+(-len(bad)%4))
        crafted=struct.pack("<IIII",4,len(badpad)+4,len(badpad),len(bad))+badpad+b"OK"
        with self.assertRaises(M.TriageError):
            M.analyze(crafted)

    def test_safe_apk_headers_and_invalid_zip(self):
        dex=bytearray(112)
        dex[:8]=b"dex\n035\x00"
        struct.pack_into("<I",dex,88,23)
        struct.pack_into("<I",dex,96,5)
        buf=io.BytesIO()
        with zipfile.ZipFile(buf,"w") as z:
            z.writestr("AndroidManifest.xml",b"\x03\x00\x08\x00")
            z.writestr("classes.dex",dex)
        out=M.analyze(buf.getvalue())
        self.assertEqual(out["format"],"APK")
        self.assertEqual(out["dex"][0]["classes"],5)
        self.assertEqual(out["dex"][0]["methods"],23)
        self.assertFalse(out["executed_target"])
        with self.assertRaises(M.TriageError):
            M.analyze(b"PK\x03\x04"+"0".encode()*30)

    def test_unknown_and_size_gates(self):
        with self.assertRaises(M.TriageError):
            M.analyze(b"junk")
        with self.assertRaises(M.TriageError):
            M.analyze(b"\x00asm\x01\x00\x00\x00",0)
        with self.assertRaises(M.TriageError):
            M.analyze(b"a"*(M.MAX_INPUT+1))


@unittest.skipUnless((FIX/"wasm/extracted.wasm.b64").exists() and
                     (FIX/"asar/extractthis.asar.b64").exists() and
                     (FIX/"android/uncrackable2.apk.b64").exists(),
                     "canonical research artifacts not distributed into Agent copies")
class AuthenticFixtureTests(unittest.TestCase):
    @staticmethod
    def read_fixture(name):
        return base64.b64decode((FIX/name).read_bytes().translate(None,b" \t\r\n"),validate=True)

    def test_public_obfuscated_wasm(self):
        out=M.analyze(self.read_fixture("wasm/extracted.wasm.b64"),limit=12)
        self.assertEqual(out["sha256"],"122e315b27cc9df6e1b0094610976e8f8dda115e41dc61b213b1c0fa6b020176")
        self.assertEqual(out["section_count"],12)
        self.assertEqual(out["code_bodies"]["count"],5)
        self.assertEqual(out["code_bodies"]["largest_bytes"],5129)
        self.assertEqual([x["name"] for x in out["exports"] if x["kind"]==0],
                         ["boring_challenge","__wbindgen_start"])
        self.assertFalse(out["executed_target"])

    def test_upstream_asar_archives(self):
        out=M.analyze(self.read_fixture("asar/extractthis.asar.b64"))
        self.assertEqual(out["sha256"],"1152a16e200b253988e4b8e6fe48667aecaf99f34072af0a984fad8acb390969")
        self.assertEqual(out["data_start"],260)
        self.assertEqual(out["entries_count"],7)
        self.assertIn("/file0.txt",[x["path"] for x in out["entries"]])
        another=M.analyze(self.read_fixture("asar/packthis.asar.b64"))
        self.assertEqual(another["sha256"],"9f6a1857d060c5f03b3e33504ff5db5010e54b035b7b85ce44cb53742b29c2c2")
        self.assertEqual(another["data_start"],1548)
        self.assertEqual(another["entries_count"],8)
        # Independently verify the original-byte payload offsets against upstream file0.txt.
        # A plausible file listing alone is insufficient evidence for ASAR addressing.
        for fixture in ("asar/extractthis.asar.b64", "asar/packthis.asar.b64"):
            raw=self.read_fixture(fixture)
            length=struct.unpack_from('<I',raw,12)[0]
            tree=json.loads(raw[16:16+length])
            entry=tree['files']['file0.txt']
            start=8+struct.unpack_from('<I',raw,4)[0]+int(entry['offset'])
            self.assertEqual(raw[start:start+entry['size']],b'file0 content')

    def test_owasp_jni_multiplatform_apk(self):
        out=M.analyze(self.read_fixture("android/uncrackable2.apk.b64"))
        self.assertEqual(out["sha256"],"4c7980ef1f6cc29508f38417c2a5b5b7721eeb4a3d7f00a0c1a08f5192fa6ddd")
        self.assertEqual(out["archive_entries"],414)
        self.assertEqual(out["dex"][0]["classes"],625)
        self.assertEqual(out["dex"][0]["methods"],7700)
        self.assertEqual([x["machine"] for x in out["native_libraries"]],
                         ["0xb7","0x28","0x3","0x3e"])
        self.assertFalse(out["executed_target"])


if __name__=="__main__":
    unittest.main()
