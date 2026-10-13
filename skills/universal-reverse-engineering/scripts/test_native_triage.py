"""Regression for portable no-install native triage; all target samples remain read-only."""
import base64
import importlib.util
import io
import json
import os
import struct
import zipfile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent.parent
SCRIPT=ROOT/"scripts/native-triage.py"
SPEC=importlib.util.spec_from_file_location("native_triage",SCRIPT)
MODULE=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
PE=ROOT/"research/live-tests/20261009-pe19-stripped/sample.b64"
ELF=ROOT/"research/live-tests/20261009-crackme4/target.b64"
OWASP=ROOT/"research/live-tests/20261009-diverse/android/uncrackable2.apk.b64"
DOTNET=ROOT/"research/live-tests/20261009-cross-platform/cracknet-dotnet.exe.b64"


@unittest.skipUnless(PE.exists() and ELF.exists(), "real sample fixtures live only in Canonical research; not distributed")
class NativeTriageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pe=base64.b64decode(PE.read_bytes().strip(),validate=True)
        cls.elf=base64.b64decode(ELF.read_bytes().strip(),validate=True)

    def test_stripped_pe_real_world_metadata(self):
        result=MODULE.analyze(self.pe,limit=40)
        self.assertEqual(result["sha256"],"a215cf67d7f261706c47d5d7f86c98c7864f081e1f4bb47bb8e63c3071a91037")
        self.assertEqual(result["format"],"PE32+")
        self.assertEqual(result["machine"],"0x8664")
        self.assertEqual(result["entrypoint_rva"],"0x1410")
        self.assertEqual(result["section_count"],10)
        self.assertEqual(result["exception_function_count"],54)
        self.assertEqual(result["candidate_iat_call_count"],12)
        self.assertEqual([(a["dll"],a["total_symbols"]) for a in result["imports"]],
                         [("KERNEL32.dll",14),("msvcrt.dll",27)])
        self.assertEqual(result["entry_within_unwind_function"]["start_rva"],"0x1410")
        self.assertFalse(result["executed_target"])

    def test_bounded_truncation_and_source_caveat(self):
        result=MODULE.analyze(self.pe,limit=3)
        self.assertEqual(len(result["exception_function_ranges_largest"]),3)
        self.assertEqual(len(result["candidate_iat_calls"]),3)
        self.assertTrue(all(a["truncated"] for a in result["imports"]))
        self.assertIn("NOT",result["source_caveat"])

    def test_elffrom_prior_real_sample(self):
        result=MODULE.analyze(self.elf,limit=12)
        self.assertEqual(result["format"],"ELF64-LE")
        self.assertEqual(result["machine"],"0x3e")
        self.assertEqual(result["entrypoint"],"0x400540")
        self.assertEqual(result["section_count"],30)
        self.assertEqual(result["size_bytes"],8740)

    def test_sectionless_elf64_program_headers_from_real_fixture(self):
        # Remove only the section directory from an upstream ELF sample;
        # retain genuine executable bytes and program headers as the oracle.
        altered=bytearray(self.elf)
        struct.pack_into("<Q",altered,40,0)  # e_shoff
        struct.pack_into("<H",altered,60,0)  # e_shnum
        struct.pack_into("<H",altered,62,0)  # e_shstrndx
        out=MODULE.analyze(bytes(altered),limit=24)
        self.assertEqual(out["section_count"],0)
        self.assertEqual(out["machine"],"0x3e")
        self.assertTrue(out["segments"])
        self.assertTrue(any(p["executable"] for p in out["segments"]))
        self.assertEqual(out["dynamic_symbol_count"],0)
        self.assertIn("do not prove",out["source_caveat"])
        broken=bytearray(altered)
        struct.pack_into("<Q",broken,32,len(broken)+4096)  # invalid e_phoff
        with self.assertRaises(MODULE.FormatError):
            MODULE.analyze(bytes(broken))

    def test_corrupt_file_fails_closed(self):
        for b in (b"",b"abc",b"MZ"+b"\x00"*16,b"\x7fELF"+b"\x00"*7):
            with self.subTest(data=b[:4]):
                with self.assertRaises(MODULE.FormatError):
                    MODULE.analyze(b)
        tampered=bytearray(self.pe)
        tampered[0x3c:0x40]=(0xffffff00).to_bytes(4,"little")
        with self.assertRaises(MODULE.FormatError):
            MODULE.analyze(bytes(tampered))

    def test_cold_cli_capped_no_execution(self):
        proc=subprocess.run([sys.executable,str(SCRIPT),str(PE),"--max-items","4"],
                            capture_output=True,text=True,timeout=20)
        self.assertEqual(proc.returncode,0,proc.stderr)
        result=json.loads(proc.stdout)
        self.assertTrue(result["read_only"])
        self.assertFalse(result["executed_target"])
        self.assertEqual(len(result["candidate_iat_calls"]),4)
        self.assertIn("tool_readiness",result)
        self.assertIn(result["deep_disassembly_status"],
                      ("UNAVAILABLE", "DETECTED_UNVERIFIED",
                       "SMOKE_PASS_TARGET_UNVERIFIED", "BROKEN"))
        self.assertEqual(result["deep_disassembly_status"],
                         result["decoder_preflight"]["status"])

    def test_api_line_wrapped_base64_and_invalid_character(self):
        from hashlib import sha256
        encoded=base64.b64encode(self.pe)
        wrapped=b'\r\n'.join(encoded[i:i+73] for i in range(0,len(encoded),73))+b'\n'
        with tempfile.TemporaryDirectory() as td:
            sample=Path(td)/'wrapped.b64'
            sample.write_bytes(wrapped)
            proc=subprocess.run([sys.executable,str(SCRIPT),str(sample),'--max-items','2'],capture_output=True,text=True,timeout=20)
            self.assertEqual(proc.returncode,0,proc.stderr)
            self.assertEqual(json.loads(proc.stdout)['sha256'],sha256(self.pe).hexdigest())
            sample.write_bytes(wrapped+b'%')
            rejected=subprocess.run([sys.executable,str(SCRIPT),str(sample)],capture_output=True,text=True,timeout=20)
            self.assertEqual(rejected.returncode,2)
            self.assertIn('Only base64 data is allowed',rejected.stderr)

    def test_bounded_disassembly_is_opt_in_and_validated(self):
        basic=MODULE.analyze(self.pe,limit=2)
        self.assertNotIn('bounded_disassembly',basic)
        bad=MODULE.bounded_disassembly(self.pe,basic,0x200000,8)
        self.assertIn(bad['status'],('UNAVAILABLE','OUT_OF_EXECUTABLE_RANGE'))
        with self.assertRaises(MODULE.FormatError):
            MODULE.bounded_disassembly(self.pe,basic,-1,2)
        with self.assertRaises(MODULE.FormatError):
            MODULE.bounded_disassembly(self.pe,basic,0x1410,129)

    def test_scoped_decoder_real_sample_without_target_execution(self):
        scope=ROOT/'research/toolchain/capstone-5.0.9'
        if not (scope/'capstone/__init__.py').exists():
            self.skipTest('isolated decoder not present on this Skill installation')
        env=dict(os.environ,PYTHONPATH=str(scope))
        proc=subprocess.run([sys.executable,str(SCRIPT),str(PE),'--max-items','2',
                             '--disasm-at','0x1410','--max-instructions','6'],
                            env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(proc.returncode,0,proc.stderr)
        out=json.loads(proc.stdout)
        decode=out['bounded_disassembly']
        self.assertEqual(decode['status'],'LINEAR_UNVERIFIED')
        self.assertEqual(decode['instruction_count'],6)
        self.assertEqual(decode['instructions'][0]['address'],'0x140001410')
        self.assertFalse(out['executed_target'])
        self.assertIn('No CFG',decode['warning'])
        elfproc=subprocess.run([sys.executable,str(SCRIPT),str(ELF),'--max-items','2',
                                '--disasm-at','0x400540','--max-instructions','5'],
                               env=env,capture_output=True,text=True,timeout=25)
        self.assertEqual(elfproc.returncode,0,elfproc.stderr)
        elfdecode=json.loads(elfproc.stdout)['bounded_disassembly']
        self.assertEqual(elfdecode['status'],'LINEAR_UNVERIFIED')
        self.assertEqual(elfdecode['address_kind'],'ELF_VA')
        self.assertEqual(elfdecode['instructions'][0]['address'],'0x400540')
        self.assertEqual(elfdecode['instructions'][0]['mnemonic'],'xor')

    def test_invalid_budget_rejected(self):
        proc=subprocess.run([sys.executable,str(SCRIPT),str(PE),"--max-items","999"],
                            capture_output=True,text=True,timeout=20)
        self.assertNotEqual(proc.returncode,0)


@unittest.skipUnless(OWASP.exists(), 'OWASP APK source exists only in Canonical research')
class RealMultiAbiAndroidELFTests(unittest.TestCase):
    def test_sectionless_elf32_load_segments_from_real_android_abi(self):
        apk=base64.b64decode(OWASP.read_bytes().translate(None,b' \t\r\n'),validate=True)
        source=zipfile.ZipFile(io.BytesIO(apk)).read('lib/x86/libfoo.so')
        altered=bytearray(source)
        struct.pack_into("<I",altered,32,0)  # e_shoff
        struct.pack_into("<H",altered,48,0)  # e_shnum
        struct.pack_into("<H",altered,50,0)  # e_shstrndx
        out=MODULE.analyze(bytes(altered))
        self.assertEqual(out['format'],'ELF32-LE')
        self.assertEqual(out['section_count'],0)
        self.assertTrue(out['segments'])
        self.assertFalse(out['executed_target'])

    def test_elf32_arm_x86_and_elf64_jni_exports(self):
        apk=base64.b64decode(OWASP.read_bytes().translate(None,b' \t\r\n'),validate=True)
        archive=zipfile.ZipFile(io.BytesIO(apk))
        cases=[('lib/armeabi-v7a/libfoo.so','ELF32-LE','0x28'),
               ('lib/x86/libfoo.so','ELF32-LE','0x3'),
               ('lib/arm64-v8a/libfoo.so','ELF64-LE','0xb7'),
               ('lib/x86_64/libfoo.so','ELF64-LE','0x3e')]
        for path,format_expected,machine in cases:
            with self.subTest(abi=path):
                raw=archive.read(path)
                out=MODULE.analyze(raw,limit=12)
                self.assertEqual((out['format'],out['machine']),(format_expected,machine))
                jni={v['name'] for v in out['symbols'] if v['name'].startswith('Java_')}
                self.assertEqual(jni,{
                    'Java_sg_vantagepoint_uncrackable2_CodeCheck_bar',
                    'Java_sg_vantagepoint_uncrackable2_MainActivity_init'})
                self.assertFalse(out['executed_target'])


@unittest.skipUnless(DOTNET.exists(), "pinned .NET research binary stays in Canonical only")
class RealDotNetCliHeaderTests(unittest.TestCase):
    @staticmethod
    def sample():
        return base64.b64decode(DOTNET.read_bytes().translate(None,b' \t\r\n'),validate=True)

    def test_real_dotnet_metadata_root_detected_without_il_claim(self):
        out=MODULE.analyze(self.sample(),limit=4)
        self.assertEqual(out['sha256'], '5e14ab3e682153c27ddbdc415a8a292e2d10ae4b2127fedecc809b9650cd4c9d')
        self.assertEqual(out['format'], 'PE32')
        self.assertTrue(out['managed_cli'])
        self.assertEqual(out['clr_metadata']['metadata_rva'], '0x2760')
        self.assertEqual(out['clr_metadata']['status'], 'VALID_METADATA_ROOT_UNPARSED')
        self.assertFalse(out['executed_target'])

    def test_corrupt_clr_metadata_signature_fails_closed(self):
        raw=bytearray(self.sample())
        # CLR metadata root absolute file offset: derive from its RVA using PE sections.
        cli=MODULE.analyze(bytes(raw))['clr_metadata']
        rva=int(cli['metadata_rva'],16)
        sec=next(s for s in MODULE.analyze(bytes(raw))['sections']
                 if s['rva']<=rva<s['rva']+s['raw_size'])
        at=sec['offset']+rva-sec['rva']
        raw[at:at+4]=b'XXXX'
        with self.assertRaises(MODULE.FormatError):
            MODULE.analyze(bytes(raw))


class PortableSafetyTests(unittest.TestCase):
    def test_unknown_and_truncated_inputs_rejected(self):
        for data in (b"",b"junk",b"MZ"+b"\\x00"*4):
            with self.assertRaises(MODULE.FormatError):
                MODULE.analyze(data)

    def test_probe_does_not_claim_disassembler(self):
        r=MODULE.tool_readiness()
        self.assertIn("objdump",r)
        self.assertIn("python_capstone",r)
        self.assertIsInstance(r["python_capstone"],bool)
        result=MODULE.decoder_preflight(r)
        self.assertIn(result["status"],("UNAVAILABLE","DETECTED_UNVERIFIED",
                                        "SMOKE_PASS_TARGET_UNVERIFIED","BROKEN"))

    def test_disassembler_path_does_not_prove_decoder(self):
        fake={"python_capstone":False,"objdump":"C:/fake/objdump.exe",
              "radare2":None,"ghidra_headless":None}
        r=MODULE.decoder_preflight(fake)
        self.assertEqual(r["status"],"DETECTED_UNVERIFIED")

    def test_capstone_smoke_requires_verified_instructions(self):
        from types import SimpleNamespace
        class Engine:
            def __init__(self, correct):
                self.correct=correct
            def disasm(self, bytecode, address):
                if not self.correct:
                    return [SimpleNamespace(address=0x1000,mnemonic="nop")]
                return [SimpleNamespace(address=0x1000,mnemonic="push"),
                        SimpleNamespace(address=0x1001,mnemonic="mov"),
                        SimpleNamespace(address=0x1004,mnemonic="ret")]
        good=SimpleNamespace(CS_ARCH_X86=3,CS_MODE_64=8,
                              Cs=lambda *args:Engine(True))
        bad=SimpleNamespace(CS_ARCH_X86=3,CS_MODE_64=8,
                             Cs=lambda *args:Engine(False))
        self.assertTrue(MODULE.capstone_decode_smoke(good))
        self.assertFalse(MODULE.capstone_decode_smoke(bad))
        broken=SimpleNamespace(CS_ARCH_X86=3,CS_MODE_64=8,
                 Cs=lambda *args: (_ for _ in ()).throw(TypeError("injected broken backend")))
        self.assertFalse(MODULE.capstone_decode_smoke(broken))


if __name__=="__main__":
    unittest.main()
