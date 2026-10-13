"""Portable CIL control-flow/token evidence with research-only real fixtures."""
import base64
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
SCRIPT=ROOT/"scripts/dotnet-cil-triage.py"
s=importlib.util.spec_from_file_location("dotnet_cil",SCRIPT)
M=importlib.util.module_from_spec(s);s.loader.exec_module(M)
RESEARCH=ROOT/"research/live-tests/20261009-cross-platform"


class Portable(unittest.TestCase):
    def test_small_method_and_static_token(self):
        # ldarg.0; call MethodDef #2; br.s to ret; nop; ret
        il=bytes.fromhex("02 28 02 00 00 06 2b 01 00 2a")
        r=M.decode_il(il)
        self.assertEqual(r["status"],"DECODED_STATIC")
        self.assertEqual(r["instruction_count"],5)
        self.assertEqual(r["instructions"][1]["token"],"0x6000002")
        self.assertEqual(r["instructions"][2]["target"],9)
        self.assertEqual(r["branch_target_validation"],"PASSED")

    def test_metadata_unicode_json_is_lossless_on_legacy_windows_codepages(self):
        # ConfuserEx can introduce zero-width Unicode in MethodDef/TypeDef names.
        metadata={"name":"\u200c\u200d测试", "status":"STATIC_IL_PARTIAL"}
        wire=M.render_json(metadata)
        self.assertTrue(wire.isascii())
        self.assertEqual(json.loads(wire),metadata)
        self.assertEqual(wire.encode("gbk").decode("gbk"),wire)

    def test_standard_bitwise_and_shift_il_opcodes(self):
        # ECMA-335 Partition III: 0x5f..0x64 have no immediate operands.
        code=bytes.fromhex("5f 60 61 62 63 64 2a")
        r=M.decode_il(code)
        self.assertEqual(r["status"],"DECODED_STATIC")
        self.assertEqual([x["opcode"] for x in r["instructions"]],
                         ["and","or","xor","shl","shr","shr.un","ret"])

    def test_unknown_opcode_and_truncation_are_not_success(self):
        for b in (b"\xff\x2a",b"\xfe",b"\x28\x01",b"\x45\x01"):
            r=M.decode_il(b)
            self.assertEqual(r["status"],"PARTIAL_UNSUPPORTED")
            self.assertIsNotNone(r["unknown"])

    def test_bad_branch_target_fails_evidence(self):
        # br.s jumps into middle of a four-byte i4 immediate.
        r=M.decode_il(bytes.fromhex("2b 02 20 00 00 00 00 2a"))
        self.assertEqual(r["status"],"PARTIAL_UNSUPPORTED")
        self.assertEqual(r["branch_target_validation"],"FAILED")

    def test_branch_target_end_of_method_fails_and_budgeted_tail_is_unknown(self):
        # Branch to offset 2 falls off the end; no valid target instruction.
        end=M.decode_il(bytes.fromhex("2b 00"))
        self.assertEqual(end["status"],"PARTIAL_UNSUPPORTED")
        self.assertEqual(end["branch_target_validation"],"FAILED")
        # Budget truncation before target offset 3 is not proof of an error.
        partial=M.decode_il(bytes.fromhex("2b 01 00 2a"),max_ins=1)
        self.assertEqual(partial["branch_target_validation"],"PARTIAL")
        self.assertEqual(partial["status"],"PARTIAL_UNSUPPORTED")

    def test_budgets_and_native_pe_fail_closed(self):
        with self.assertRaises(M.CILError):
            M.decode_il(b"\x2a",max_ins=0)
        with self.assertRaises(M.CILError):
            M.inspect(b"notPE")
        p=subprocess.run([sys.executable,str(SCRIPT),"--help"],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0)
        self.assertIn("--method",p.stdout)


@unittest.skipUnless((RESEARCH/"cracknet-dotnet.exe.b64").exists(),"research fixtures only on Canonical")
class RealCLR(unittest.TestCase):
    @staticmethod
    def raw(name):
        return base64.b64decode((RESEARCH/name).read_bytes().translate(None,b" \t\r\n"),validate=True)

    def test_cracknet_independent_method_counts(self):
        buf=self.raw("cracknet-dotnet.exe.b64")
        main=M.inspect(buf,"Main",max_instructions=256)
        self.assertEqual(main["artifact_sha256"],"5e14ab3e682153c27ddbdc415a8a292e2d10ae4b2127fedecc809b9650cd4c9d")
        self.assertEqual(main["method_count"],13)
        self.assertEqual(main["status"],"STATIC_IL_DECODED")
        self.assertEqual(main["methods"][0]["il"]["instruction_count"],75)
        crypto=M.inspect(buf,"DecryptStringAES",max_instructions=256)
        self.assertEqual(crypto["methods"][0]["il"]["instruction_count"],102)
        self.assertFalse(main["executed_target"])

    def test_other_dotnet_assemblies(self):
        cases=[("r2-HelloWorld.dll.b64",8),("r2-TestPInvoke.dll.b64",4),("r2-hellocd.dll.b64",4)]
        for name,n in cases:
            with self.subTest(name=name):
                r=M.inspect(self.raw(name),max_methods=3,max_instructions=96)
                self.assertEqual(r["method_count"],n)
                self.assertTrue(r["managed_cli"])
                self.assertTrue(r["methods"])
                self.assertFalse(r["executed_target"])

    def test_real_confuserex_stdout_cp936(self):
        path=RESEARCH/"dotscope-confuserex-mkaring_constants_cfg_controlflow.exe.b64"
        if not path.exists():
            self.skipTest("ConfuserEx compiled fixture only in Canonical")
        env=os.environ.copy()
        env["PYTHONIOENCODING"]="cp936"
        p=subprocess.run([sys.executable,str(SCRIPT),str(path),"--method","Main",
                          "--max-instructions","320"],capture_output=True,env=env,timeout=30)
        self.assertEqual(p.returncode,0,p.stderr.decode("ascii","replace")[:300])
        d=json.loads(p.stdout.decode("ascii"))
        self.assertEqual(d["artifact_sha256"],"03e3787e75028973508ede6aed7bb84885eb3849e6d25a437e149de6d7b7b95d")
        self.assertTrue(d["managed_cli"])
        self.assertNotEqual(d["status"],"REJECTED")

    def test_filename_dotnet_does_not_override_pe_header(self):
        with self.assertRaises(M.CILError):
            M.inspect(self.raw("r2-dotnet-mixed-hello.exe.b64"))


if __name__=="__main__":unittest.main()
