"""Read-only scoped PowerShell preflight contract; no engine is started."""
import json
import shutil
import subprocess
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("preflight.ps1")
POWERSHELL = shutil.which("powershell.exe")


@unittest.skipUnless(POWERSHELL, "Windows PowerShell is not present on this host")
class PowerShellPreflight(unittest.TestCase):
    @staticmethod
    def run_probe(*args):
        p = subprocess.run(
            [POWERSHELL, "-NoProfile", "-File", str(SCRIPT), *args],
            capture_output=True, text=True, timeout=20,
        )
        if p.returncode:
            raise AssertionError(p.stderr or p.stdout)
        return json.loads(p.stdout)

    def test_csv_list_splits_deduplicates_and_never_smokes(self):
        out = self.run_probe("-ToolNames", "python,node,python")
        self.assertTrue(out["read_only"])
        self.assertEqual(out["verification_scope"], "PATH discovery only; no smoke or target analysis")
        self.assertTrue(out["scoped_tool_check"])
        self.assertEqual([x["name"] for x in out["tools"]], ["python", "node"])
        for tool in out["tools"]:
            self.assertEqual(tool["readiness"], "discovered_unverified" if tool["available"] else "unavailable")
            self.assertFalse(tool["smoke_validated"])
            self.assertFalse(tool["target_validated"])

    def test_nonexistent_backend_cannot_be_declared_ready(self):
        out = self.run_probe("-ToolNames", "__reverse_skill_missing_probe__")
        tool = out["tools"][0]
        self.assertFalse(tool["available"])
        self.assertEqual(tool["readiness"], "unavailable")
        self.assertIsNone(tool["path"])

    def test_deep_backend_inventory_is_discovery_only(self):
        out = self.run_probe()
        self.assertFalse(out["scoped_tool_check"])
        names = {x["name"] for x in out["tools"]}
        self.assertTrue({"rea", "analyzeHeadless", "r2", "rz-bin", "ilspycmd", "unblob", "binwalk", "wasm-tools"} <= names)
        self.assertFalse(any(x["smoke_validated"] or x["target_validated"] for x in out["tools"]))


if __name__ == "__main__":
    unittest.main()
