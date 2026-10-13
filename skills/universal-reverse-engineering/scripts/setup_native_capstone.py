"""Install an optional, hash-pinned Capstone wheel ONLY in project-local research/toolchain.

This package bootstrap is opt-in; its files are independent of the canonical Skill
and all Agent runtimes. Revert by deleting only research/toolchain/capstone-5.0.9.
No global Python/pip configuration, PATH, services, or registry changes.
"""
import hashlib
import io
import json
from pathlib import Path
import sys
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parent.parent
DEST=ROOT/"research/toolchain/capstone-5.0.9"
SOURCE="https://files.pythonhosted.org/packages/50/e6/6f06fdb6a9ed32b2f7cd9c036b92d5324112c3ef7080f2c71efc367d40dd/capstone-5.0.9-py3-none-win_amd64.whl"
EXPECTED="732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0"


def test_backend():
    sys.path.insert(0,str(DEST))
    import capstone
    engine=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    inst=list(engine.disasm(bytes([0x55,0x48,0x89,0xe5,0xc3]),0x401000))
    got=[(x.mnemonic,x.op_str) for x in inst]
    expected=[("push","rbp"),("mov","rbp, rsp"),("ret","")]
    if got!=expected:
        raise AssertionError(f"wrong machine-level decoder output {got}")
    return {"package_version":capstone.__version__,"backend_test":"PASS","decoded":got}


if __name__=="__main__":
    if sys.platform!="win32":
        raise SystemExit("only Windows amd64 wheel supported")
    if not (DEST/"capstone"/"__init__.py").exists():
        if "--install" not in sys.argv:
            raise SystemExit("not installed; run explicitly with --install")
        with urllib.request.urlopen(SOURCE,timeout=60) as response:
            chunks=list(iter(lambda:response.read(65536),b""))
        wheel=b"".join(chunks)
        digest=hashlib.sha256(wheel).hexdigest()
        if digest!=EXPECTED:raise SystemExit(f"wheel SHA256 mismatch: {digest}")
        with zipfile.ZipFile(io.BytesIO(wheel)) as pkg:
            names=pkg.namelist()
            if len(names)>2000 or sum(x.file_size for x in pkg.infolist())>50000000:
                raise SystemExit("unexpected wheel size/file count")
            for member in pkg.infolist():
                if member.filename.startswith("/") or ".." in Path(member.filename).parts:
                    raise SystemExit("wheel traversal rejected")
            pkg.extractall(DEST)
    print(json.dumps({"scope":str(DEST),"upstream":"PyPI capstone==5.0.9 Windows AMD64",
       "upstream_wheel_sha256":EXPECTED,"rollback":"Remove only the scoped toolchain folder",
       **test_backend()},indent=2))
