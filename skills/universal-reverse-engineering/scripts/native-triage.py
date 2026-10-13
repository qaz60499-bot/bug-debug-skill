#!/usr/bin/env python3
"""Read-only PE32/PE64 and ELF32/ELF64 LE/BE triage; no execution, installs or writes."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import struct
import sys
from pathlib import Path


class FormatError(ValueError):
    pass


def field(buf: bytes, fmt: str, offset: int):
    n = struct.calcsize(fmt)
    if offset < 0 or n + offset > len(buf):
        raise FormatError(f"truncated field at 0x{offset:x}, expected {n} bytes")
    result = struct.unpack_from(fmt, buf, offset)
    return result[0] if len(result) == 1 else result


def ascii_z(buf: bytes, offset: int, limit: int = 192) -> str:
    if not (0 <= offset < len(buf)):
        raise FormatError(f"string outside file: 0x{offset:x}")
    raw = buf[offset:min(len(buf), offset + limit)].split(b"\x00", 1)[0]
    return raw.decode("utf-8", "replace")


def entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = [0] * 256
    for b in blob:
        counts[b] += 1
    n = len(blob)
    return round(-sum((c / n) * math.log2(c / n) for c in counts if c), 3)


def scoped_capstone_available() -> bool:
    """Discover only installed or already staged Capstone, never install it.

    Canonical research has a pinned decoder; lean Agent copies can opt in via
    RE_CAPSTONE_ROOT pointing to an authorized existing package directory.
    """
    if importlib.util.find_spec("capstone") is not None:
        return True
    roots = []
    if os.environ.get("RE_CAPSTONE_ROOT"):
        roots.append(Path(os.environ["RE_CAPSTONE_ROOT"]))
    roots.append(Path(__file__).resolve().parents[1] / "research/toolchain/capstone-5.0.9")
    for root in roots:
        if (root / "capstone/__init__.py").is_file():
            name = str(root)
            if name not in sys.path:
                sys.path.insert(0, name)
            return importlib.util.find_spec("capstone") is not None
    return False


def tool_readiness() -> dict:
    names = {"objdump": ("llvm-objdump", "llvm-objdump.exe", "objdump", "objdump.exe"),
             "radare2": ("r2", "r2.exe"), "ghidra_headless": ("analyzeHeadless", "analyzeHeadless.bat")}
    found = {key: next((shutil.which(t) for t in variants if shutil.which(t)), None)
             for key, variants in names.items()}
    found["python_capstone"] = scoped_capstone_available()
    found["python_pefile"] = importlib.util.find_spec("pefile") is not None
    return found


def capstone_decode_smoke(module) -> bool:
    """Verify decoded mnemonic/address sequence; mere module presence is not readiness."""
    try:
        engine = module.Cs(module.CS_ARCH_X86, module.CS_MODE_64)
        insns = list(engine.disasm(b"\x55\x48\x89\xe5\xc3", 0x1000))
        return [(i.address, i.mnemonic.lower()) for i in insns] == [
            (0x1000, "push"), (0x1001, "mov"), (0x1004, "ret")
        ]
    except Exception:
        return False


def decoder_preflight(readiness: dict) -> dict:
    """Differentiate PATH detection from actual instruction decoding."""
    if readiness["python_capstone"]:
        try:
            import capstone
            if capstone_decode_smoke(capstone):
                return {"status": "SMOKE_PASS_TARGET_UNVERIFIED", "backend": "capstone",
                        "reason": "Decoded trusted x86-64 bytes; target-specific analysis still required"}
            return {"status": "BROKEN", "backend": "capstone",
                    "reason": "Capstone present but instruction smoke test failed"}
        except Exception as error:
            return {"status": "BROKEN", "backend": "capstone",
                    "reason": type(error).__name__}
    detected = [name for name in ("objdump", "radare2", "ghidra_headless") if readiness[name]]
    if detected:
        return {"status": "DETECTED_UNVERIFIED", "backend": detected,
                "reason": "Executable path alone does not establish working disassembly"}
    return {"status": "UNAVAILABLE", "backend": None,
            "reason": "No confirmed working instruction decoder"}


def ascii_inventory(buf: bytes, sections: list[dict], limit: int, query: str = "") -> dict:
    """Scans bounded non-executable data. Text hits are observations, not semantics."""
    count=0
    results=[]
    needle=query.lower()
    for sec in sections:
        if sec.get("executable",False) or sec.get("raw_size",0)<=0:
            continue
        raw=buf[sec["offset"]:sec["offset"]+sec["raw_size"]]
        for m in re.finditer(rb"[\x20-\x7e]{6,}",raw):
            value=m.group().decode("ascii","replace")
            if needle and needle not in value.lower():
                continue
            count+=1
            if len(results)<limit:
                results.append({"section":sec["name"],"rva":hex(sec["rva"]+m.start()),
                                "file_offset":hex(sec["offset"]+m.start()),"text":value[:160]})
    return {"hits_total":count,"hits":results,"truncated":count>len(results),
            "query":query,"confidence":"raw ASCII presence only"}


def inspect_pe(buf: bytes, limit: int) -> dict:
    peoff = field(buf, "<I", 0x3c)
    if peoff > len(buf) - 256 or buf[peoff:peoff+4] != b"PE\x00\x00":
        raise FormatError("invalid or truncated PE signature")
    coff = peoff + 4
    machine, nsections, timestamp, _, _, optional_size, flags = field(buf, "<HHIIIHH", coff)
    opt = coff + 20
    magic = field(buf, "<H", opt)
    if magic not in (0x20b, 0x10b):
        raise FormatError(f"unsupported PE optional header 0x{magic:x}")
    is64 = magic == 0x20b
    entry_rva = field(buf, "<I", opt+16)
    image_base = field(buf, "<Q" if is64 else "<I", opt+24 if is64 else opt+28)
    ndd = field(buf, "<I", opt+(108 if is64 else 92))
    dir_off = opt+(112 if is64 else 96)
    def directory(idx):
        if idx >= ndd or dir_off+8*(idx+1) > opt+optional_size:
            return (0, 0)
        return field(buf, "<II", dir_off+idx*8)
    sections = []
    for i in range(min(nsections, 96)):
        o = opt+optional_size+i*40
        raw_name, virt_size, rva, raw_size, raw_ptr, _, _, _, _, characteristics = field(buf, "<8sIIIIIIHHI", o)
        if raw_size and (raw_ptr+raw_size > len(buf)):
            raise FormatError("section raw content extends beyond file")
        name = raw_name.split(b"\x00",1)[0].decode("ascii","replace")
        sections.append({"name":name,"rva":rva,"virtual_size":virt_size,"offset":raw_ptr,
                         "raw_size":raw_size,"entropy":entropy(buf[raw_ptr:raw_ptr+raw_size]),
                         "executable":bool(characteristics & 0x20000000)})
    def raw_offset(rva, count=1):
        for sec in sections:
            if sec["rva"] <= rva and rva+count <= sec["rva"]+sec["raw_size"]:
                offset=sec["offset"]+rva-sec["rva"]
                if offset+count <= len(buf): return offset
        if 0 <= rva < min(len(buf),opt+optional_size+nsections*40) and rva+count <= len(buf):
            return rva  # mapped PE header
        return None
    def read_at_rva(rva, fmt):
        off=raw_offset(rva,struct.calcsize(fmt))
        if off is None: raise FormatError(f"RVA 0x{rva:x} is not file backed")
        return field(buf,fmt,off)
    imports = []
    iat_names = {}
    import_dir, import_size = directory(1)
    if import_dir and import_size:
        for i in range(min(import_size//20,128)):
            desc_rva=import_dir+i*20
            o=raw_offset(desc_rva,20)
            if o is None: break
            original,ts,chain,name_rva,iat_rva=field(buf,"<IIIII",o)
            if not (original or name_rva or iat_rva): break
            name_off=raw_offset(name_rva)
            if name_off is None: continue
            dll=ascii_z(buf,name_off)
            names=[]
            total_symbols=0
            stride=8 if is64 else 4
            ordinal_flag=1 << (63 if is64 else 31)
            for k in range(4096):
                thunk=original or iat_rva
                at=raw_offset(thunk+k*stride,stride)
                if at is None: break
                val=field(buf,"<Q" if is64 else "<I",at)
                if val == 0: break
                if val & ordinal_flag:
                    name=f"ordinal:{val & 0xffff}"
                else:
                    pos=raw_offset(val+2)
                    if pos is None: name="unresolved-name"
                    else: name=ascii_z(buf,pos)
                total_symbols+=1
                iat_names[iat_rva+k*stride]=name
                if len(names)<limit:
                    names.append({"name":name,"iat_rva":hex(iat_rva+k*stride)})
            imports.append({"dll":dll,"symbols":names,"total_symbols":total_symbols,
                            "truncated":total_symbols>len(names)})
    functions=[]
    exception_rva,exception_size=directory(3)
    if is64 and exception_rva and exception_size:
        for i in range(min(exception_size//12,100000)):
            pos=raw_offset(exception_rva+i*12,12)
            if pos is None: break
            start,end,unwind=field(buf,"<III",pos)
            if not (0 < start < end):
                continue
            if any(s["executable"] and s["rva"]<=start< s["rva"]+max(s["virtual_size"],s["raw_size"]) for s in sections):
                functions.append({"start_rva":hex(start),"end_rva":hex(end),"size":end-start,
                                  "unwind_rva":hex(unwind)})
    largest=sorted(functions,key=lambda x:x["size"],reverse=True)[:limit]
    # Only syntactic byte candidates: the start of each instruction is NOT established
    # without a real decoder. Never promote these to confirmed call-graph edges.
    candidate_iat_calls=[]
    candidate_total=0
    for sec in sections:
        if not sec["executable"] or not sec["raw_size"]:
            continue
        code=buf[sec["offset"]:sec["offset"]+sec["raw_size"]]
        for j in range(len(code)-5):
            if code[j:j+2]!=b"\xff\x15":
                continue
            rel=field(code,"<i",j+2)
            target=sec["rva"]+j+6+rel
            if target not in iat_names:
                continue
            candidate_total+=1
            if len(candidate_iat_calls)<limit:
                origin=sec["rva"]+j
                container=next((f for f in functions if int(f["start_rva"],16)<=origin<int(f["end_rva"],16)),None)
                candidate_iat_calls.append({"candidate_rva":hex(origin),"iat_rva":hex(target),
                    "import_name":iat_names[target],
                    "enclosing_unwind_range":container["start_rva"] if container else None})
    # CLI data-directory evidence distinguishes .NET assemblies from ordinary PE files.
    # A valid metadata signature is a container observation, never recovered IL semantics.
    cli_rva, cli_size = directory(14)
    cli = None
    if cli_rva or cli_size:
        if cli_size < 72:
            raise FormatError("truncated CLR CLI directory")
        cli_off = raw_offset(cli_rva, 72)
        if cli_off is None:
            raise FormatError("CLR CLI header outside file-backed PE sections")
        cb, runtime_major, runtime_minor, metadata_rva, metadata_size = field(buf, "<IHHII", cli_off)
        if cb < 72 or metadata_rva == 0 or metadata_size < 16:
            raise FormatError("invalid CLR CLI metadata bounds")
        metadata_off = raw_offset(metadata_rva, 16)
        if metadata_off is None or buf[metadata_off:metadata_off+4] != b"BSJB":
            raise FormatError("invalid CLR metadata root signature")
        cli = {"status":"VALID_METADATA_ROOT_UNPARSED", "cli_rva":hex(cli_rva),
               "metadata_rva":hex(metadata_rva), "metadata_size":metadata_size,
               "runtime_version":f"{runtime_major}.{runtime_minor}",
               "source_caveat":"Metadata root signature proves CLR container, not IL decoding or execution behavior"}
    return {"format":"PE32+" if is64 else "PE32","machine":hex(machine),"entrypoint_rva":hex(entry_rva),
            "managed_cli":cli is not None,"clr_metadata":cli,
            "image_base":hex(image_base),"section_count":nsections,"sections":sections,
            "import_directory_rva":hex(import_dir),"imports":imports,
            "exception_function_count":len(functions),
            "exception_function_ranges_largest":largest,
            "entry_within_unwind_function":next((f for f in functions if int(f["start_rva"],16)<=entry_rva<int(f["end_rva"],16)),None),
            "candidate_iat_call_count":candidate_total,"candidate_iat_calls":candidate_iat_calls,
            "tls_directory_rva":hex(directory(9)[0]),
            "source_caveat":"PE imports and unwind ranges are metadata. Byte-pattern matches are candidate call sites, NOT decoded instructions or proven executable paths."}


def inspect_elf(buf: bytes, limit: int) -> dict:
    """Bounded ELF32/ELF64 LE/BE metadata and dynamic symbol evidence; no execution."""
    if len(buf) < 52 or not buf.startswith(b"\x7fELF") or buf[4] not in (1, 2) or buf[5] not in (1, 2):
        raise FormatError("ELF32 or ELF64 little/big-endian required")
    is64 = buf[4] == 2
    endian = "<" if buf[5] == 1 else ">"
    suffix = "LE" if buf[5] == 1 else "BE"
    hdrfmt = endian + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    typ,machine,ver,entry,phoff,shoff,flags,ehsize,phentsize,phnum,shentsize,shnum,shstridx=field(buf,hdrfmt,16)
    minimum = 64 if is64 else 52
    required_sh = 64 if is64 else 40
    if ehsize < minimum:
        raise FormatError("invalid ELF header size")
    if shoff == 0 and shnum == 0:
        # Valid sectionless ELF images occur in stripped firmware. Bound PT_LOAD
        # evidence by the program-header directory, not speculative sections.
        required_ph = 56 if is64 else 32
        if not (0 < phnum <= 4096 and phentsize >= required_ph and
                phoff <= len(buf) and phnum * phentsize <= len(buf) - phoff):
            raise FormatError("sectionless ELF requires valid program headers")
        segments = []
        for i in range(phnum):
            values = field(buf, endian + ("IIQQQQQQ" if is64 else "IIIIIIII"),
                           phoff + i * phentsize)
            if is64:
                ptype, pflags, poff, vaddr, _, filesz, memsz, _ = values
            else:
                ptype, poff, vaddr, _, filesz, memsz, pflags, _ = values
            if poff > len(buf) or filesz > len(buf) - poff or (ptype == 1 and memsz < filesz):
                raise FormatError("ELF program segment outside file or invalid memory size")
            if ptype == 1:
                segments.append({"name":"PT_LOAD", "addr":hex(vaddr),
                                 "offset":poff,"size":filesz,"mem_size":memsz,
                                 "type":ptype,"flags":hex(pflags),
                                 "executable":bool(pflags & 1)})
        return {"format":f"ELF{64 if is64 else 32}-{suffix}",
                "machine":hex(machine),"type":typ,"entrypoint":hex(entry),
                "section_count":0,"sections":[],"segments":segments[:limit],
                "segments_truncated":len(segments)>limit,
                "dynamic_symbol_count":0,"symbols":[],"symbols_truncated":False,
                "source_caveat":"Sectionless ELF: bounded PT_LOAD program headers only; missing sections do not prove no dynamic symbols, code semantics, or functions"}
    if shentsize < required_sh or not (0 < shnum <= 4096) or not (0 <= shstridx < shnum):
        raise FormatError("invalid ELF header or section count")
    if shoff > len(buf) or shnum * shentsize > len(buf) - shoff:
        raise FormatError("ELF section directory out of bounds")
    raw=[]
    section_fmt = endian + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    for i in range(shnum):
        name_idx,kind,flg,addr,off,size,link,info,align,entsize=field(buf,section_fmt,shoff+i*shentsize)
        if kind != 8 and (off > len(buf) or size > len(buf)-off):
            raise FormatError("ELF section out of bounds")
        raw.append((name_idx,kind,flg,addr,off,size,link,info,align,entsize))
    names=raw[shstridx]
    if names[1]!=3 or names[5]>len(buf)-names[4]:
        raise FormatError("invalid ELF section name table")
    name_blob=buf[names[4]:names[4]+names[5]]
    sections=[]
    for entry0 in raw:
        name_idx,kind,flg,addr,off,size,*_=entry0
        name=ascii_z(name_blob,name_idx) if name_idx < len(name_blob) else "?"
        sections.append({"name":name,"addr":hex(addr),"offset":off,"size":size,"type":kind,
                         "entropy":entropy(buf[off:off+size]) if kind!=8 else 0,
                         "executable":bool(flg&4)})
    total_symbols=0
    named_exports=[]
    examples=[]
    for idx,sec in enumerate(raw):
        name_idx,kind,flg,addr,off,size,link,info,align,entsize=sec
        if kind != 11:  # only .dynsym; avoid full debug/symbol databases
            continue
        expected=24 if is64 else 16
        if not (0 <= link < len(raw)) or entsize < expected or entsize==0:
            raise FormatError("invalid ELF dynamic symbol table")
        strsec=raw[link]
        if strsec[1]!=3 or strsec[5]>len(buf)-strsec[4]:
            raise FormatError("invalid ELF symbol string table")
        strings=buf[strsec[4]:strsec[4]+strsec[5]]
        count=size//entsize
        if count>200000: raise FormatError("excessive ELF dynamic symbol table")
        total_symbols+=count
        for j in range(count):
            at=off+j*entsize
            if is64:
                st_name,st_info,st_other,st_shndx,st_value,st_size=field(buf,endian+"IBBHQQ",at)
            else:
                st_name,st_value,st_size,st_info,st_other,st_shndx=field(buf,endian+"IIIBBH",at)
            if not st_name or st_name>=len(strings):
                continue
            symbol=ascii_z(strings,st_name,limit=256)
            item={"name":symbol,"addr":hex(st_value),"size":st_size,
                  "type":st_info&15,"defined":st_shndx!=0}
            if st_shndx!=0 and (symbol.startswith("Java_") or symbol=="JNI_OnLoad"):
                named_exports.append(item)
            elif len(examples)<limit and st_shndx!=0 and (st_info&15)==2:
                examples.append(item)
    chosen=(named_exports+examples)[:limit]
    return {"format":f"ELF{64 if is64 else 32}-{suffix}","machine":hex(machine),
            "type":typ,"entrypoint":hex(entry),"section_count":shnum,
            "sections":sections[:max(40,limit)],"sections_truncated":shnum>max(40,limit),
            "dynamic_symbol_count":total_symbols,
            "symbols":chosen,"symbols_truncated":len(named_exports)+len(examples)>len(chosen),
            "source_caveat":"ELF sections and defined dynsym names are static facts, not reachable behavior or JNI call evidence"}



def bounded_disassembly(buf: bytes, metadata: dict, address: int, limit: int) -> dict:
    """Optional bounded linear decode at one PE RVA / ELF VA, not a CFG.

    Supports x86/x64 PE/ELF, plus ELF32 MIPS/ARM and ELF64 AArch64, with
    actual architecture/endian encoded in each verified target header. Never
    infer reachability, runtime relocation, or decrypted-state behavior.
    """
    if address < 0 or not (1 <= limit <= 128):
        raise FormatError("bounded disassembly requires nonnegative address and count 1..128")
    fmt = metadata["format"]
    machine = metadata["machine"]
    is_pe = fmt.startswith("PE")
    if is_pe:
        supported = machine in ("0x8664", "0x14c")
    else:
        supported = ((fmt.startswith("ELF32-") and machine in ("0x3", "0x8", "0x28")) or
                     (fmt.startswith("ELF64-") and machine in ("0x3e", "0xb7")))
    if not supported:
        return {"status": "UNSUPPORTED_ARCH", "reason": "No bounded decoder mapping for this machine/format"}
    if metadata["decoder_preflight"]["status"] != "SMOKE_PASS_TARGET_UNVERIFIED":
        return {"status": "UNAVAILABLE", "reason": "No tested decoder; no automatic install or tool bootstrap"}
    try:
        import capstone
    except ImportError:
        return {"status": "UNAVAILABLE", "reason": "Capstone module is not importable"}
    for sec in (metadata["sections"] or metadata.get("segments", [])):
        if not sec["executable"]:
            continue
        section_address = sec["rva"] if is_pe else sec["addr"]
        start = int(section_address,16) if isinstance(section_address,str) else int(section_address)
        available = sec["raw_size"] if is_pe else sec["size"]
        if not (start <= address < start + available):
            continue
        offset = sec["offset"] + address - start
        if offset >= len(buf):
            break
        count_bytes = min(available - (address-start), len(buf)-offset, min(1024,limit*15))
        block = buf[offset:offset+count_bytes]
        endian = capstone.CS_MODE_BIG_ENDIAN if fmt.endswith("-BE") else capstone.CS_MODE_LITTLE_ENDIAN
        if machine in ("0x14c", "0x3", "0x8664", "0x3e"):
            arch = capstone.CS_ARCH_X86
            mode = capstone.CS_MODE_32 if machine in ("0x14c", "0x3") else capstone.CS_MODE_64
        elif machine == "0x8":
            arch,mode = capstone.CS_ARCH_MIPS, capstone.CS_MODE_MIPS32 | endian
        elif machine == "0x28":
            arch,mode = capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM | endian
        else:
            arch,mode = capstone.CS_ARCH_ARM64, endian
        engine = capstone.Cs(arch, mode)
        # For PE, instruction virtual addresses include the module image base.
        base = int(metadata["image_base"],16) if is_pe else 0
        insns = []
        for ins in engine.disasm(block, base+address):
            insns.append({"address": hex(ins.address), "bytes": ins.bytes.hex(),
                          "mnemonic": ins.mnemonic, "operands": ins.op_str})
            if len(insns) == limit:
                break
        return {"status": "LINEAR_UNVERIFIED", "start": hex(address),
                "address_kind": "PE_RVA" if is_pe else "ELF_VA",
                "backend": "capstone", "section": sec["name"],
                "instruction_count": len(insns), "max_instructions": limit,
                "bytes_covered": sum(len(bytes.fromhex(x["bytes"])) for x in insns),
                "instructions": insns,
                "warning": "Linear decode anchored at chosen file offset. No CFG, instruction reachability, decrypted-state or runtime execution claim."}
    return {"status": "OUT_OF_EXECUTABLE_RANGE",
            "reason": "Address must lie within a raw-backed executable section"}


def analyze(buf: bytes, limit: int=24, string_query: str = "", disasm_at: int | None = None, max_instructions: int = 24) -> dict:
    if len(buf)>128*1024*1024: raise FormatError("file exceeds 128MB safe triage budget")
    result={"size_bytes":len(buf),"sha256":hashlib.sha256(buf).hexdigest(),
            "read_only":True,"executed_target":False}
    if buf.startswith(b"MZ"):
        result.update(inspect_pe(buf,limit))
    elif buf.startswith(b"\x7fELF"):
        result.update(inspect_elf(buf,limit))
    else:
        raise FormatError("unknown native format; bounded triage only")
    if result["format"] in ("PE32+","PE32"):
        result["data_strings"]=ascii_inventory(buf,result["sections"],limit,string_query)
    result["tool_readiness"]=tool_readiness()
    result["decoder_preflight"]=decoder_preflight(result["tool_readiness"])
    result["deep_disassembly_status"]=result["decoder_preflight"]["status"]
    result["disassembly_note"]="No disassembly or full function semantics claimed by this metadata tool"
    if disasm_at is not None:
        result["bounded_disassembly"] = bounded_disassembly(buf,result,disasm_at,max_instructions)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("input",help="Native file or explicit .b64 snapshot, not executed")
    p.add_argument("--max-items",type=int,default=24)
    p.add_argument("--string-query",default="",help="Literal case-insensitive substring in bounded data strings")
    p.add_argument("--disasm-at",type=lambda x:int(x,0),default=None,help="Optional PE RVA / ELF VA, e.g. 0x1410; requires an explicitly available decoder")
    p.add_argument("--max-instructions",type=int,default=24,help="Bounded linear decode count 1..128")
    a=p.parse_args()
    if not (1<=a.max_items<=128):p.error("--max-items must be 1..128")
    if not (1<=a.max_instructions<=128):p.error("--max-instructions must be 1..128")
    f=Path(a.input)
    try:
        if f.stat().st_size>180*1024*1024: raise FormatError("input exceeds encoded size budget")
        raw=f.read_bytes()
        # GitHub/API base64 often contains folded lines. Remove ONLY ASCII whitespace;
        # keep strict alphabet/padding validation so malformed inputs fail closed.
        buf=base64.b64decode(raw.translate(None,b" \t\r\n"),validate=True) if f.suffix.lower()==".b64" else raw
        print(json.dumps(analyze(buf,a.max_items,a.string_query,a.disasm_at,a.max_instructions),ensure_ascii=False,indent=2))
    except (FormatError, ValueError, OSError) as e:
        print(json.dumps({"status":"unsupported","reason":str(e)}),file=sys.stderr)
        sys.exit(2)


if __name__=="__main__":
    main()
