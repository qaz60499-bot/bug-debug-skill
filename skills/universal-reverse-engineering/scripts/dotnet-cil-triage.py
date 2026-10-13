#!/usr/bin/env python3
"""Read-only bounded CLR MethodDef and CIL evidence; no runtime or .NET SDK.

Uses existing PE header/CLR validation, bounded metadata tables and method bodies.
Unknown IL instructions are explicit Unknown, not guessed decompilation/CFG.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("native_triage_for_cil", Path(__file__).with_name("native-triage.py"))
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


class CILError(ValueError):
    pass


def read(buf, fmt, at):
    size = struct.calcsize(fmt)
    if at < 0 or at > len(buf) - size:
        raise CILError("truncated CLR field")
    values = struct.unpack_from(fmt, buf, at)
    return values[0] if len(values) == 1 else values


def method_inventory(buf, limit=24):
    if len(buf) > 128 * 1024 * 1024 or not 1 <= limit <= 128:
        raise CILError("invalid CLR analysis budget")
    if not buf.startswith(b"MZ"):
        raise CILError("requires PE/CLR binary")
    pe = native.inspect_pe(buf, 2)
    if not pe["managed_cli"]:
        raise CILError("binary has no valid CLR CLI directory")

    def rva_pos(rva, length=1):
        if rva <= 0 or length < 1:
            raise CILError("invalid RVA")
        for sec in pe["sections"]:
            if sec["raw_size"] and sec["rva"] <= rva and length <= sec["raw_size"] and rva-sec["rva"] <= sec["raw_size"]-length:
                off = sec["offset"] + rva-sec["rva"]
                if off + length <= len(buf):
                    return off
        raise CILError("CLR RVA has no file-backed PE section")

    md_rva = int(pe["clr_metadata"]["metadata_rva"], 16)
    md_len = pe["clr_metadata"]["metadata_size"]
    if not 24 <= md_len <= 16 * 1024 * 1024:
        raise CILError("invalid CLR metadata size")
    md = rva_pos(md_rva, md_len)
    if buf[md:md+4] != b"BSJB":
        raise CILError("CLR metadata magic mismatch")
    version_len = read(buf, "<I", md+12)
    if version_len > 512:
        raise CILError("invalid CLR runtime version length")
    end_metadata = md + md_len
    version = buf[md+16:md+16+version_len].rstrip(b"\0").decode("ascii","replace")
    current = md + 16 + (version_len+3)//4*4
    _, stream_count = read(buf, "<HH", current)
    if not 1 <= stream_count <= 24:
        raise CILError("invalid metadata stream count")
    current += 4
    streams = {}
    for _ in range(stream_count):
        relative, size = read(buf, "<II", current)
        current += 8
        terminator = buf.find(b"\0", current, min(end_metadata,current+96))
        if terminator < 0:
            raise CILError("unterminated metadata stream name")
        name = buf[current:terminator].decode("ascii", "replace")
        current += (terminator-current+1+3)//4*4
        if relative > md_len or size > md_len-relative:
            raise CILError("metadata stream outside CLR root")
        streams[name] = (md+relative, size)
    if "#Strings" not in streams:
        raise CILError("CLR #Strings stream absent")
    table_address, table_size = streams.get("#~", streams.get("#-", (None,0)))
    if table_address is None or table_size < 24:
        raise CILError("unsupported metadata table stream")
    strings_start, strings_length = streams["#Strings"]
    def literal(index):
        if index == 0: return ""
        if index >= strings_length:raise CILError("string heap index outside stream")
        end = buf.find(b"\0", strings_start+index, strings_start+strings_length)
        if end < 0:raise CILError("unterminated metadata string")
        return buf[strings_start+index:end].decode("utf-8","replace")[:256]
    heap_flags = read(buf, "<B", table_address+6)
    valid = read(buf, "<Q", table_address+8)
    counts = {}
    off = table_address+24
    for i in range(64):
        if valid & (1<<i):
            counts[i] = read(buf,"<I",off)
            off += 4
    if sum(counts.values()) > 1_000_000 or counts.get(6,0)>150000:
        raise CILError("excessive CLR metadata rows")
    szstr = 4 if heap_flags&1 else 2
    szguid = 4 if heap_flags&2 else 2
    szblob = 4 if heap_flags&4 else 2
    def tblidx(t):
        return 4 if counts.get(t,0)>=65536 else 2
    def coded(tables,bits):
        return 4 if max((counts.get(t,0) for t in tables),default=0)>=1<<(16-bits) else 2
    typeref = coded((1,2,27),2)
    rowsize = {
        0:2+szstr+3*szguid,
        1:coded((0,26,35,1),2)+2*szstr,
        2:4+2*szstr+typeref+tblidx(4)+tblidx(6),
        3:tblidx(4),
        4:2+szstr+szblob,
        5:tblidx(6),
        6:8+szstr+szblob+tblidx(8),
    }
    pos = {}
    for t in range(7):
        if t not in counts:continue
        pos[t] = off
        advance = counts[t]*rowsize[t]
        if advance > table_address + table_size - off:
            raise CILError("truncated CLR MethodDef metadata")
        off += advance
    type_rows = []
    for i in range(counts.get(2,0)):
        p=pos[2]+i*rowsize[2]+4
        n=read(buf, "<I" if szstr==4 else "<H",p);p+=szstr
        namespace=read(buf, "<I" if szstr==4 else "<H",p);p+=szstr
        p+=typeref+tblidx(4)
        first=read(buf, "<I" if tblidx(6)==4 else "<H",p)
        type_rows.append((first, ".".join(x for x in (literal(namespace),literal(n)) if x)))
    methods = []
    for i in range(counts.get(6,0)):
        at=pos[6]+i*rowsize[6]
        rva,impl,flags=read(buf,"<IHH",at)
        p=at+8
        n=read(buf, "<I" if szstr==4 else "<H",p)
        name=literal(n)
        owner=next((v for first,v in reversed(type_rows) if first<=i+1),"<unknown>")
        item={"token":f"0x{0x06000000+i+1:08x}","class":owner,"name":name,"rva":hex(rva),
              "impl_flags":hex(impl),"flags":hex(flags)}
        if rva:
            a = rva_pos(rva)
            firstbyte=read(buf,"<B",a)
            if firstbyte&3 == 2:
                header,code_bytes = 1,firstbyte>>2
                extra=False
            elif firstbyte&3==3:
                flags_word=read(buf,"<H",a)
                header=(flags_word>>12)*4
                code_bytes=read(buf,"<I",a+4)
                extra=bool(flags_word&0x8)
                if not 12<=header<=64:raise CILError("invalid CLR fat method header")
            else:
                raise CILError("unrecognized CIL method header")
            if code_bytes > 1_048_576:
                raise CILError("oversized IL method")
            rva_pos(rva, header+code_bytes)
            il=buf[a+header:a+header+code_bytes]
            item.update({"il_length":code_bytes,"il_sha256":hashlib.sha256(il).hexdigest(),
                         "has_extra_sections":extra})
            item["_il"] = il
        methods.append(item)
    return {"artifact_sha256":hashlib.sha256(buf).hexdigest(),"metadata_version":version,
            "method_count":len(methods),"managed_cli":True,"methods":methods}


OPS = {
    0x00:("nop",""),0x01:("break",""),0x02:("ldarg.0",""),0x03:("ldarg.1",""),
    0x04:("ldarg.2",""),0x05:("ldarg.3",""),0x06:("ldloc.0",""),
    0x07:("ldloc.1",""),0x08:("ldloc.2",""),0x09:("ldloc.3",""),
    0x0a:("stloc.0",""),0x0b:("stloc.1",""),0x0c:("stloc.2",""),0x0d:("stloc.3",""),
    0x0e:("ldarg.s","u1"),0x0f:("ldarga.s","u1"),0x10:("starg.s","u1"),
    0x11:("ldloc.s","u1"),0x12:("ldloca.s","u1"),0x13:("stloc.s","u1"),
    0x14:("ldnull",""),0x15:("ldc.i4.m1",""),0x16:("ldc.i4.0",""),
    0x17:("ldc.i4.1",""),0x18:("ldc.i4.2",""),0x19:("ldc.i4.3",""),
    0x1a:("ldc.i4.4",""),0x1b:("ldc.i4.5",""),0x1c:("ldc.i4.6",""),
    0x1d:("ldc.i4.7",""),0x1e:("ldc.i4.8",""),0x1f:("ldc.i4.s","i1"),
    0x20:("ldc.i4","i4"),0x21:("ldc.i8","i8"),0x22:("ldc.r4","r4"),
    0x23:("ldc.r8","r8"),0x25:("dup",""),0x26:("pop",""),0x27:("jmp","tok"),
    0x28:("call","tok"),0x29:("calli","tok"),0x2a:("ret",""),
    0x45:("switch","switch"),0x58:("add",""),0x59:("sub",""),0x5a:("mul",""),
    0x5b:("div",""),0x5c:("div.un",""),0x5d:("rem",""),0x5e:("rem.un",""),
    0x5f:("and",""),0x60:("or",""),0x61:("xor",""),
    0x62:("shl",""),0x63:("shr",""),0x64:("shr.un",""),
    0x65:("neg",""),0x66:("not",""),0x67:("conv.i1",""),0x68:("conv.i2",""),
    0x69:("conv.i4",""),0x6a:("conv.i8",""),0x6f:("callvirt","tok"),
    0x72:("ldstr","tok"),0x73:("newobj","tok"),0x74:("castclass","tok"),
    0x75:("isinst","tok"),0x7a:("throw",""),0x7b:("ldfld","tok"),
    0x7d:("stfld","tok"),0x7e:("ldsfld","tok"),0x80:("stsfld","tok"),
    0x8c:("box","tok"),0x8d:("newarr","tok"),0x8e:("ldlen",""),
    0x8f:("ldelema","tok"),0x90:("ldelem.i1",""),0xdc:("endfinally",""),
    0xdd:("leave","br4"),0xde:("leave.s","br1")
}
for i,name in enumerate(("br.s","brfalse.s","brtrue.s","beq.s","bge.s","bgt.s",
                         "ble.s","blt.s","bne.un.s","bge.un.s","bgt.un.s","ble.un.s","blt.un.s")):
    OPS[0x2b+i] = (name,"br1")
for i,name in enumerate(("br","brfalse","brtrue","beq","bge","bgt",
                         "ble","blt","bne.un","bge.un","bgt.un","ble.un","blt.un")):
    OPS[0x38+i] = (name,"br4")
EXT = {
    0x00:("arglist",""),0x01:("ceq",""),0x02:("cgt",""),0x03:("cgt.un",""),
    0x04:("clt",""),0x05:("clt.un",""),0x06:("ldftn","tok"),
    0x09:("ldarg","u2"),0x0a:("ldarga","u2"),0x0b:("starg","u2"),
    0x0c:("ldloc","u2"),0x0d:("ldloca","u2"),0x0e:("stloc","u2"),
    0x11:("endfilter",""),0x15:("initobj","tok"),0x1a:("rethrow","")
}


def decode_il(il: bytes, max_ins=256):
    if not 1<=max_ins<=1024 or len(il)>1_048_576:
        raise CILError("invalid IL decode budget")
    instructions=[]
    p=0
    unsupported=None
    while p<len(il):
        if len(instructions)>=max_ins:
            break
        at=p
        opcode=il[p];p+=1
        if opcode==0xfe:
            if p>=len(il):
                unsupported={"offset":at,"reason":"truncated extended CIL opcode"}
                break
            op=EXT.get(il[p]);p+=1
        else:op=OPS.get(opcode)
        if op is None:
            unsupported={"offset":at,"reason":f"unsupported opcode 0x{opcode:x}"}
            break
        name,kind=op
        rec={"offset":at,"opcode":name}
        formats={"i1":"<b","u1":"<B","u2":"<H","i4":"<i",
                 "i8":"<q","br1":"<b","br4":"<i","tok":"<I",
                 "r4":"<f","r8":"<d"}
        if kind in formats:
            width=struct.calcsize(formats[kind])
            if p+width>len(il):
                unsupported={"offset":at,"reason":"truncated IL instruction"}
                break
            value=struct.unpack_from(formats[kind],il,p)[0]
            p+=width
            if kind.startswith("br"):
                rec["target"]=p+value
            elif kind=="tok":
                rec["token"]=hex(value)
            else:
                rec["value"]=value
        elif kind=="switch":
            if p+4>len(il):
                unsupported={"offset":at,"reason":"truncated IL switch"}
                break
            n=struct.unpack_from("<I",il,p)[0];p+=4
            if n>256 or p+n*4>len(il):
                unsupported={"offset":at,"reason":"invalid IL switch limits"}
                break
            rel=struct.unpack_from("<"+str(n)+"i",il,p);p+=n*4
            rec["targets"]=[p+v for v in rel]
        instructions.append(rec)
    boundary={e["offset"] for e in instructions}
    targets=[v for i in instructions for v in ([i["target"]] if "target" in i else i.get("targets",[]))]
    # End-of-method is not an instruction target. If the instruction budget
    # stopped decoding early, destinations in the undecoded suffix are UNKNOWN,
    # not falsely invalid.
    invalid=[v for v in targets if v<0 or v>=len(il) or (v<p and v not in boundary)]
    if invalid and unsupported is None and p==len(il):
        unsupported={"offset":invalid[0],"reason":"IL branch target not an instruction boundary"}
    return {"status":"PARTIAL_UNSUPPORTED" if unsupported or p<len(il) else "DECODED_STATIC",
            "il_bytes":len(il),"instruction_count":len(instructions),
            "instructions":instructions,"instructions_truncated":p<len(il) and unsupported is None,
            "unknown":unsupported,"branch_target_validation":"FAILED" if invalid else ("PARTIAL" if p<len(il) else "PASSED")}


def inspect(buf, method_name=None, max_methods=8, max_instructions=128):
    if not 1<=max_methods<=64 or not 1<=max_instructions<=1024:
        raise CILError("invalid analysis budget")
    r=method_inventory(buf)
    matches=[m for m in r["methods"] if "_il" in m and
             (method_name is None or m["name"]==method_name or m["class"]+"."+m["name"]==method_name)]
    if not matches:
        return {"artifact_sha256":r["artifact_sha256"],"managed_cli":True,
                "metadata_version":r["metadata_version"],"method_count":r["method_count"],
                "status":"METHOD_NOT_FOUND","methods":[],"executed_target":False}
    records=[]
    for m in matches[:max_methods]:
        decoded=decode_il(m["_il"],max_instructions)
        for ins in decoded["instructions"]:
            if "token" in ins and ins["opcode"] in ("call","callvirt","newobj","ldftn"):
                value=int(ins["token"],16)
                if value>>24==6 and 1<=value&0xffffff<=len(r["methods"]):
                    target=r["methods"][(value&0xffffff)-1]
                    ins["target_method"]=target["class"]+"."+target["name"]
        records.append({k:v for k,v in m.items() if k!="_il"} | {"il":decoded})
    return {"artifact_sha256":r["artifact_sha256"],"managed_cli":True,
            "metadata_version":r["metadata_version"],"method_count":r["method_count"],
            "status":"STATIC_IL_PARTIAL" if any(m["il"]["status"]!="DECODED_STATIC" for m in records) else "STATIC_IL_DECODED",
            "methods":records,"methods_truncated":len(matches)>len(records),
            "executed_target":False,"source_caveat":"CIL instructions and MethodDef tokens from original PE bytes only; no decompilation, runtime reflection resolution, state machine proof or obfuscation removal."}


def render_json(value):
    # Obfuscated metadata can contain Unicode not representable by Windows cp936/GBK.
    # ASCII-escaped JSON is lossless and keeps stdout valid on any locale.
    return json.dumps(value, ensure_ascii=True, indent=2)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("input")
    p.add_argument("--method",default=None,help="Exact method name or Type.Method; no code execution")
    p.add_argument("--max-methods",type=int,default=4)
    p.add_argument("--max-instructions",type=int,default=128)
    a=p.parse_args()
    try:
        if not 1<=a.max_methods<=64 or not 1<=a.max_instructions<=1024:
            raise CILError("invalid analysis budget")
        f=Path(a.input)
        if f.stat().st_size > 180*1024*1024:
            raise CILError("input too large")
        raw=f.read_bytes()
        buf=base64.b64decode(raw.translate(None,b" \t\r\n"),validate=True) if f.suffix.lower()==".b64" else raw
        print(render_json(inspect(buf,a.method,a.max_methods,a.max_instructions)))
    except (CILError,native.FormatError,ValueError,OSError) as ex:
        print(json.dumps({"status":"REJECTED","reason":str(ex)}),file=sys.stderr)
        return 2
    return 0


if __name__=="__main__":
    sys.exit(main())
