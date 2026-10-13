#!/usr/bin/env python3
"""Bounded offline WASM, ASAR and APK metadata. No target execution or installation."""
from __future__ import annotations
import argparse
import base64
import hashlib
import io
import json
import struct
import sys
import zipfile
from pathlib import Path

MAX_INPUT = 128 * 1024 * 1024
MAX_ITEMS = 128


class TriageError(ValueError):
    pass


def need(blob: bytes, off: int, size: int):
    if off < 0 or size < 0 or size > len(blob) - off:
        raise TriageError("truncated or out-of-range field")


def uleb(blob: bytes, off: int):
    val = 0
    for i in range(5):
        need(blob, off, 1)
        b = blob[off]
        off += 1
        if i == 4 and b > 0x0f:
            raise TriageError("WASM u32 LEB overflow")
        val |= (b & 127) << (7*i)
        if b < 128:
            return val, off
    raise TriageError("overlong WASM LEB")


def name(blob: bytes, off: int):
    length, off = uleb(blob, off)
    need(blob, off, length)
    if length > 4096:
        raise TriageError("oversized WASM name")
    return blob[off:off+length].decode("utf-8"), off+length


def wasm(blob: bytes, limit: int):
    if blob[:8] != b"\x00asm\x01\x00\x00\x00":
        raise TriageError("unsupported WASM magic or version")
    pos = 8
    sections = []
    imported = []
    exported = []
    function_count = None
    bodies = None
    seen_standard_sections = set()
    while pos < len(blob):
        if len(sections) >= 128:
            raise TriageError("excessive WASM section count")
        secid = blob[pos]
        pos += 1
        if secid != 0:
            if secid in seen_standard_sections:
                raise TriageError("duplicate WASM section id")
            seen_standard_sections.add(secid)
        length, pos = uleb(blob, pos)
        need(blob, pos, length)
        end = pos+length
        p = pos
        part = {"id": secid, "size": length}
        if secid == 0:
            part["name"], p = name(blob, p)
        if secid == 2:
            count,p = uleb(blob,p)
            if count>20000:
                raise TriageError("excessive WASM import count")
            for _ in range(count):
                module,p = name(blob,p)
                symbol,p = name(blob,p)
                need(blob,p,1)
                kind=blob[p];p+=1
                if len(imported)<limit:
                    imported.append({"module":module,"name":symbol,"kind":kind})
                if kind==0:
                    _,p = uleb(blob,p)
                elif kind in (1,2):
                    if kind==1:
                        need(blob,p,1);p+=1  # element type
                    flags,p=uleb(blob,p)
                    _,p=uleb(blob,p)
                    if flags&1:
                        _,p=uleb(blob,p)
                elif kind==3:
                    need(blob,p,2);p+=2  # value type, mutability
                elif kind==4:
                    _,p=uleb(blob,p)  # attribute
                    _,p=uleb(blob,p)  # tag type index
                else:
                    raise TriageError("unsupported WASM import type")
                if p>end:
                    raise TriageError("WASM import exceeds section")
            part["count"]=count
        if secid==3:
            function_count,p=uleb(blob,p)
            part["count"]=function_count
        if secid==7:
            count,p=uleb(blob,p)
            if count>20000:
                raise TriageError("excessive WASM export count")
            for _ in range(count):
                label,p=name(blob,p)
                need(blob,p,1);kind=blob[p];p+=1
                index,p=uleb(blob,p)
                if len(exported)<limit:
                    exported.append({"name":label,"kind":kind,"index":index})
                if p>end:
                    raise TriageError("WASM export exceeds section")
            part["count"]=count
        if secid==10:
            count,p=uleb(blob,p)
            if count>100000:
                raise TriageError("excessive WASM code bodies")
            body_max=0
            for _ in range(count):
                n,p=uleb(blob,p)
                if n>end-p:
                    raise TriageError("WASM body outside code section")
                body_max=max(body_max,n)
                p+=n
            if p!=end:
                raise TriageError("WASM body extent mismatch")
            bodies={"count":count,"largest_bytes":body_max}
            part.update(bodies)
        sections.append(part)
        pos=end
    if function_count is not None and (bodies is None or bodies["count"] != function_count):
        if function_count or bodies is not None:
            raise TriageError("WASM function and code counts disagree")
    if bodies is not None and function_count is None and bodies["count"]:
        raise TriageError("WASM code bodies without function declarations")
    return {"format":"WASM","section_count":len(sections),"sections":sections[:limit],
            "validation_scope":"bounded-section-structure-only; not full WebAssembly module validation",
            "imports":imported,"exports":exported,"code_bodies":bodies,
            "caveat":"WASM binary sections and exports do not prove obfuscated computation, runtime paths, or algorithm semantics"}


def asar(blob: bytes, limit: int):
    need(blob, 0, 16)
    prefix,outer,payload,actual=struct.unpack_from("<IIII",blob,0)
    if prefix!=4 or outer!=payload+4 or actual>payload or 8+outer>len(blob) or actual>8*1024*1024:
        raise TriageError("invalid ASAR Pickle header")
    try:
        tree=json.loads(blob[16:16+actual])
    except (UnicodeError,ValueError) as e:
        raise TriageError("invalid ASAR JSON header") from e
    start=8+outer
    found=[]
    total=0
    bad=[]
    def walk(obj,prefix="",depth=0):
        nonlocal total
        if depth>30:
            raise TriageError("ASAR nesting too deep")
        files=obj.get("files")
        if not isinstance(files,dict):
            raise TriageError("invalid ASAR directory node")
        for segment,entry in files.items():
            if not isinstance(segment,str) or not segment or segment in (".","..") or "/" in segment or "\\" in segment:
                raise TriageError("unsafe ASAR path")
            if not isinstance(entry,dict):
                raise TriageError("invalid ASAR file node")
            total+=1
            if total>20000:
                raise TriageError("excessive ASAR entries")
            path=prefix+"/"+segment
            if "files" in entry:
                walk(entry,path,depth+1)
            elif "link" in entry:
                if len(found)<limit:found.append({"path":path,"kind":"symlink","link":entry["link"]})
            else:
                size=entry.get("size",0)
                if type(size)!=int or size<0:
                    raise TriageError("invalid ASAR file size")
                unpacked=entry.get("unpacked") is True
                if not unpacked:
                    text=entry.get("offset","0")
                    if not isinstance(text,str) or not text.isdecimal():
                        raise TriageError("invalid ASAR offset")
                    off=int(text)
                    if off>len(blob)-start or size>len(blob)-start-off:
                        bad.append(path)
                if len(found)<limit:found.append({"path":path,"size":size,"unpacked":unpacked})
    walk(tree)
    if bad:
        raise TriageError("ASAR file extent out of bounds: "+", ".join(bad[:3]))
    return {"format":"ASAR","header_bytes":outer,"data_start":start,
            "entries_count":total,"entries":found,"truncated":total>len(found),
            "caveat":"Archive listing is not renderer/preload/IPC call-flow evidence; unpacked payloads are external"}


def apk(blob: bytes, limit: int):
    try:
        z=zipfile.ZipFile(io.BytesIO(blob))
        entries=z.infolist()
        if len(entries)>30000 or sum(e.file_size for e in entries)>1024*1024*1024:
            raise TriageError("unbounded APK member inventory")
        filenames={e.filename for e in entries}
        if "AndroidManifest.xml" not in filenames or not any(p.endswith(".dex") for p in filenames):
            raise TriageError("ZIP is not an APK with manifest and DEX")
        dex=[];libs=[]
        for e in entries:
            if e.filename.endswith(".dex") and len(dex)<limit:
                with z.open(e) as f:
                    header=f.read(112)
                if len(header)<112 or not header.startswith(b"dex\n"):
                    raise TriageError("invalid DEX header")
                dex.append({"path":e.filename,"size":e.file_size,
                            "version":header[4:7].decode("ascii","replace"),
                            "methods":struct.unpack_from("<I",header,88)[0],
                            "classes":struct.unpack_from("<I",header,96)[0]})
            elif e.filename.startswith("lib/") and e.filename.endswith(".so") and len(libs)<limit:
                with z.open(e) as f:
                    header=f.read(20)
                if len(header)<20 or not header.startswith(b"\x7fELF"):
                    raise TriageError("invalid ELF member")
                libs.append({"path":e.filename,"size":e.file_size,
                             "elf_class":header[4],"machine":hex(struct.unpack_from("<H",header,18)[0])})
        return {"format":"APK","archive_entries":len(entries),"dex":dex,
                "native_libraries":libs,"truncated":len(dex)>=limit or len(libs)>=limit,
                "caveat":"APK header/DEX/native inventory cannot establish JNI behavior; verify DEX native declarations and ELF dynsym independently"}
    except (zipfile.BadZipFile,RuntimeError,EOFError) as e:
        raise TriageError("invalid or corrupt APK ZIP") from e


def analyze(blob: bytes, limit: int=16):
    if len(blob)>MAX_INPUT:
        raise TriageError("file exceeds 128 MiB triage cap")
    if not 1<=limit<=MAX_ITEMS:
        raise TriageError("max-items must be 1..128")
    out={"size_bytes":len(blob),"sha256":hashlib.sha256(blob).hexdigest(),
         "read_only":True,"executed_target":False}
    if blob[:8]==b"\x00asm\x01\x00\x00\x00":
        out.update(wasm(blob,limit))
    elif blob[:4]==b"PK\x03\x04":
        out.update(apk(blob,limit))
    else:
        out.update(asar(blob,limit))
    return out


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("file")
    p.add_argument("--max-items",type=int,default=16)
    args=p.parse_args()
    target=Path(args.file)
    try:
        if target.stat().st_size>180*1024*1024:
            raise TriageError("encoded input exceeds 180 MiB cap")
        raw=target.read_bytes()
        if target.suffix.lower()==".b64":
            raw=base64.b64decode(raw.translate(None,b" \t\r\n"),validate=True)
        print(json.dumps(analyze(raw,args.max_items),indent=2,ensure_ascii=False))
    except (OSError,ValueError,UnicodeError) as e:
        print(json.dumps({"status":"unsupported","reason":str(e)}),file=sys.stderr)
        sys.exit(2)

if __name__=="__main__":main()
