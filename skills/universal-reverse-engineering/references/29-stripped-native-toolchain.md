# 29 — Native Binary Triage Fallback for Stripped PE/ELF

## Scope

A read-only, standard-library native **triage and evidence indexing** adapter for environments where Ghidra/IDA/llvm-objdump/radare2/Capstone are not readily available. Current metadata supports PE32/PE32+ and **ELF32/ELF64 little- and big-endian**, including bounded ELF `.dynsym` exports useful for Android JNI; sectionless ELF records bounded PT_LOAD segments rather than claiming missing symbols do not exist. Other unsupported formats remain explicit. This is NOT a replacement for disassembly, decompilation, symbolic execution, or instrumented behavior verification. It does not execute unknown binaries, download tools, install dependencies, alter global environments or start ports.

Use after verified artifact fingerprint, when the task involves native PE/ELF and real tool preflight has failed, or for cheap first-pass evidence before deeper authorized analysis.

## Available native CLI

```text
python scripts/native-triage.py <native-file-or-explicit-b64> --max-items 24
python scripts/native-triage.py <sample.b64> --string-query dll --max-items 8
# Only for verified ELF32 MIPS indirect-GOT questions; always opt-in, standard library only:
python scripts/native-call-targets.py <sample-mips-elf-or-b64> --max-items 16 --max-scan-bytes 8388608
# For one already identified MIPS32 jalr callsite (avoid dumping broad results):
python scripts/native-call-targets.py <sample> --callsite 0x4054d8 --max-items 1
# Only after verified decoder readiness and exact user-scoped address:
python scripts/native-triage.py <sample> --disasm-at 0x1410 --max-instructions 12
# If the lightweight Agent copy has no decoder, opt in to an existing scoped package:
# RE_CAPSTONE_ROOT=<existing-trusted-capstone-package-root> python scripts/native-triage.py <sample> --disasm-at 0x1410
```

The `.b64` form is only for an externally acquired, provenance-fixed test fixture. Standard ASCII space/tab/CR/LF in line-wrapped GitHub API Base64 are stripped before **strict** alphabet and padding validation; other invalid characters still fail closed. Decode in memory; original file and analysis output remain separate. If an unknown file starts with `MZ` or ELF magic but is corrupt, fail closed with an explicit error. Upper file-size bound: 128 MiB decoded (180 MiB supplied); returned arrays capped. The CLI writes only JSON to stdout or a structured unsupported error to stderr.

## Evidence capabilities

- SHA256, byte size, format, machine, PE entrypoint/sections/entropy/imports, ELF32/ELF64 section summaries and bounded dynamic symbol names (`Java_...` / `JNI_OnLoad` first, not a full Java/Native call graph).
- PE x64 exception-directory (unwind .pdata) function ranges: recovered function **boundaries**, not semantic function names.
- Candidate `FF 15 disp32` RIP-relative IAT call byte sequences and their likely containing unwind range. *No verified instruction boundaries*: false positives possible, no executable call graph claimed.
- Non-executable PE data ASCII-string inventory with source offset/RVA, section, count and truncation indicator; string appearance does not prove a particular key or algorithm is used.
- Optional `--disasm-at` uses a **PE RVA or ELF virtual address**, only an existing, tested Capstone backend, an executable raw-backed section and a strict 1–128 instruction budget. Machine/header-gated mappings include **x86/x64 PE/ELF, ELF32 MIPS32 LE/BE, ELF32 ARM (ARM mode), ELF64 AArch64**; ARM Thumb and unrecognized machines remain unverified. Decoded results are always `LINEAR_UNVERIFIED` (not a reachable CFG, decryption proof, or decompiler); actual imported call targets and branches still need separate original-byte/evidence validation. No new tool or service starts, and metadata-only remains the default.
- Backend detection reports PATH/module presence separately from a real decoder smoke test. When Capstone is present, a trusted `push/mov/ret` sequence must decode with correct x64 instruction addresses; false or broken modules fail closed. Finding an objdump/radare2/Ghidra command alone now produces `DETECTED_UNVERIFIED`, **not** an assertion that analysis succeeded.
- `deep_disassembly_status` values: `UNAVAILABLE`, `DETECTED_UNVERIFIED`, `BROKEN`, or `SMOKE_PASS_TARGET_UNVERIFIED`. Even the last means only a known-byte smoke test passed; a target-specific decoded instruction and independent behavioral evidence remain mandatory.

## MIPS32 GP/GOT/PLT bounded call-target recovery (optional)

When a concrete target is an **ET_EXEC ELF32 MIPS** using standard GP-relative GOT and lazy PLT stubs, `scripts/native-call-targets.py` reads only ELF/PT_LOAD/PT_DYNAMIC/PT_MIPS_REGINFO, bounded dynsym and GOT entries, and validates strict instruction fields (`lw t9,offset(gp)` → `jalr t9` → GOT pointer → four-instruction stub → dynsym index/name). The native tool supports **both little and big endian** and **sectionless** binaries without requiring Capstone, Java or a running Ghidra. It is an **on-demand evidence adapter**, not a second Skill or generic cross-platform CFG engine.

The output includes SHA256, `status`, `resolved_import_calls`, `unknown_jalr`, `focus_callsite`, `calls_truncated`, `scan_truncated`, source addresses, GP source and recorded assumptions. `--callsite` limits reported edges to one exact aligned MIPS virtual address (a chosen local question), although the bounded ELF/program metadata are still scanned. Candidates are **static mapping in the file only**: PIC GP may be changed per function; GOT can be relocated or patched at runtime; bytes in an executable segment are not automatically reachable instructions. PLT internal resolver calls are excluded from application call-site counts. Without confirmed dataflow or an independent runtime oracle, never claim a complete call graph, reachability or function semantics. PIE/ET_DYN, MIPS64, other ABI conventions and nonmatching stubs are unsupported or unverified; return Unknown, not a guessed target. For unknown MIPS targets, prefer verified Ghidra/angr backend if available; no auto-install. Test with `python -m unittest discover -s scripts -p test_native_call_targets.py -v` (portable synthetic positive/negative fixtures; research-only real firmware fixtures run only when present).

## Routing integration

Existing `static-map`, `symbol-recovery`, `structure-recovery` and optional `data-flow` remain the capability entry points. **Do not create a new unconditional Router**. If the CLI produces metadata but the unresolved question requires instruction-level branch, pointer or import-resolution proof:
1. record metadata as Observation;
2. preserve candidate IAT edges and ambiguous string roles as Inference;
3. report `deep_disassembly_status=UNAVAILABLE` and function behavior as Unknown when no supported backend is present;
4. request a confirmed existing Ghidra/IDA/radare2/objdump/Capstone backend for further local analysis, or stop. Do not treat `planCapabilities.status=planned` as proof of tool availability or execution success.
5. If a backend becomes available, request targeted disassembly at the proven RVA rather than loading the entire image and trusting pseudo-source.

## Confirmed scoped decoder test, distinct from triage

研究环境中已对真实 V3 x64 PE 的 TLS callback RVA 0x89030 使用隔离 Capstone wheel（PyPI 5.0.9，SHA256 `732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0`）成功解码，并对 TLS 的两段 XOR/ROL 字节转换进行离线复现及原字节逆变换测试。研究证据路径：`research/live-tests/20261009-v3-x64/independent-TLS-addendum.md`。

`scripts/native-triage.py` 现在优先使用当前 Python 已安装的 Capstone；若不可用，会发现 **Canonical 本目录下已经存在的** `research/toolchain/capstone-5.0.9`，或者按需使用明确指定的 `RE_CAPSTONE_ROOT`（仅允许已经存在且可验证的 package 目录，**不下载安装、也不更改全局 PATH**）。只有在实际通过已知指令 smoke test 时才把 decoder 标为可用。完整版 Agent 副本不自带研究 toolchain，所以 Agent 复制版如果没有 Python 已安装的 Capstone，必须由执行方明确提供已有作用域；未满足时仍返回 `UNAVAILABLE`，不可伪称深度分析已完成。独立测试通过不代表任意机器可用，移植时须重新验证。被保护的磁盘原始入口不能因线性解码返回语法正确指令就当成真实入口机制，先识别 TLS/解码状态。

## Authentic PE64 V3 — high-complexity static analysis (2026-10-09)

Sample: `knewstimek/crackme-agent-bench/v3/crackme_v3_x64.exe`, SHA-256 `d1bbaa14a1fd91340fac98aadec6203dc50364823914189bcb558688552a6eb8`, checked against upstream Git blob SHA1 `bd682e260d2065dd4888c9893560016a034aad5f`. Independent metadata report was saved before reading the repository README.

- 17 PE sections, .text entropy 7.988, .pack RVA 0x89000; 1,711 x64 unwind ranges.
- Real x64 disassembly of .pack RVA 0x8907d in an isolated analysis container verifies two VirtualProtect calls and rolling XOR/ROL7 loops; the code bytes were extracted from the exact upstream sample and were never run as a Windows executable.
- Function-level emulation on memory copies recovered 422,864 bytes of .text and 4,096 bytes of .data. Decrypted entry RVA 0x9d74 starts `sub rsp, 0x28; call 0xa5b8; add rsp, 0x28; jmp 0x9b68`, independently instruction-decoded by GNU objdump. Details: `research/live-tests/20261009-v3/`.
- This is **verified partial unpacking**, not whole-program/VM/flag recovery. Windows native disassembler/decompiler availability remains unverified; a bounded Linux container disassembled only extracted code windows.

## Complexity regression — synthetic PE benchmark

Source: https://github.com/agentrebench/AgentRE-Bench
Sample: `version3/binaries/windows_stripped/windows_level19_ReflectiveDLLInjection.exe`, 18,432 bytes, SHA256 `a215cf67d7f261706c47d5d7f86c98c7864f081e1f4bb47bb8e63c3071a91037`.

**Pre-ground-truth static-only result:** correct PE64 identity, imports, 54 unwind function ranges, 12 byte-pattern IAT candidates; could not prove the full reflective mapping, relocation, AES and anti-debug behavior. Reference answer opened only after recording this limitation, in `research/live-tests/20261009-pe19-stripped/pre-ground-truth.md`.

**Post-answer auxiliary check:** ASCII inventory finds `Rfl3ct!v3_DLL_k3DllMain` in .rdata; the embedded key prefix is directly observable but its cryptographic role is NOT independently established. This is not counted as a blind-reverse win.

### Acceptance boundaries

- Canonical real-fixture tests: `python -m unittest discover -s scripts -p test_native_triage.py -v`.
- Router: `node --test scripts/test-routing.mjs scripts/test-routing-hardening.mjs`.
- Not tested: PE live execution, debugger, stripped call-graph completeness, cryptographic operation verification, genuinely obfuscated function behavior. The absence of a disassembler backend is a real gap, never a successful deep reverse.

No change to the optional independent Architecture Review skill or other Agents' global runtime configuration.
