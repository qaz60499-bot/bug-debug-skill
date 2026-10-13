# Routing Regression Cases

These cases protect the routing SSoT. They are not exhaustive analysis tasks; they are acceptance checks for skill behavior.

## Verification-contract coverage anti-overclaim (2026-10-09)

- Every registered artifact platform has exactly one historical *case-specific* fixture evidence level. New routes cannot silently inherit another platform's validation claims.
- `status=planned` is a route outcome only; the same output explicitly reports `verification.backend=not_probed` and `verification.currentTarget=unverified`.
- Old first-layer PE successes cannot be generalized into complete VM/flag recovery; ASAR listing cannot prove Electron IPC; Android ELF symbol linkage cannot prove runtime JNI; WASM imports cannot prove algorithm semantics.
- Negative capability/readiness combinations must not promote a case's historic fixture level into end-to-end success. New sample acceptance requires independent ground truth, including conditions where tools are unavailable or report partial outputs.
- The coverage contract uses the existing Router registry; no extra stage, model call or second harness.

## Required positive cases

| Case | Input signal | Expected route / behavior |
|---|---|---|
| evidence-contract | Any non-trivial reverse finding | Must classify records as Observation / Inference / Unknown before Finding. |
| unknown-preserved | Decompiler output has ambiguous role | Must keep ambiguity as Unknown or low-confidence Inference. |
| artifact-first | Unknown binary/APK/IPA/folder | Must fingerprint before deep analysis. |
| symbol-recovery | Generated labels block navigation | Must recover names with evidence and confidence, not rename broadly by guess. |
| structure-recovery | Field offsets or object layout matter | Must separate observed offsets/accesses from inferred field roles. |
| function-level-emulation | Small self-contained transform/checksum/decoder | May emulate function only within recorded assumptions and scope. |
| unity-il2cpp-route | UnityPlayer/global-metadata.dat/IL2CPP evidence present | Must activate Unity/IL2CPP route and keep metadata/native/resources separate. |
| version-diff | Two builds of same target | Must fingerprint each build before comparing matched components. |
| android-framework-route | APK shows framework family/generator | Must identify framework and separate generated glue from app-owned logic. |
| routing-ssot | Router copy or Agent entry references this skill | Must point to canonical SSoT and avoid installing second runtime/router. |

## Required negative cases

| Case | Forbidden behavior |
|---|---|
| csharp-alone-unity | C# metadata alone must not imply Unity. |
| merged-build-evidence | Evidence from different builds must not be merged without separate fingerprints. |
| decompiler-only-confirmed | Pseudocode alone must not produce a confirmed finding. |
| framework-glue-owned | Framework-generated code must not be treated as app-owned logic without ownership evidence. |
| emulator-overclaim | Function-level emulation result must not claim whole-app behavior. |
| global-hook-first | APK/mobile tasks must not start with global Frida hooks before route/surface map. |
| tool-driven-route | Tool availability must not determine route. |

## PASS condition

A compliant Agent or lightweight router must:

1. route from evidence;
2. ask for or produce artifact fingerprint when missing;
3. load only relevant reference paths;
4. preserve Observation / Inference / Unknown separation;
5. avoid modifying Agent Runtime / ToolRouter while installing this skill.

## Capability-routing regression additions (2026-10-09)

The following are concrete machine tests in `scripts/test-routing.mjs`:

| Case | Expected behavior |
|---|---|
| semantic-needs-not-keywords | Given semantic capability IDs, select only those IDs and prerequisites, regardless of tool words in the goal. |
| platform-is-adapter | APK can select platform adapter while retaining protocol/data-flow analysis abilities. |
| depth-is-not-a-router | Shallow vs deep must not create separate independent Skill routes or auto-load extra modules. |
| dynamic-gate | Runtime hooks need a hypothesis and authorized target scope. |
| protected-unity-gate | Obfuscation and IL2CPP routes require verified signals. |
| version-fingerprint-gate | Two independent fingerprints before version diff. |
| architecture-independent | External architecture handoff is never auto-executed or required. |
| unknown-triage | Missing target/need triggers bounded triage, not all analyzers. |
| capability-dedup | Repeated needs do not repeat module selection. |
| unsupported-explicit | Missing module is reported, never forced into an unrelated module. |
| capability-integrity | Every registered reference and dependency exists. |

## Optional deep capability route cases (2026-10-09)

| Case | Expected result |
|---|---|
| Real identified multi-GB trace with focused question and traceArtifact | trace-reduction; indexed, bounded retrieval; do not dump full log |
| Vague phrase 'trace' with no artifact | needs_evidence, no trace-reduction |
| Observed JNI/IPC process crossing | data-flow + boundary-tracing, no automatic dynamic observation |
| Platform keywords alone without observed boundary | do not activate boundary-tracing |
| Two controlled independent input/output cases | differential-verification, not version-diff |
| Same comparison case repeated | needs_evidence; no differential-verification |
| Agent-generated Ghidra names re-read as proof | invalid circular corroboration; original/derived provenance remains separate |
| Tool returns overbroad trace matches | count/coverage/truncated and refine scope; no huge context output |
| Same tool failure signature repeated twice | revise hypothesis/backend or stop; no parameter churn |
| Source-only known-small-function query | no trace/boundary/diff extra modules; normal route |

## Stripped native PE toolchain feasibility and fallback (2026-10-09)

- Planner modules `static-map`, `symbol-recovery`, `structure-recovery` can be selected without an available native disassembler; they are a **plan**, not a successful execution.
- Portable native triage reports actual SHA/PE header, 54 x64 unwind ranges and 12 **candidate** IAT byte matches for the frozen 18,432-byte PE benchmark, capped output and no target execution.
- Missing actual decoder must report `deep_disassembly_status=UNAVAILABLE`; do not claim exact instruction control flow, AES proof or fully reconstructed loader from PE metadata.
- Synthetic malformed native file and excessive output-budget cases fail closed.
- Benchmark ground truth cannot be consulted until a separate pre-ground-truth observation/Unknown report is saved.

**Live Agent semantic evals still required**: natural-language task → Task Descriptor accuracy, false activation, missed capability, cross-language runtime handoff, abort/permission guards and evidence sufficiency. Deterministic tests cannot prove LLM interpretation quality.

## Empty-load / fault-injection hardening regression (2026-10-09)

Executable suite: `node --test scripts/test-routing.mjs scripts/test-routing-hardening.mjs`.

- Cold-load without target or semantic capabilities must be bounded to target-triage, not every module.
- Inputs with malformed `needs`, `artifact.kind`, or `verifiedSignals` must fail explicitly.
- Identical binary fingerprints must not satisfy independent-version diff evidence.
- Inherited JavaScript keys such as `toString`, `constructor` and `__proto__` must never become registered capabilities or artifact types.
- Invalid registry cycles must fail closed.
- Conditional modules lacking their gates must not activate.
- CLI must work with an isolated temporary descriptor and return deterministic JSON; missing arguments fail predictably.
- 10,000 mixed dry-run plans must not mutate inputs or trigger any external Skill action.
- Manifest must include registered references, planner and both suites.
- These checks verify deterministic routing only; **natural-language semantic intent accuracy, tool executability and live binary/device analysis remain separately unverified**.

## 2026-10-10 semantic objective + scoped mixed-project routing regression

- Optional structured `objectives` (identified by Agent from target/question, not text keywords) must supply minimal missing capabilities through the *existing* registry, while explicit `needs` continues to work and dependencies remain deduplicated.
- State/async question selects control-flow + data-flow only; does **not** auto-run hooks, download tools or execute a target.
- Android APK with proven `binary-elf` child includes Android + Native references; Browser Extension with actually inspected Native Messaging host loads extension + Native adapters; IDE Extension remains routing-only until real target-level proof.
- Out-of-scope native code never becomes a selected adapter merely because a repo contains it.
- Unknown objective, malformed surface, absent evidenceRef or unknown sub-artifact must fail closed or return partial/triage. `observe-runtime`, `compare-builds` and `trace-runtime-boundary` still require authorization/fingerprints/verified boundary signals.
- `evidenceRef` is a pointer supplied by Agent, not a provenance oracle: a passing plan does **not** authenticate its contents or prove semantic intent accuracy; live Agent evaluations remain separate.

## 2026-10-10 Swift / iOS Github-depth routing cases

- Fixed Swift ARM64 Mach-O with observed `swift-metadata` / `swift-async` must select Native plus iOS/Swift specialist reference exactly once and choose control/data flow for `swift-async-lifecycle`.
- Actual iOS Swift sources need both `swift-source` and `ios-target`; Objective-C-only UIKit sources need `objc-source` and `ios-target`; plain Swift/ObjC source without confirmed iOS target or generic Mach-O must not activate iOS specialist just because the goal names Swift/ObjC.
- `swift-protocol-dispatch` includes structure recovery; `objc-swift-bridge` still requires observed interop signal; `ios-runtime-dispatch` without authorization and runtime hypothesis remains partial.
- All specialized backends are optional. GitHub tool availability cannot certify local tool install or Swift generic/Witness runtime/ObjC receiver/Async executor L4 semantics. Static pinned Mach-O 13/13 must remain passing; research data is not copied to production Agents.

## 2026-10-10 USB real iOS application route tests

- USB installed app metadata must be read-only and anchored to bundle/build; local IPA identity (Info.plist, Mach-O header, SHA) is checked independently before treating it as the installed app. A RemoteAI local Build 4 IPA must not be conflated with actual USB-installed Build 45.
- Three independently inspected codebases: RemoteAI-Mobile Swift actor/AsyncStream, CloudCode-iOS Swift+ObjC bridge, NetworkPolicyInspector-iOS pure ObjC UIKit + RootHelper. Each must select iOS guidance based on verified source and iOS target; pure ObjC previously missed the specialist reference and is an explicit regression.
- A real NPI Build 13 IPA with embedded ARM64 NPIRootHelper can select iOS app plus Native sub-artifact only when that exact helper is in-scope; bridge tracing still requires actually observed process boundary and does not imply its runtime spawn completed.
- USB device presence and install-record success mean device/installed-app metadata is accessible, NOT Swift runtime/Witness/ObjC receiver/Task scheduler L4 proof.

## 2026-10-09 diverse hard-artifact and non-redundant fallback regressions

- Verified upstream WASM with one very large obfuscated code body: bounded import/export/code-body metadata; no module instantiate, algorithm conclusion stays Unknown.
- Electron official ASAR binaries: Pickle outer size vs JSON bytes and padding; all non-unpacked file offsets must fit the original blob; corrupt/traversal entries fail closed.
- OWASP UnCrackable Level 2 APK: ZIP/DEX header and four ABI library identities; ELF32/ELF64 `.dynsym` yields identical two JNI exported functions; DEX `ACC_NATIVE` declarations independently match static symbols. No runtime invocation claim.
- Negative test invalid WASM LEB, corrupt ASAR, non-APK ZIP, unsupported architectures and overbroad output; no target execution/install/Agent memory or new daemon.
- One existing Semantic Router remains authoritative; `container-triage.py` is an optional CLI fallback, not a new module or a mandatory startup cost. Real fixtures remain Canonical research only.

## Real v2 / AgentRE22 reverse tests & scoped native decode (2026-10-09)

- GitHub line-wrapped Base64 with verified SHA/Git blob loads exactly; non-Base64 contamination remains rejected.
- Metadata-only input never triggers disassembly, target execution, installation or extra service.
- `--disasm-at` requires preflight-smoked existing Capstone; invalid addresses and instruction-count overflow fail closed; source-linked linear decode is `LINEAR_UNVERIFIED`, not a recovered CFG.
- V2 x64 real PE: TLS callback RVA 0x87030, bounded in-memory XOR/ROL7 transforms decrypt 419152+4096 bytes, reversible byte-for-byte; deeper state machine/flag remain Unknown.
- AgentRE-Bench Level22 stripped PE: hashed fixture, 543 PE unwind ranges, 265 decoded IAT call-site observations; no claim of independently recovered AES/syscall-resolution graph or whole-program behavior.
- Actual project reports stay in Canonical `research/live-tests/`; Agent copies contain only portable Script/Reference changes and are not given large fixtures.

## REA optional backend and lean-output acceptance (2026-10-09)

- With `--compact`, capability IDs, selected references and gaps match the full plan, with less serialized output. Planner never executes an external tool.
- `preflight.ps1 -ToolNames rea` checks only the specified executable, performs no installation or MCP registration; missing tool returns `available=false`, not a fake pass.
- Static JavaScript/Electron: prefer direct local source/ASAR evidence; use REA `analyze-javascript-application <target> --json` only when REA is already installed and the scoped question requires its graph/IPC evidence.
- Native: deep analysis requires a ready provider verified by REA `providers --json` (or the existing native CLI). A REA package on PATH does not imply Ghidra/IDA readiness.
- Runtime capture, snapshots, and code reconstruction remain opt-in/evidence-driven. No global agent mutation, auto-download, new daemon or extra port.
- A tool preflight pass is distinct from executing a real reverse analysis. Where REA/provider is absent, report `Unavailable`; do not report end-to-end success.

