# 23 — Generic Capability Routing and Evidence-driven Composition

This Skill is independent and target-neutral. It is NOT an Android/iOS/device reversing tool and does not require the Architecture Skill.

## Semantic task descriptor

The host Agent interprets the user's concrete goal before tool choice. Minimal task descriptor:
- `goal`: the mechanism/question to explain;
- `artifact.kind`: source, binary-pe, binary-elf, binary-macho, apk, aab, dex, ipa, dotnet, electron, flutter, javascript, wasm, bytecode, firmware or unknown;
- `needs`: explicit capability IDs from `config/routing-v2.json`;
- `objectives` (optional): Agent-identified question class, not a keyword classifier. Existing `objective_capabilities` maps a short structured investigation goal to the minimum registered capabilities (e.g. `explain-state` → control-flow + data-flow; Swift-specific `swift-protocol-dispatch` → structure/control, `swift-async-lifecycle` → control/data, `objc-swift-bridge` → boundary tracing, `ios-runtime-dispatch` → gated dynamic observation). The original evidence gates still apply;
- `artifact.surfaces` (optional): *in-scope* previously observed sub-artifacts `{kind,evidenceRef}` for cross-runtime projects (APK + observed ELF, browser extension + observed native host, Electron + actual addon); unsupported or empty evidence reference triggers partial/triage rather than loading an unrelated platform adapter;
- `verifiedSignals`: observed artifacts with source, never guess based on labels;
- `scope`, `depth`, `constraints`: user-selected; depth changes the amount and strength of evidence, NOT a quick/deep router;
- `runtimeHypothesis`, `authorizedRuntimeObservation`: when dynamic observation is warranted;
- `allowCrossSkillHandoff`: explicit handoff decision; not a global dependency.
- `traceArtifact`: actual identified trace/log source, required only for optional `trace-reduction`.
- `verifiedSignals`: verified `ipc`, `jni`, `ffi`, `interop`, `cross-process`, `cross-runtime` or `browser-bridge` for optional `boundary-tracing`.
- `comparisonCases`: two or more distinct and identified observations/test vectors to plan `differential-verification`.

The host is responsible for understanding goal semantics; the optional one-shot `scripts/route-capabilities.mjs --request <descriptor.json>` validates and composes capability dependencies, **not** an LLM and **not** a second runtime. It never executes a tool or another Skill.

## Capability matching

1. Identify the actual unanswered question and least expensive decisive evidence.
2. Choose the minimal sufficient `needs`. A mention of a tool or platform is never enough to activate a high-cost module.
3. Consult the machine registry, require gates and inspect unresolved needs.
4. Select a relevant platform **adapter** only when target type is actually known; platform does not determine every ability. In mixed projects, add only observed and task-relevant `artifact.surfaces` with original file/hash/location references; Agent must check the provided evidenceRef itself (planner checks structure, not provenance). Browser/IDE extension packaging does not imply Electron; source repositories do not imply decompilation.
5. Load only selected references and real available tools/MCP adapters.
6. Re-plan **incrementally** only if findings create a new unanswered question.
7. Stop when enough reproducible evidence answers the question or explicitly report uncertainty.
8. If a genuinely large trace, a cross-boundary question, or an observed comparison is essential, select the corresponding optional deep capability in `references/28-deep-trace-boundary-and-differential.md` only after its evidence gate is satisfied. Reject unbounded retrieval and treat Agent-generated annotations as lower-trust derivations. See `references/26-evidence-provenance-and-checkpoint.md` and `references/27-bounded-tool-and-context-budget.md`.

Useful generic paths:
- source code / runtime implementation: entrypoints → state writes → caller/callee → data flow → runtime event, if necessary;
- compiled code: artifact identity → sections/metadata → xref/CFG → structure or symbol recovery when needed;
- network protocol: captured message and provenance → producer/parser → encoding/state transition → optional observed trace;
- cross-version: fingerprint independently → matching basis → diff → bounded verification.

## Separation of concerns

`Platform adapter` identifies artifact grammar and suitable tools.
`Analysis capability` selects what question to investigate.
`Tool adapter` checks available CLI/MCP and invokes evidence-producing operations under existing agent permissions.
`Architecture-review` is a separate Skill; never make it a required dependency or copy its implementation.

Swift/ObjC compiled binaries are still Native artifacts: the single planner adds the iOS/macOS platform *reference* only after verified Swift/ObjC Mach-O signals; Swift source requires both genuine Swift code and an iOS target. This is a bounded reference overlay, not a second router or automatic L4 tracing. No automatic global instrumentation, no automatic tool installs, no full-repository scan for a localized question, no permanent daemon, no global agent routing changes. Preserve original artifacts.

## Evidence and completion

Claim categories: Observation / Inference / Unknown. Bind to artifact fingerprint, exact location, tool/version, coverage and supporting observation. Do not assert behavior from decompiler pseudocode alone. If source/snapshot is partial, acknowledge incomplete reachability. A higher user-requested depth increases verification obligations but cannot fabricate unavailable facts.
