# v2 Capability Index

This file is the short activation index. Detailed procedure lives in the referenced files and the routing SSoT.

## Evidence Contract

Source: `references/14-evidence-contract.md`

Every claim is classified as Observation, Inference, or Unknown before it becomes a finding. Reverse-engineering reports must not collapse these classes.

## Artifact Fingerprint

Source: `references/15-artifact-identity.md`

Before deeper analysis or version comparison, record exact identity: hash, size, format, architecture, version/build, package/bundle ID, signing metadata, runtime/framework indicators, and acquisition context.

## Symbol Recovery

Source: `references/16-symbol-recovery.md`

Recover semantic names from symbols, imports/exports, selectors, RTTI/type metadata, strings+xrefs, callers/callees, and version matches. Proposed names remain Inference until supported by independent observations.

## Structure Recovery

Source: `references/17-structure-recovery.md`

Recover only the layout needed for the current question. Separate observed sizes/offsets/access patterns from inferred field roles.

## Function-level Emulation

Source: `references/18-function-level-emulation.md`

Use emulation as a bounded verification route for small self-contained functions. Record modeled inputs, environment assumptions, and scope limits.

## Unity / IL2CPP Route

Source: `references/19-unity-il2cpp.md`

Activate only when Unity-specific artifacts exist. Keep Unity resources, managed metadata, IL2CPP-derived symbols/types, and platform-native components as separate evidence layers.

## Version Diff

Source: `references/20-version-diff.md`

Fingerprint each version separately, match components with recorded basis/confidence, and avoid claiming behavioral change from renaming/layout movement alone.

## Android Framework Routing

Source: `references/21-android-framework-routing.md`

Identify framework family before assigning logic ownership. Separate framework-generated glue from app-owned code, and route JNI/native libraries to native analysis.

## Routing SSoT / regression cases

Sources:

- `routing.md`
- `config/routing-v2.json`
- `routing-regression-cases.md`
- `references/22-routing-ssot-regression.md`

`routing.md` is the human source of truth. `config/routing-v2.json` is the machine-checkable index. `routing-regression-cases.md` lists required positive and negative routing cases.

## v2.2 Semantic Capability Router (independent, generic)

- Policy: `routing.md`; machine capability registry: `config/routing-v2.json`.
- Interpretation and evidence: `references/23-capability-routing.md`.
- Cross-platform data flow and protocol: `references/24-data-flow-and-protocol.md`.
- Optional independent Skill collaboration: `references/25-cross-skill-handoff.md`.
- Deterministic capability planner: `scripts/route-capabilities.mjs --request <task-descriptor.json>`.
- Test: `node --test scripts/test-routing.mjs scripts/test-routing-hardening.mjs` (includes empty-load, hostile/invalid input, CLI smoke and 10k deterministic planning checks).

## v2.2.2 Deep functional optional capabilities

- `trace-reduction`: identified large trace/log; bounded search, original offsets and causal checks (`references/28-deep-trace-boundary-and-differential.md`).
- `boundary-tracing`: observed IPC/FFI/JNI/cross-runtime boundary; depends on data-flow and follows producer → transport → consumer.
- `differential-verification`: at least two distinct identified cases; controlled input/output comparisons, not a substitute for version Fingerprints.
- Evidence provenance and resumption method: `references/26-evidence-provenance-and-checkpoint.md`.
- Tool availability, bounded retrieval, failure taxonomy and evaluation budget: `references/27-bounded-tool-and-context-budget.md`.

## v2.2.3 Native toolchain fallback from a hard real-binary regression

- Only after fingerprint and backend preflight, use `python scripts/native-triage.py <file-or-.b64> --max-items 24` for read-only PE64/ELF64 static triage when full disassembly is missing.
- Recover PE x64 unwind function boundaries, scoped imports, candidate IAT references and bounded data strings. These are *Observations/candidates*, not decoded branches or proven runtime paths. Complete details: `references/29-stripped-native-toolchain.md`.
- Canonical integration test: `python -m unittest discover -s scripts -p test_native_triage.py -v`. Do not distribute executable benchmark samples to Agents merely to run regression.
- Hard PE benchmark explicitly exposes an unmet deep-disassembly capability. Report `UNAVAILABLE` and Unknown rather than asserting a complete reverse.

Do not conflate artifact type (including mobile/firmware) with user intent or analysis capability. Depth is a user-controlled investigation dimension, not an alternate skill/router. Architecture-review remains independent and never auto-invoked by this script.
