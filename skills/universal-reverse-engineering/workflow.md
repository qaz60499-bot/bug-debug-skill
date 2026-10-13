# Universal Reverse Engineering Workflow

## Phase A — Intake

1. Confirm authorization, target ownership/scope, and the concrete question.
2. Preserve the original artifact read-only; work on an analysis copy.
3. Build the Artifact Fingerprint:
   - path/source/acquisition note;
   - SHA-256 and size;
   - format/container;
   - architecture/ABI;
   - package/bundle/version/build/signing metadata;
   - runtime/framework indicators;
   - tool versions used for identification.
4. Create a case from `templates/case-template.md`.

## Phase B — Route

Route before selecting tools:

```text
format → platform → runtime/framework → protection → question type → tool path
```

Select one PRIMARY route and optional SECONDARY routes. Record intentionally skipped routes when they are tempting but not needed.

## Phase C — Surface Map

Prefer low-cost, high-certainty observations:

- file header, sections, segments;
- imports/exports/symbols/selectors;
- strings/resources/config;
- embedded files;
- manifests/entitlements/metadata;
- obvious entrypoints;
- library/runtime/framework fingerprints;
- protocol/API/storage indicators;
- protection/packing/obfuscation indicators.

Output a map. Do not turn every string into a conclusion.

## Phase D — Static Deepening

Around the current question:

```text
string/symbol/metadata
→ xref
→ function
→ callers/callees
→ types/data structures
→ control/data flow
→ raw disassembly or IL verification
```

At least one decisive point must be anchored below pseudocode: bytes, assembly/IL, xref, relocation, metadata record, trace, or runtime value.

## Phase E — Recovery tracks

Use only when the route requires them:

- Symbol Recovery: recover stable names from evidence, not from taste.
- Structure Recovery: recover minimum necessary layout and separate offsets from field-role guesses.
- Function-level Emulation: model one bounded function and record assumptions.
- Unity/IL2CPP: keep metadata, generated names, native addresses, and assets as separate layers.
- Version Diff: fingerprint each version first, then compare.
- Android Framework Routing: separate framework glue from app-owned logic.

## Phase F — Hypothesis Queue

Each hypothesis must include:

- H-id and statement;
- supporting Observations;
- competing explanations or counter-evidence;
- smallest next test;
- cost/risk;
- stop condition.

Sort by smallest information-gain cost. Avoid broad tracing when a single xref, metadata record, or breakpoint can answer the question.

## Phase G — Dynamic Escalation

Only when the smallest useful next step requires runtime evidence:

- debugger breakpoint/watchpoint;
- Frida or equivalent targeted Hook;
- API/syscall/network trace;
- memory snapshot;
- controlled input differential;
- function-level emulation.

One dynamic action validates one hypothesis. Record inputs, environment, tool version, and observed values.

## Phase H — Evidence Contract

Every record is classified:

- Observation: reproducible fact.
- Inference: interpretation backed by Observations.
- Unknown: unresolved or unproven point.

Findings are composed from Observations and Inferences while preserving Unknowns.

## Phase I — Synthesis

Use `Evidence → Finding → Path`:

- Evidence: decisive Observation IDs and supporting Inferences.
- Finding: current explanation and confidence.
- Path: next shortest verification path or completion condition.

## Phase J — Finish

Completion means:

- the question is answered or explicitly blocked;
- decisive chain has reproducible evidence;
- uncertainty is listed;
- route choices are explained;
- next step is not blind exploration.
