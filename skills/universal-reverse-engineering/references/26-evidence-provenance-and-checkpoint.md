# 26 — Evidence Provenance, Independent Verification, and Resumable Checkpoints

This is a cross-cutting *method*, not a new router or persistent service. Load only when a long/iterative reverse-engineering investigation, database annotation, high-confidence conclusion, or resumption requires it.

## Avoid evidence laundering

- **Original**: immutable input bytes, verified metadata, actual runtime event captured under authorization.
- **Tool-derived**: disassembly/decompiler/SSA/CFG/call graph derived from an identified original, tool, project database and analysis settings.
- **Agent-proposed**: semantic names, types, classifications, comments, summaries, patches and conjectures written by an agent.
- **Independent oracle**: test vectors, external specification, instrumented trace or independently reproduced observable behavior, with provenance.

Never count a Ghidra/IDA database readback of an earlier Agent rename/type/comment as independent corroboration. Preserve the original symbol/type and explicit author/source whenever available. Tool-derived output may inherit Agent proposals from the mutable analysis database; label that dependency.

## Minimal evidence record (only fields available)

```text
Evidence ID:
Artifact fingerprint (hash + build / relevant unit):
Acquisition context and permission:
Tool, concrete version/backend, analysis-project snapshot:
Operation and scoped query:
Location / span / event timestamp:
Raw pointer or immutable excerpt (redacted as required):
Source class: original | tool-derived | agent-proposed | independent-oracle
Parent evidence IDs / transformations:
Observed coverage and truncation:
Unknown, caveat, or invalidation condition:
```

Observation / Inference / Unknown remain the primary claim contract. A proposed semantic name is Inference even after it appears in a tool's output. An unsupported or circular claim never upgrades to Confirmed.

## Bounded hypothesis loop

1. Write the smallest competing hypotheses and a **distinguishing observation**.
2. Choose the shortest read-only observation with sufficient discrimination.
3. Preserve negative results as *measured zero*, never confuse them with *not queried* or *tool unavailable*.
4. Cross-check with a source independent of the hypothesis. Disassembly and decompiler views from the same annotated database are **not** fully independent.
5. Stop at sufficient proof; on unresolved alternatives, record Unknown instead of inventing certainty.

## Mutation safety (only with explicit scope)

- Default to read-only and analysis copies; never rename/type/patch originals merely to make reasoning easier.
- Before changing an analysis database, record affected symbol/type counts, known offsets/CFG, original annotations, project identity and rollback point as applicable.
- Stage proposed changes on the analysis copy; compare before/after invariants and collateral effects. Verify the check can actually detect a deliberately introduced difference in a safe fixture.
- Reclassify any dependent evidence as potentially stale after a relevant change, and repeat only the smallest checks.
- Preserve separate source identity for each build, program, process, architecture and tool database.

## Checkpoint outside chat context

Store a concise task-owned checkpoint only when useful to resume a genuinely long investigation (no global memory daemon). Include: goal/scope, artifact hash, source/build identity, tool+DB snapshot, selected capabilities, observations with evidence IDs, explicitly provisional hypotheses, last completed step, next minimal proof, failure signatures, budgets, open Unknowns, and forbidden actions. Resumption first validates current artifact/tool/DB state; stale findings remain historical, not current proof.

Read before writing. Never treat notes or another agent's summary as direct measurement.

References (methods only, no external installs):
- https://github.com/GeReV/ghidra-iterative-re
- https://github.com/morluto/rea
- https://bbs.kanxue.com/thread-291067.htm
