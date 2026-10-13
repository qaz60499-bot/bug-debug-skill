# 28 — Deep Functional Capabilities: Trace, Cross-boundary Flow, Differential Verification

This reference hosts *independent optional analysis capabilities* selected by the existing Semantic Capability Router. It is not a second Router, does not auto-run debugger/instrumentation and does not make platform modules compulsory.

## A. `trace-reduction` — indexed large-observation analysis

Entry: a real identified trace/log/capture `traceArtifact`; objective describes a specific observable state/value/control question. Record artifact path/ID, provenance, known format, date/timebase, process/thread identities, size and coverage. Do not read an entire multi-GB trace into chat.

1. Find or build a read-only indexed/searchable view using an *existing* CLI/MCP backend; don't deploy a global trace system.
2. Search restricted windows by process/thread, event class, function/PC, time span, producer/consumer or value with contextual predicates.
3. Return hit counts, original offsets and bounded snippets; if too many matches, fail closed with refinable filter rather than dump results.
4. Reconstruct the specific sequence and dependencies, not just text occurrences; preserve gaps and buffer drops.
5. Cross-check ambiguous source/sink links against code/xrefs or separately captured runs as appropriate.

Value searches alone are not causal flow. A trace without the relevant event type cannot prove its absence.

## B. `boundary-tracing` — cross-runtime/cross-process lineage

Entry: at least one observed `verifiedSignals` boundary indicator: `ipc`, `interop`, `jni`, `ffi`, `cross-process`, `cross-runtime`, `browser-bridge`. Depends on `data-flow` and its static map. Trace the minimum chain:
producer → serialization / ABI → queue / RPC / transport → receiver → transformation → state consumer.

At every hop distinguish synchronous calls from asynchronous delivery, process and thread ownership, ordering/retry/ACK, field framing and endianness, lost observability, and which side generated each field. Match exact process/build/session IDs; never splice different sessions as one complete trace.

If a hop is unavailable, terminate the path at **Unknown** and specify one lowest-cost distinguishing test. Only route to dynamic-observation when its separate authorization and runtime hypothesis gates pass.

## C. `differential-verification` — bounded observed comparisons

Entry: at least two distinct, identified `comparisonCases` (test vectors, captures or configurations). This does NOT automatically mean `version-diff`: comparison can be two inputs to the same build or static analysis settings.

1. Describe controlled input difference, invariant environment, expected output and actual independent observable.
2. Verify both identities, comparability, capture scope and measurement quality.
3. Compare at the smallest decisive unit: bytes, decoded fields, branch/trace span or externally visible function result.
4. Distinguish correlation and byte/location movement from semantic causality.
5. Record failures and counterexamples; repeated cases cannot substitute for an independent source of truth.

Never claim matching functions equivalent because two decompiler texts look similar. Use a known reference result, observed I/O oracle, test vectors or validated constraints when possible. Do not execute untrusted target code outside an approved isolated environment.

Source inspiration:
- https://github.com/amruth-sn/kong
- https://github.com/GeReV/ghidra-iterative-re
- https://github.com/agentrebench/AgentRE-Bench
- https://bbs.kanxue.com/thread-289797.htm
