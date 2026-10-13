# 24 — Cross-platform Data Flow and Protocol Analysis

Use only when the task asks where a value originates, how it transforms or where it is consumed, or to reconstruct a communication protocol. This is a functional capability, NOT a device specialization.

## Data-flow route

1. Define `source`, `sink`, tracked value, observation scope and expected transformation.
2. Find a bounded entrypoint and xref/caller chain. Prefer source/IR/IL when available; for binaries validate crucial paths against instruction-level evidence.
3. Follow data through aliasing, serialization, IPC or native/managed boundaries only when evidence supports crossing.
4. Record path segments with location, observed or inferred role and gaps. Do not mistake textual symbol references for executable call/data-flow facts.
5. If an input value or a dispatch branch is runtime-dependent and unresolved, propose the smallest distinguishing runtime observation.

## Protocol route

1. Determine message boundary and transport from captures/code, not guesswork.
2. Locate producer/serializer, transport, parser and consumer; separate client-generated and server-generated fields.
3. Model field encoding, lengths, endianness, ordering, integrity/checksum and state transitions only to the extent observed.
4. Use controlled sample differences to test hypotheses; preserve redacted payloads and timing/provenance.
5. Unknown protocol fields remain Unknown. Never infer an authentication/security guarantee from a client-only check.

Potential adapters: native text search, code graph, JADX, Ghidra, IDA, browser network inspection, Wireshark, protocol parser and targeted debugger. Only select available, suitable tools under authorized scope.

Output: bounded flow graph or message schema + evidence links + unresolved fields + minimal next verification and stop condition.
