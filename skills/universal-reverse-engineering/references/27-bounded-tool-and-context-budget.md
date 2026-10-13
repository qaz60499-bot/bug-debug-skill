# 27 — Evidence Retrieval Budget, Tool Adapters, and Failure-Aware Depth

Cross-cutting execution discipline. Only the **host Agent** calls tools. This Skill does not install, own, auto-start, or register MCP servers, create a daemon, add ports, or alter global Agent configuration.

## Tool-capability adapter contract

For the exact task and environment, prefer an already working tool. Record:
- capability and actual backend (CLI / headless / GUI / MCP), version, readiness and target database identity;
- supported input types, output schema, precise address/span/offset semantics and reproducibility;
- whether operation is read-only, mutates a database, executes target code, or accesses a network;
- observed latency/volume if measured, output size and pagination/filter support;
- constraints: platform/license, sandbox and user authorization, fallback, and failure modes.

A name in a catalog is NOT proof of installation. For failed readiness, return Unavailable with the reason; do not silently bootstrap software.

## Adaptive retrieval (no invented global numeric thresholds)

```text
Identify decisive question
→ cheapest reliable metadata/strings/imports/manifest
→ scoped symbol + xref/CFG/IL/trace index
→ bounded graph/dataflow/targeted decompile
→ independent verification where needed
→ authorized runtime experiment only for an unresolved hypothesis
→ evidence report + stop or explicit gap
```

Prefer server-side filters, scoped queries, pagination and summarized counts before fetching raw material. Never dump every function, full trace, every embedded asset or all MCP schemas into the model. For a very broad query, return `count / covered_span / truncated / query_filter / next_page` and refine, rather than inflating context. Keep large raw observations in user-authorized task artifacts and reference exact spans/hash.

Choose the next action by *expected question-resolving evidence* versus measured or estimated tool cost (latency, output, environment risk), not tool brand or sheer number of available capabilities. If native CLI or a focused source search settles the question, skip readiness scans for unrelated providers. Prefer the planner's `--compact` projection when an explicit plan is necessary; don't run it for an obvious one-step task. Reuse native REA snapshots only when the same exact query is likely to recur; avoid building a second cache. Independent read-only queries may run concurrently if they do not share mutable tool/database state and the host supports concurrency. Mutating queries, version-sensitive databases and dependent steps are ordered.

## Failure and retry taxonomy

- No tool installed / permission denied / incompatible version → stop that backend; report gap or select existing alternative.
- Empty response / zero hits → differentiate **measured zero**, truncated scope, parser failure and unavailable data.
- Oversized response → narrow by address/function/caller/time/process/value and page; reject unbounded output at adapter boundary.
- Timeout / crash / stale DB → preserve prior immutable evidence, validate state, retry one bounded equivalent path if justified.
- Repeated same failure signature → after two equivalent failed attempts, stop parameter churn; revise the hypothesis, input representation or backend class.
- Conflicting decompilers → verify against raw bytes/disassembly or runtime observation; do not vote by tool count.

## Evaluation telemetry (for real benchmark runs)

Track task success against independent ground truth, unsupported claims, missed capabilities, false routing, invalid/redundant calls, tool output bytes/tokens, time, stopped-by-budget cases, evidence coverage and number of retries. Include the cost of readiness checks and tool startup. Do not claim performance improvements based only on a 10k in-memory planner loop.

References:
- https://github.com/agentrebench/AgentRE-Bench
- https://github.com/bethington/ghidra-mcp
- https://github.com/cellebrite-labs/ghidra-rpc
- https://bbs.kanxue.com/thread-289797.htm
