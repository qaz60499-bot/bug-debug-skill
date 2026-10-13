# 25 — Optional Collaboration With Independent Architecture Skill

The Universal Reverse Engineering Skill and the Architecture Review Skill are separately owned. Neither is a dependency, supervisor, or replacement for the other.

## When to request external architecture review

- Reversing uncovers ambiguous ownership of state, async cancellation, fallback/recovery or duplicate controllers across modules;
- User specifically asks whether the implementation architecture is correct, redundant or conflicting;
- The concrete mechanism is known but its systemic impact or responsibility boundary remains unclear.

Do not hand off a single-function explanation merely because it belongs to an application.

## Reverse → Architecture evidence handoff

Pass a bounded packet, not a merged runtime:
- user goal and exact unanswered architecture question;
- root/worktree, relevant scope and source/artifact fingerprints;
- observed callers, control/data-flow and runtime state transitions, each with provenance;
- Observation / Inference / Unknown separated;
- confirmed facts, competing explanations, missing evidence;
- explicit user restrictions and no-edit/read-only boundary;
- candidate next verification and stopping condition.

The receiving Agent uses **its own** configured `architecture-review` Skill, tools, permissions and output directory. If unavailable, report Unavailable; do not silently clone/install or invent results.

## Architecture → Reverse evidence handoff

Accept architecture findings as hypotheses and localized pointers, not binary/behavioral proof:
- candidate files, interfaces, state ownership and dependency edges;
- native analyzer records and scope/snapshot limitations;
- narrow mechanism question that requires reverse or dynamic verification.

Start at the identified evidence gap; do not re-run the whole architecture audit. Return a scoped `Evidence → Finding → Path` result.

## Boundary

No persistent dispatcher, daemon, extra MCP port, shared mutable global cache, or copying the other Skill's rules. Cross-skill handoff requires an explicit need, a supported host capability and authorized scope. Neither a tool exit code nor an architecture candidate by itself authorizes code modification.
