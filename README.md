# Bug Debug Skill

A portable public archive of a structured debugging workflow for coding agents.

## What it does

The workflow standardizes:

1. Failure classification before editing
2. Conditional repository mapping
3. Forward Trace to the earliest divergence
4. Evidence states: CONFIRMED / SUSPECTED / UNKNOWN
5. Conditional reverse-provenance investigation when static and runtime behavior diverge
6. Forward Impact Trace before root-cause confirmation
7. Minimal safe edits only after causal evidence closes
8. Code review focused on correctness/state/data integrity
9. Runtime / state / artifact / semantic verification
10. Diagnosis-only mode after repeated failed fixes instead of stacking retry/fallback/watchdog mechanisms

## Included skills

- `bug-triage` — main debugging router
- `repo-map` — bounded repository mapping
- `safe-edit` — minimal evidence-supported edits
- `code-review` — correctness-first review
- `test-and-verify` — risk-proportionate verification
- `plan-before-code` — bounded planning for larger changes
- `universal-reverse-engineering-router` — lightweight provenance investigation route

## Design principles

- Evidence first
- Runtime truth over stale memory
- Search breadth may increase after a failed fix; change breadth should not
- Tests passing does not prove the requested bug is fixed
- External failures should not default to project-code edits
- Finding a source value does not prove the causal chain
- Avoid compensating mechanisms without causal evidence

## Validation snapshot

The archived version was regression-tested with:

- 36 / 36 unit tests passing
- 344 / 344 deterministic contract checks passing
- Repeated live decision checks for reverse gating, failed-fix handling, runtime-vs-test verification, external failure routing, and source-chain closure

Live file-edit E2E coverage can still depend on the execution harness used by the host agent.

## Portability note

This public archive intentionally removes machine-specific maintenance paths and runtime-instance details. Install or route to your own reverse-engineering capability when the reverse-provenance path is triggered.
