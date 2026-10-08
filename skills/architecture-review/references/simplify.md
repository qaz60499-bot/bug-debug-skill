# Simplify with existing Harness workflows

Explicit user modification intent is required. Audit alone is read-only. The CLI performs analysis and emits candidates; editing remains with Codex and the existing `safe-edit` skill. Do not create another refactoring engine.

For a candidate, confirm actual responsibility and callers, effective configuration, dynamic entry status, ownership of async/concurrent state, recovery/fallback obligations and reachable side effects. Native unused/clone output is insufficient. Resolve static/runtime conflicts before editing. Unknown dynamic entry/config paths, unclear concurrency control, distinct responsibilities, low-frequency recovery mechanisms and missing behavior regression block automatic merging/deletion.

Establish observed tests for the existing behavior, including concurrency/cancellation/recovery when relevant. Record baseline commands, outputs and exact source version. The optional pure `assessSimplification` helper in `scripts/router.mjs` returns `blocked` or `ready_for_harness_edit`; its input is the agent's evidence-backed assessment, not independent proof of equivalence. `ready` is never permission to skip verification.

Use `safe-edit` for minimal sufficient changes within the user's authorized boundary. Record before/after hashes and owned paths; preserve unrelated modifications. Invoke `test-and-verify`, with `bug-triage` if behavior diverges. Only observed successful regressions permit `verified`. `assessRegression` refuses success with missing/failed artifacts. A failed regression must not be described as a successful simplification.

If rollback is necessary, revert only edits owned by this change after checking current content against the recorded after state. Concurrent or user edits require a careful targeted restoration. Never use repository reset/clean or broad recursive cleanup. After rollback, rerun the original baseline and report the observed outcome.

Report candidate, evidence, rationale, affected callers/configuration, actual modification, baseline and regression artifacts, unresolved obligations and rollback outcome. Fewer files/lines is not an acceptance criterion.
