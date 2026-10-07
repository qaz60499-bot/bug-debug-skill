---
name: bug-triage
description: Use when debugging errors, build failures, runtime exceptions, broken behavior, 报错排查, bug定位, 构建失败, 运行错误, debug.
---

# Bug Triage

Classify the failure, route the investigation, and confirm a causal explanation before a minimal fix. A symptom or project-owned stack frame alone is not a root cause.

## Workflow

1. Record the actual symptom, expected result, reproduction, running version/build, effective configuration, state, and relevant bounded logs. If reproduction is unavailable, retain uncertainty and gather evidence; do not guess a broad patch.
2. Classify the failure domain (multiple labels may apply): `PROJECT_BUG`, `CONFIGURATION_FAILURE`, `RUNTIME_STATE_FAILURE`, `NETWORK_FAILURE`, `PROVIDER_FAILURE`, `ENVIRONMENT_FAILURE`, `TOOL_OR_PROTOCOL_FAILURE`, `AUTH_OR_QUOTA`, `NO_PROGRESS`, `STALLED`, or `UNKNOWN_NEEDS_EVIDENCE`. Only evidence of `PROJECT_BUG` justifies a project-code fix; other domains first require investigation of their actual source. For apparent stalls, inspect session/tool/transport events before declaring a stall or retrying side effects; silence or no file changes alone is insufficient.
3. After failure classification, invoke `repo-map` only for `PROJECT_BUG`, project-owned `CONFIGURATION_FAILURE` / `RUNTIME_STATE_FAILURE`, or uncertain ownership where project-structure evidence is actually needed. If sufficient evidence identifies `NETWORK_FAILURE`, `PROVIDER_FAILURE`, `AUTH_OR_QUOTA`, pure `ENVIRONMENT_FAILURE`, or external `TOOL_OR_PROTOCOL_FAILURE`, skip `repo-map`; do not mechanically scan the project. Use Native/Project Memory only to choose a candidate area; when project mapping is warranted, confirm current files, symbols, dependencies, configuration and runtime entry points. Memory cannot replace current disk evidence.
4. Start with Forward Trace: input/action → entry/request → modules → configuration loading → logic → runtime state → output. Find the earliest divergence from expected behavior and separate downstream errors from causes.
5. Label each root-cause hypothesis `CONFIRMED`, `SUSPECTED`, or `UNKNOWN`, with supporting/contradicting evidence and the smallest distinguishing observation. Apply the conditional Reverse route below when triggered.
6. Confirm the causal chain with Forward Impact Trace: proposed root cause → intermediate configuration/data/state/module effects → the original observed fault. An identified source alone is not confirmation. Unclosed links stay `SUSPECTED`/`UNKNOWN`; gather evidence before editing.
7. When evidence closes that chain, invoke `safe-edit` for the smallest causal change, `code-review` for side effects and unnecessary mechanisms, then `test-and-verify` for the original reproduction and observed result. Use `plan-before-code` only when complexity or risk requires it.
8. If the first minimal fix fails, increase Search Breadth, not Change Breadth: gather new evidence and reclassify; invoke Reverse when evidence remains incomplete. Repeated failed fixes without a reliable cause enter diagnosis-only mode; stop editing and stacking mechanisms.

## Conditional Reverse route

Invoke an installed `universal-reverse-engineering` capability, or use the included `universal-reverse-engineering-router`, if any applies:

- Forward Trace cannot explain the real symptom.
- `Static Expected != Runtime Actual`.
- Configuration or state provenance is unclear.
- The first minimal fix failed and the evidence is still incomplete.
- Hidden/external/generated configuration, external state, or a runtime override is suspected.

Invocation contract:

- Read the installed `universal-reverse-engineering/SKILL.md`, or the included `universal-reverse-engineering-router/SKILL.md`. Follow the installed capability's scope and load only relevant references. Do not create another reverse/debug Skill or copy a full specialist reference set into this workflow.
- Pass the concrete symptom, target/version/build, actual versus expected values, Forward Trace boundary, evidence locations, hypotheses, and the bounded provenance question.
- The Reverse capability owns code/data/configuration/state/caller provenance and build-artifact/runtime investigation. Request the source finding, causal evidence locations, and Observation / Inference / Unknown; do not treat an Inference as `CONFIRMED`.
- Return to this triage at step 6. Confirmation requires the Forward Impact Trace to explain the intermediate effects and original fault before Safe Edit.

## Rules

- Evidence insufficient → no confirmed root-cause claim; non-`PROJECT_BUG` → no default project-code patch.
- Failed fix → broader evidence, minimal edit boundary; repeated failure → diagnosis, not compensation.
- Do not add fallback, retry, watchdog, or a second recovery/state mechanism unless causal evidence proves it is necessary for this fault.
- Preserve existing behavior and dependencies unless the confirmed cause requires change.
- No actual outcome verification → no claim that the bug is fixed.

## Final response

Report the failure domain, confirmed cause + evidence (or hypotheses + missing evidence), Reverse route if used, Forward Impact Trace, minimal change/files, original reproduction and verification results, and remaining uncertainty.
