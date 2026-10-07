---
name: universal-reverse-engineering-router
description: Lightweight entry to an existing universal reverse-engineering method. Use for authorized reverse analysis or a provenance investigation explicitly routed by bug-triage; keep full specialist references isolated.
metadata:
  version: "2.1.1-router"
  updated: "2026-10-06"
  runtime_self_contained: true
---

# Universal Reverse Engineering Router

Reuse an installed `universal-reverse-engineering` capability when available. Ordinary debugging starts in `bug-triage`, which decides when provenance investigation is needed. Do not make every bug a reverse-analysis task.

## Existing method and routing

- If the current environment has a full `universal-reverse-engineering` Skill installed, read it and only the references relevant to the bounded question.
- Otherwise, resolve a bounded source/configuration/state provenance question using the process below.
- Deep native/mobile/decompilation/emulation work beyond this lightweight router's scope requires a dedicated reverse-engineering capability. Return the scoped question and missing evidence to the primary agent; do not broaden the task or install a new specialist pack without authorization.

## Bounded provenance investigation

1. Fix the target identity: real source/config/artifact paths, version/build and runtime instance, actual versus expected values, timestamps and evidence locations. Fingerprint artifacts before deep or cross-build claims; keep original artifacts read-only.
2. Starting from the observed result, follow only relevant value writers/readers, references, and callers to the state/data/configuration origin and invocation that produced it. Use targeted source search and data/call-flow references; distinguish generated/framework glue from app-owned logic.
3. Establish the effective source and precedence, rather than assuming a configuration file is active: inspect the relevant loader/generator, CLI/environment overrides, persisted/external state (files/database/Registry/services), generated build configuration, and the artifact actually running. Inspect only sources that the evidence points to.
4. Prefer static mapping; validate an unresolved edge with the smallest runtime observation that tests one hypothesis. Bind every source claim to a path/symbol/query/trace or observed runtime value; do not patch a symptom while tracing its source.
5. Return the source finding and relevant causal edges as Observation / Inference / Unknown, with evidence locations and unresolved alternatives. When invoked by `bug-triage`, return control for its Forward Impact Trace and root-cause confirmation before editing. The router does not decide that a bug is fixed.

## Constraints

- Route before tool choice; use static evidence before bounded dynamic validation.
- Preserve Unknowns; do not merge versions/builds without separate fingerprints.
- Do not install/copy a full specialist reference set into this lightweight router, create a second Runtime/ToolRouter, or override identity/memory/domain Skills.
- Source tracing belongs here and in the installed full reverse capability; `bug-triage` holds only triggers, invocation, and confirmation gates.
