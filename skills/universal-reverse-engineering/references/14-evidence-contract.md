# 14 — Evidence Contract

## Purpose

Every reverse-engineering claim must be classified before it becomes a finding. This prevents decompiler guesses, generated labels, and framework assumptions from being treated as facts.

## Observation

A directly reproducible fact produced by the target artifact or a deterministic analysis tool.

Examples:

- file hash, size, format, architecture, section or segment metadata;
- package name, bundle identifier, version/build, signing metadata;
- symbol, import, export, string, or xref location;
- instruction bytes, IL, or metadata record at a recorded address or token;
- runtime value observed at a named breakpoint, watchpoint, trace point, or emulator step;
- manifest, entitlement, resource, route, protocol field, or config value.

Observation rules:

- record artifact identity and version/build;
- record location: address, token, path, class, method, offset, resource ID, or field;
- record tool/view/version used to observe it;
- do not silently rewrite an observation into a semantic conclusion.

## Inference

An interpretation derived from one or more Observations.

Every inference records:

- supporting Observation IDs;
- confidence: high / medium / low;
- competing explanation or counter-evidence when relevant;
- the smallest next test that could strengthen or falsify it.

Decompiler-generated names, guessed types, reconstructed structures, recovered symbols, Unity/IL2CPP names, Android framework ownership, and version-diff explanations are Inference until independently confirmed.

## Unknown

Anything not established by available evidence stays explicitly Unknown.

Unknown is not failure. It prevents guessed facts from entering the case model. Unknown should include:

- missing artifact identity;
- unresolved symbol or type ownership;
- conflicting decompiler output;
- suspected but unproven runtime transformation;
- version differences that may be layout or compiler noise;
- runtime behavior not yet observed.

## Contract

```text
Observation -> Inference -> Finding
       \          |
        \-> Unknown <- unresolved ambiguity
```

A finding may be marked Confirmed only when its decisive statements are backed by reproducible Observations. Otherwise preserve the inference confidence and remaining Unknowns.

## Minimal record

```text
ID:
Class: Observation | Inference | Unknown
Artifact fingerprint:
Location:
Tool/view:
Statement:
Supports:
Confidence:
Counter-evidence:
Next minimal test:
```

## Anti-patterns

- Treating a generated or guessed name as source truth.
- Treating a layout shift as a behavior change without additional evidence.
- Treating one framework indicator as full framework attribution.
- Hiding ambiguity instead of recording it as Unknown.
