# 17 — Structure Recovery

## Purpose

Recover only the type and layout information needed for the current analysis question.

A recovered structure is a model with confidence levels, not source truth. Keep observed layout facts separate from inferred field names or roles.

## Observation layer

Record facts such as:

- observed allocation size;
- stack/local size;
- field offset or array index;
- load/store width;
- repeated access pattern;
- constructor or initializer writes;
- metadata-declared fields where available;
- serialization/deserialization field order;
- call sites that pass or receive the object.

## Inference layer

Only after observations, infer:

- likely type name;
- likely field role;
- ownership/lifetime;
- enum meanings;
- pointer/reference relationships;
- version-to-version layout changes.

Each inferred field needs confidence and alternatives.

## Minimal record

```text
Structure ID:
Artifact fingerprint:
Observed size:
Evidence locations:
Field/offset table:
Observed accesses:
Inferred roles:
Confidence per field:
Conflicting layouts:
Next minimal test:
```

## Scope control

Stop when the structure model is sufficient to explain the current evidence. Do not reconstruct a full program type system unless it is required by the question.

## Cross-version rule

A layout recovered from one version does not apply to another until version matching confirms the corresponding component and layout.
