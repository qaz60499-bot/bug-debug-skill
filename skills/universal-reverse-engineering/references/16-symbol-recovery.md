# 16 — Symbol Recovery

## Purpose

Recover stable semantic names without mistaking generated labels for source truth.

Symbol recovery is a navigation aid and evidence model, not a cosmetic bulk rename pass.

## Evidence sources

Use one or more of:

- existing symbols, exports, imports, selectors, RTTI, reflection metadata;
- debug metadata, PDB/dSYM/map files when available;
- strings with xrefs;
- callers, callees, and control-flow position;
- type signatures, argument count, return shape, and repeated call patterns;
- framework/runtime conventions;
- version-to-version matches;
- runtime traces or emulator observations for a bounded function.

## Recovery record

For every recovered name, retain:

- original address, token, selector, method ID, or identifier;
- original/generated label;
- proposed semantic name;
- supporting Observation IDs;
- confidence;
- unresolved alternatives;
- whether the rename has been applied to a database/project or only recorded in notes.

## Confidence guide

- High: independent evidence agrees, such as symbol metadata plus xref behavior or runtime value.
- Medium: several static indicators agree, but no independent runtime or metadata confirmation exists.
- Low: name is a local navigation hypothesis only.

## Stop rule

Prefer a small set of high-confidence names that improve the current route. Do not rename broad surfaces speculatively.

## Anti-patterns

- Renaming a function solely from pseudocode shape.
- Overwriting original labels without keeping a mapping.
- Applying names from one version to another without version-diff support.
- Treating decompiler or model-suggested names as Observations.
