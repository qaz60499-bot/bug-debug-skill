# 20 — Version Diff

## Purpose

Compare versions without mixing evidence. Version diff explains what changed only after each artifact has its own fingerprint and matched components are justified.

## Required inputs

For each version/build:

- artifact fingerprint;
- extraction relationship if files came from a container;
- tool versions used for analysis;
- route used for that artifact;
- known Unknowns that may affect comparison.

## Matching basis

Record why two items are considered corresponding:

- stable symbol or metadata identity;
- same export/import/selector;
- same resource/package path;
- same string/xref neighborhood;
- same function shape with supporting evidence;
- same caller/callee relationship;
- same framework-generated location plus same app-owned context.

## Change classes

Separate observations from interpretations:

- observed bytes changed;
- symbol/name changed;
- layout/offset changed;
- dependency/import changed;
- string/resource/config changed;
- control-flow/data-flow changed;
- behavior changed, only when supported by runtime or equivalent evidence.

## Anti-overclaim rule

A layout, address, or generated-name change alone does not prove a behavioral change. Treat it as Observation plus low/medium-confidence Inference until a decisive path confirms it.

## Minimal record

```text
Version A fingerprint:
Version B fingerprint:
Matched component:
Match basis:
Observed change:
Interpretation:
Confidence:
Counter-evidence:
Next minimal test:
```
