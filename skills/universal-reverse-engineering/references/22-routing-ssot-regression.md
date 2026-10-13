# 22 — Routing SSoT / Regression Cases

## Purpose

Keep canonical routing behavior stable across Canonical Skill copies and lightweight router installs.

## Source of Truth

- Human SSoT: `routing.md`
- Machine index: `config/routing-v2.json`
- Acceptance cases: `routing-regression-cases.md`
- Skill entry: `SKILL.md`

If these disagree, update them together. Do not create a second Agent Runtime or ToolRouter to resolve routing drift.

## Agent sync rule

Full Skill targets receive the complete skill directory.

Lightweight router targets receive only a router Skill that:

- points to the canonical methodology;
- preserves the target instance identity and memory;
- keeps specialist Skills isolated;
- does not carry the full reference set;
- does not create another runtime/router layer.

## Regression classes

A routing change must preserve:

- Evidence Contract behavior;
- artifact-first behavior;
- Android framework ownership split;
- Unity/IL2CPP activation only with Unity evidence;
- version-diff fingerprint separation;
- symbol and structure recovery confidence rules;
- bounded local function verification scope;
- negative rules listed in `routing-regression-cases.md`.

## Minimal sync verification

```text
Canonical version matches target full Skill version.
Full Skill targets contain SKILL.md, manifest.json, routing.md, workflow.md, config, templates, references.
Router targets contain lightweight router only.
Excluded Codex targets are not given full Skill.
No Agent Runtime or ToolRouter files are modified.
```
