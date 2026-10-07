---
name: code-review
description: Use when reviewing code, checking recent changes, finding risks before commit, 代码审查, review修改, 检查有没有问题, 提交前检查.
---

# Code Review

Use this skill when reviewing a patch, checking recent changes, or finding risks before committing.

## Goals

- Catch correctness bugs and regressions before style issues.
- Focus on actionable, evidence-based findings.
- Avoid rewriting code during review unless asked.

## Review checklist

Check for:

- correctness regressions and unintended state mutation
- concurrency, ordering, or repeated-request hazards
- public API, data, or schema contract changes
- fail-open / fail-closed regressions, destructive behavior, or lost error handling
- unrelated file changes
- broken imports, paths, or configuration updates
- type/shape mismatches and missing normal/loading/empty/failure handling when relevant
- hardcoded secrets, tokens, URLs, or environment-specific values
- duplicated logic or hot-path performance problems when material
- missing tests or verification for the changed behavior

## Output format

Group findings by severity:

### Must fix
Problems likely to break behavior, corrupt state/data, violate a contract, or cause serious risk.

### Should fix
Problems with credible regression, maintainability, or UX impact.

### Optional
Low-risk improvements that do not affect correctness.

### Looks good
Mention key areas that are okay.

## Rules

- Cite exact files and functions when possible.
- Tie severity to a concrete failure mode and evidence; do not inflate severity from style preference.
- Prioritize correctness, state/data integrity, contracts, and destructive effects over formatting or style.
- Do not invent issues without evidence.
- Prefer a short focused review over a long generic checklist.
- If no major issue is found, say so clearly.
