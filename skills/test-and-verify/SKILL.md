---
name: test-and-verify
description: Use when asked to test, verify, run checks, find build/lint/test commands, 改完验证, 跑测试, build检查, lint检查, verification.
---

# Test and Verify

Use this skill after code changes or when the user asks how to confirm something works.

## Goals

- Find realistic, risk-proportionate verification steps.
- Use existing project commands.
- Avoid claiming success from tests that do not prove the requested outcome.

## Workflow

1. Detect the project type and available verification commands from config, task files, CI, or docs.
2. Choose verification by risk: narrow unit/lint checks for local changes; build/integration checks for boundary changes; state, artifact, runtime, or semantic-result checks when the requested outcome depends on them.
3. Start with the narrowest useful check and expand only when risk or results justify it.
4. Compare the observed result with the requested business/semantic outcome; test PASS alone is not proof of full correctness.
5. If no automated test exists, perform or describe the smallest meaningful manual verification.
6. If a command fails, explain whether the failure is related to the change and what remains uncertain.

## Rules

- Do not invent commands that are not present.
- Do not run destructive commands.
- Do not install or upgrade dependencies unless necessary and allowed.
- Verify persisted state or produced artifacts when success depends on them, not only process exit codes.
- If verification cannot be completed, clearly say what was not verified and why.
- For UI projects, include manual checks for normal, loading, empty, and error states when relevant.

## Final response checklist

Include:

- Checks selected and why they match the risk
- Commands run, if any
- Results and observed semantic/business outcome
- Manual or artifact/state verification, when relevant
- What remains unverified
