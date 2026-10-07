---
name: plan-before-code
description: Use when the task asks to plan before coding, design an implementation approach, list files to change, avoid starting edits immediately, 先规划再写代码, 先出方案, 不要直接改代码.
---

# Plan Before Code

Use this skill when the user wants a plan, implementation approach, architecture decision, or any change that may touch multiple files.

## Goals

- Understand the existing project before editing.
- Reduce unnecessary rewrites and wrong assumptions.
- Make the edit scope explicit before code changes.

## Workflow

1. Inspect the minimum necessary files.
2. Identify the feature, bug, or requested outcome.
3. List the files likely to be changed.
4. Explain the implementation steps.
5. Call out risks, compatibility issues, or unclear assumptions.
6. Do not edit code until the plan is clear, unless the requested change is very small.

## Output format

Use this structure:

- Goal
- Current findings
- Files to change
- Implementation steps
- Risks / assumptions
- Verification method

## Rules

- Do not propose a large rewrite unless clearly necessary.
- Do not introduce new frameworks or dependencies without a reason.
- If the user explicitly says “直接改 / no need to ask”, proceed after a very brief plan.
- For small one-file changes, keep the plan short.
