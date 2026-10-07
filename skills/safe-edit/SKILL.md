---
name: safe-edit
description: Use when modifying an existing project safely, making minimal changes, avoiding unrelated refactors, 不要乱改, 只改相关文件, 安全修改, minimal edit.
---

# Safe Edit

Use this skill when modifying an existing codebase and the user expects focused, low-risk changes.

## Goals

- Make the smallest correct change.
- Avoid breaking existing behavior.
- Avoid unnecessary refactoring.

## Workflow

1. Locate the exact files related to the task.
2. Read nearby code and define the intended change boundary; note visible pre-existing unrelated changes.
3. Preserve existing naming, style, file structure, and public APIs.
4. Change only the code needed for the request.
5. Avoid formatting or refactoring unrelated code.
6. Inspect the resulting diff and confirm it stayed inside the intended boundary, including public API, data/schema, and state changes.
7. Summarize changed files and impact.

## Rules

- Do not rename files, functions, or variables unless required.
- Do not change project architecture unless the user asks for it.
- Do not delete code before checking whether it is referenced.
- Do not update dependencies unless needed for the task.
- Do not mix refactoring with bug fixes unless explicitly requested.
- For bugs, change only the evidence-supported causal point. A failed fix broadens investigation, not the edit boundary; return to `bug-triage` before another patch without new evidence.
- Do not add fallback, retry, watchdog, or another recovery/state mechanism unless causal evidence makes it necessary for the requested fix.
- Do not overwrite or absorb unrelated existing changes; leave them untouched when ownership is unclear.
- If a safer partial fix exists, prefer it over a risky broad rewrite.

## Final response checklist

Include:

- What changed
- Files changed
- Why this is safe
- How to verify
- Any limitations or follow-up needed
