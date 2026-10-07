---
name: repo-map
description: Use when asked to understand a repository, find where a feature is implemented, map project structure, 项目结构分析, 找功能在哪, repo map, codebase overview.
---

# Repo Map

Use this skill when the user asks to understand a project, locate a feature, trace data flow, or identify where to make a change.

## Goals

- Build a compact map of the repository.
- Avoid reading the entire project unnecessarily.
- Help future edits target the correct files.

## Workflow

1. Inspect the root directory.
2. Identify package/config files and the project type.
3. Identify entry points, pages/routes, components, services/API modules, utilities, tests, and docs.
4. Search for feature keywords only when needed.
5. Open a small number of high-signal files.
6. Produce a concise map.

## Output format

Use this structure:

| Area | Path | Purpose |
|---|---|---|

Then add:

- Main entry points
- Important modules
- Data/API flow
- Where to edit for the requested task
- Files not inspected / uncertainty

## Rules

- Do not modify files when using this skill unless the user also asks for edits.
- Do not scan huge generated folders such as `node_modules`, `dist`, `build`, `.git`, or minified files.
- Prefer targeted search over opening many files.
- Be explicit when the map is partial.
