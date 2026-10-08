---
name: architecture-review
description: Audit project architecture, redundant mechanisms, dependencies, async and parallel state management, runtime scripts and configuration, or module control relationships; safely simplify architecture when the user explicitly requests changes. 检查架构复杂度、冗余机制、异步并行状态、脚本配置，分析机制合并或保留功能的架构简化。Use native analyzers with reproducible evidence and explicit unknowns.
---

# Architecture Review

Audit is read-only. Select Simplify only when the current user has explicitly requested modifications; an unused/clone report never grants modification authority. Honor existing authorization without asking again.

## Execute

1. Identify the actual workspace, bounded paths and evidence question. Read applicable project instructions. Keep output in an explicit task directory **outside** the audited workspace; do not install tools or execute project scripts just to audit.
2. Write a request JSON using the example below. Invoke the executable with the Harness shell tool:

```powershell
node <absolute-path-to-architecture-review>/scripts/architecture.mjs audit --request <absolute-request.json>
```

```json
{
  "root": "D:/path/to/project",
  "goal": "检查入口、模块依赖和重复代码",
  "scope": ["src"],
  "taskDir": "D:/path/to/isolated-audit",
  "mode": "audit"
}
```

The rule router favors Native + existing control/runtime follow-up for duplicate *mechanism* responsibility, using Knip only for entry/unused/config evidence, jscpd for explicit duplicate *code*, and dependency-cruiser for dependency/cycle requests. It does not automatically run all analyzers. Use `plan` instead of `audit` to inspect the request, content snapshot and selected checks. Supply a literal `pattern` only for a concrete regex search question. Tool versions, options, stdout/stderr, native JSON pointers, snapshot and missing coverage remain in `result.json`; `audit.md` is a bounded display, not the whole evidence.

3. Read the returned report and relevant records in `result.json` using bounded reads. Follow raw pointers when interpreting a finding. Tool status and audit completeness are independent. Do not conclude that no finding means no complexity or that exit zero means the goal is answered.
4. For required delegated evidence, invoke the **existing** local skills through Codex: `repo-map` for a bounded structural map, `universal-reverse-engineering` for control/provenance, `bug-triage` and `test-and-verify` for observed concurrency/recovery. Pass goal, version, scope, input snapshot, raw references and the unanswered question. Their results must retain Observation / Inference / Unknown and runtime instance/time boundaries. These are Harness follow-ups, not CLI analyses already completed. Expand scope only to close a specific evidence gap; keep each expansion bounded by user scope/budget. Stop when evidence answers the goal, or report Unknown/Unsupported with the reason and next distinguishing check.
5. Explain confirmed architecture issues with source and native evidence; distinguish candidates, unresolved dynamic/config-driven paths, and checks not performed. Report actual coverage and capability limits. For Simplify, read [references/simplify.md](references/simplify.md) and use the existing safe-edit/debug/test workflows.

Read [references/native-tools.md](references/native-tools.md) when choosing configurations, assessing analyzer limitations or requesting deep analysis. Read [references/evidence.md](references/evidence.md) only for cache/provenance contracts or external executor integration. Load neither by default.

## Boundaries

- The helper is a one-shot CLI with native child-process transport; Harness callers may inject their executor. No Agent scheduler, permission system, retries, watchdog, context manager or background service is added.
- Native scope-bounded checks hash requested files plus root/ancestor configuration and lockfiles, not unrelated siblings. Knip and dependency-cruiser retain project-level content snapshots to protect native reachability/import/config semantics even when the display scope is one file. Project snapshots include ignored source/config and exclude generated/dependency directories; they are not proof of environmental or dynamic-import closure. Snapshots expose scanMode, scanPaths, outsideScope, hashed/discovered counts, budgets and skipped files. Only scope-bounded Native search can reuse verified task-local cache; non-native analyzers and incomplete snapshots cannot. External configuration/dependencies remain explicit Unknown where closure is not established.
- Reuse is confined to the supplied task directory and identical workspace/content/config/options/tool identity. Raw artifacts are immutable and hash checked. Failed/cancelled/timed-out/stale runs are not reusable. No shared latest-generation pointer exists.
- Native categories remain distinct: unused, import dependency, clone, data flow and runtime observation. Similar code alone does not prove duplicate responsibility. Preserve dynamic entry points, fallback/recovery, cancellation ownership and safety boundaries until verified.
- Aider RepoMap and CodeQL/Joern are not emulated. If a mature engine is unavailable or not integrated, report that boundary. The installed `repo-map` skill is a manual map, not an equivalent mature parser/ranking implementation.
