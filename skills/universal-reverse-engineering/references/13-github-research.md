# 13 — GitHub Research Notes

研究快照：2026-09-19。这里记录吸收的方法，不让外部仓库的全局规则接管本地技能包。

## reverse-skill

吸收：
- PRIMARY routing；
- tool capability index；
- Evidence → Finding → Path；
- routing/coherence regression；
- 多平台 specialist 拆分。

不直接照搬：
- 外部全局行为规则；
- 自动 bootstrap/自动安装大量工具；
- 与本地专项边界不一致的执行链。

## wshobson/agents

吸收 Progressive Disclosure：用 skill metadata 触发，总控正文保持紧凑，平台细节放 reference 按需加载。

## IDA / Ghidra / Binary Ninja MCP 项目

吸收共同点：
- 让 Agent 获取分析数据库中的确定性结果；
- decompile、xref、type、call graph、disassembly 相互验证；
- 地址、类型、数值和符号来源要可追溯；
- MCP 是接口层，不是事实替代品。

## Android RE 项目

吸收：
- dependency preflight；
- 多视角反编译/字节码互证；
- UI/功能 → 调用链 → 网络/API 的映射；
- APK/AAB/DEX/JAR 等输入分类。

## 本地已有内容

本包继续复用 `10-SRC-BugBounty-专项/03-移动端与逆向` 与 `06-GitHub工具图谱`，只把其中可跨平台复用的方法抽到本通用技能。

## 稳定核心

```text
Route-first
+ Progressive Disclosure
+ Deterministic Tool Evidence
+ Static-first
+ Hypothesis-driven Dynamic
+ Evidence→Finding→Path
+ Tool Supply-chain Isolation
```

## 2026-10-09 — Generic capability routing and independent Skill composition

- `zhaoxuya520/reverse-skill`: inspired unified route registry, capability disambiguation and negative/coherence tests. Do not copy a keyword-only router, autorun bootstrap or global security-harness directives.
- `wshobson/agents`: use metadata-driven progressive disclosure and independent specialist contracts; do not activate all of the pack.
- `magnus919/agent-skills`: use evidence handoff and explicit stop/entry conditions between *independent* skills. In our case architecture-review is optional, not a precondition or parent.
- `CodeGraphContext/CodeGraphContext`: optional source-code graph adapter for evidence-backed callers/dependencies; an external indexing service is not a required runtime.
- `joernio/joern`: optional deep code property graph/data-flow engine; availability is not integration or proof. Preserve existing unsupported boundary until tested.

Public source links: https://github.com/zhaoxuya520/reverse-skill ; https://github.com/wshobson/agents ; https://github.com/magnus919/agent-skills ; https://github.com/CodeGraphContext/CodeGraphContext ; https://github.com/joernio/joern

The result is a *generic reverse engineering skill with a composable capability registry*, not an Android/device-only reverse skill and not a merged architecture-reverse runtime. External code is not copied.

## 2026-10-09 — Broad survey, depth and efficiency methods

Research note (sample counts, selection caveats and detailed decisions): `research/20261009-large-source-efficiency-depth-review.md`. Seventeen GitHub discovery queries returned 362 *search-result slots* before deduplication; these are not 362 independent validated repositories. Additional Linux.do/看雪/Reddit/benchmark evidence was reviewed.

Adopted as method (not vendor code): `GeReV/ghidra-iterative-re` source provenance and mutation invariants; `morluto/rea` evidence and artifact identity; `newliver666/apk-reverse` failure gates and stop signals; `bethington/ghidra-mcp` bounded lazy tool retrieval; `cellebrite-labs/ghidra-rpc` server-side filtered searches; `amruth-sn/kong` call dependency context; `agentrebench/AgentRE-Bench` telemetry and deterministic scoring; 看雪 large trace indexed retrieval. New optional semantic capabilities: `trace-reduction`, `boundary-tracing`, `differential-verification` (all fail closed without observed prerequisites).

Avoided: whole security pack imports, automatic MCP installs/ports, global multi-agent daemon, wholesale reverse-engineering rewrite, unverified performance claims. Benchmarking with actual targets is separately required.
