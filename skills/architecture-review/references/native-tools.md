# Native tool routes

Prefer native Git/rg/read for localization; no semantic call graph is inferred from text hits. The helper retains source paths/lines and native stdout/stderr. Use a concrete pattern for symbols; inventory alone is insufficient to locate a symbol.

The three lightweight analyzers are resolved from an explicit `toolRoot`, target `node_modules`, then the skill's isolated `tools/node_modules`. No automatic installation happens during audit. Installed versions and native bin identities are recorded. `options.knipConfig`, `options.dependencyConfig` and `options.tsConfig` select actual project configurations. Native JavaScript/TypeScript configs execute as native tools normally do: review trust before invoking them; Audit authorization does not authorize arbitrary untrusted config execution.

Knip preserves native entry/project/workspace/plugin/resolver categories. Specify entries through real native config; do not replace resolution with an import regex. An unused file/export remains a candidate; dynamic loaders, package exports, production scripts and plugins require separate entry confirmation. Calibration status is documented in the delivery reports; do not infer reliability from counts or exit codes.

dependency-cruiser preserves module/edge/rule/dependency-type/dynamic/resolve/cycle fields. TS requires the actual native transpiler and relevant tsconfig. Type-only edges require native precompilation-dependency options. Variable dynamic import cannot be considered resolved just because no edge was emitted. Analyzer coverage and skipped languages remain explicit.

jscpd retains original report, clone pair endpoints, token/line thresholds and fragments. Use `jscpdMinTokens` / `jscpdMinLines` options only when they suit the question. Clone detection establishes textual similarity, not interchangeable responsibility. Reports are stored only under the isolated run directory.

RepoMap: no Aider mature parser/query/ranking/token-budget implementation is currently integrated. Use the installed manual `repo-map` skill when it answers a bounded structural question, and keep this distinction visible. Do not label a regex or import graph as Aider equivalence.

Control/runtime: use existing `universal-reverse-engineering`, `bug-triage`, `test-and-verify`; pass the concrete unanswered evidence question rather than recreating their procedures. Neither static imports nor arbitrary passing tests prove production task ownership, cancellation propagation or recovery.

CodeQL/Joern: availability probes alone do not constitute an execution adapter. Before deep execution verify native engine, license, platform, language, extractor/frontend/build chain, query/overlay/models, scope and resource budget. Preserve raw database/query/result references and unresolved/skipped paths. No engines are downloaded by this skill. Unintegrated native execution is explicitly Unsupported/Experimental, absent engines Unavailable; native deep-analysis verification and Swift SDK/build extraction remain Not Measured.
