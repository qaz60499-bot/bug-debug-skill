---
name: universal-reverse-engineering
description: Route authorized reverse-engineering work across native binaries, Android/iOS, .NET, thick clients, firmware, WASM/bytecode, obfuscated targets, Unity/IL2CPP, version diff, symbol recovery, structure recovery, and bounded function-level emulation. Use route-first, fingerprint-first, evidence-first, static-first analysis.
license: Local skill pack; external references retain their own licenses.
compatibility: Windows-first, cross-platform methodology; prefers CLI/headless/structured output when available.
metadata:
  version: "2.2.7"
  updated: "2026-10-10"
  user-invocable: true
  canonical: true
---

# 通用逆向工程总控

## 目标

把逆向任务固定为稳定流程：

```text
授权与目标问题
→ 任务语义 / 所需证据 / 用户深度与边界
→ 目标识别与必要 Artifact Fingerprint
→ Capability Router（平台适配 + 所需功能能力）
→ 按依赖加载与最小证据路径
→ 必要时增量追踪 / 定点验证
→ Observation / Inference / Unknown
→ Finding / Path / Stop
```

本技能是独立的、跨平台跨目标的通用逆向总控与能力路由层。逆向软件、源码、二进制、运行机制、数据流与协议均可使用；Android/iOS/设备不是其默认边界。架构审查、调试、测试等为独立可选协作技能，不是本技能的强制依赖，也不复制其内部实现。

## 核心原则

1. **Semantic route first**：先理解真正问题及所需证据，再根据已核验目标信号组合功能能力与平台适配；不按关键词直接启动工具。
2. **Fingerprint first**：跨样本、跨版本、跨平台前必须先固定 artifact identity。
3. **Evidence first**：结论必须能回到可复现证据。
4. **Static first**：先建立静态地图，再做必要的最小验证。
5. **Progressive disclosure**：只加载命中的 reference。
6. **Preserve originals**：原样本只读保存，分析副本和输出分离。
7. **Record uncertainty**：不能证明的内容保留为 Unknown。

## Evidence Contract

任何报告项必须分类：

- **Observation**：可复现事实，例如哈希、格式、地址、符号、xref、元数据、资源、运行时观测。
- **Inference**：由 Observation 推出的解释，例如函数语义、结构字段角色、框架归属、版本差异解释。
- **Unknown**：未被证明或仍有竞争解释的部分。

## 精准能力入口

从用户问题和证据生成任务描述，按 `routing.md` 进行语义能力路由。详见 `references/23-capability-routing.md`；`config/routing-v2.json` 是机器可检查的能力注册表。只有改路由、检查机器索引或需要复现实验时才读取完整配置/回归用例。可选只读规划器：`node scripts/route-capabilities.mjs --request <task.json> --compact`（精简输出）；输入中的 `needs` 由 Agent 结合任务与实际证据选定。对于状态追踪、数据流、调用链、协议、跨进程、版本比较等可明确归类的目标，也可附 `objectives` 让**同一个** Router 补齐最小能力；混合项目仅为本题确实涉及且已检查的子组件附 `artifact.surfaces: [{kind,evidenceRef}]`，例如浏览器扩展与 Native Messaging Host、APK 与已核实的 `.so`。来源/证据引用必须由 Agent 查真实项目核实；脚本不自行查磁盘、猜技术栈、执行工具或证明行为。详见 `routing.md` §3a。简单且路径明确的任务不必调用规划器；脚本只验证能力组合与前置条件，不执行分析工具。

**iOS/Swift 深层路由**：对于真实 Swift/ObjC Mach-O（不是所有 Mach-O），已验证对应 metadata/selector/async 信号时通过现有 Router 自动增加 iOS 参考；已核实 Swift **或纯 Objective-C** 源码且确属 iOS target 也可触发（分别核对 `swift-source` 或 `objc-source` 与 `ios-target`）。Swift protocol/Witness、Async/Actor、ObjC↔Swift bridge、运行时派发分别由结构化目标选择必要模块，并继续执行原来的动态授权门槛。具体静态深度 Oracle 与 GitHub 专业后端参考见 `references/04-ios-macos.md`，不增加 Swift parser/常驻工具。

`depth` 由用户提示词与证据需求控制，不分设简单/深度两个 Router。按需读取命中 reference，未知能力明确报 Unknown，不盲目启动全部工具。仅有实际观测的 Trace、跨运行时边界或至少两份可比案例，才允许额外激活 `trace-reduction`、`boundary-tracing`、`differential-verification`；无证据时保持 Unknown。工具查询优先服务端过滤与分页；只在确有后端需求时通过现有 `scripts/preflight.ps1 -ToolNames rea` 等方式定点检查，已安装的 REA 可按 `references/11-tool-selection.md` 作为可选 CLI/MCP 后端使用，禁止自动 setup / npx 下载；原始证据不得与 Agent 自己写入的注释互相佐证；长期任务按需保存可校验断点，不建立第二套常驻系统。若实际反汇编后端不可用，优先选用 `scripts/native-triage.py` 做受限证据提取；仅在现有 Capstone 经过真实 smoke-test 且目标地址已固定时，使用 `--disasm-at <PE_RVA-or-ELF_VA>` 进行有界线性解码，不可将其当成 CFG 或程序行为证明；未验证的指令级结论保持 Unknown；对真实 WASM/ASAR/APK，在无对应专业工具且仅需格式、导入导出或容器入口信息时，可按需运行 `scripts/container-triage.py`（只读、上限输出），Android `.so` 的 ELF32/ELF64 元数据与 JNI 导出再交现有 `native-triage.py`，不因存在 `.so` 就全量扫描；**仅当已核验目标是 MIPS32 ELF、具体问题需要 GOT/PLT 间接调用静态目标时**，再按 `references/29-stripped-native-toolchain.md` 调用无依赖、只读、受限的 `scripts/native-call-targets.py`（含大端/缺节表，通过 PT_DYNAMIC），仅报告 Static Candidate，不能把导入符号链接当成调用可达性、CFG、运行时行为或通用架构深度 PASS；`planCapabilities.status=planned` 只表示能力规划通过，不表示工具可用或逆向任务完成。路由报告中的 `verification` 明确区分历史样本级证据、当前工具未探测与目标语义未验收；历史样本通过不能自动迁移为新项目通过，也不能把格式识别或单层解包说成端到端逆向。

**.NET/CIL 受限深度入口**：只有实际 `managed_cli=true` 且本题要求方法级证据时，才调用 `python scripts/dotnet-cil-triage.py <PE-or-b64> --method <methodName> --max-methods 4 --max-instructions 128`，从原始 CLR Metadata/MethodDef/IL 读取字节、局部分支与托管方法 token；未支持的 opcode/EH、混淆/反射/运行时调用须明确 Unknown，不是 ILSpy/de4dot 替代品。详见 `references/05-dotnet.md`。

**WASM 按需调用链入口**：已确认 WASM v1 目标且当前问题需要某个函数的直接调用、Table/Element/`call_indirect` 静态关联时，先选定 local function index，再运行 `python scripts/wasm-call-targets.py <wasm-or-b64> --local-function <index>`。此工具只解析受界单函数和相关元数据；候选关系不证明控制流可达、运行时 Table 未变化、Host 交互或 L4。`table.set` 出现在聚焦函数、格式不支持或损坏时保持 Unsupported；详见 `references/08-wasm-bytecode-vm.md`。普通容器检查继续使用 `container-triage.py`，不触发此深层工具。

再按目标和功能能力加载对应 reference：

| 目标 | Reference |
|---|---|
| 未知文件/先分类 | `references/01-target-triage.md` |
| PE/ELF/Mach-O/native | `references/02-native-pe-elf-macho.md` |
| Android APK/AAB/DEX | `references/03-android.md` |
| iOS/macOS / Swift / ObjC（包含已识别 Swift/ObjC Mach-O 或 iOS Swift/ObjC 源码） | `references/04-ios-macos.md` |
| .NET/C# | `references/05-dotnet.md` |
| Electron/Flutter/厚客户端 | `references/06-electron-flutter-thick-client.md` |
| 固件/IoT | `references/07-firmware.md` |
| WASM/bytecode/自定义 VM | `references/08-wasm-bytecode-vm.md` |
| 壳/混淆/反分析 | `references/09-packed-obfuscated-anti-analysis.md` |
| 动态验证 | `references/10-dynamic-analysis.md` |
| 工具选择 | `references/11-tool-selection.md` |
| 证据与输出 | `references/12-evidence-model.md` |
| GitHub 方法吸收记录 | `references/13-github-research.md` |
| Evidence Contract | `references/14-evidence-contract.md` |
| Artifact Fingerprint | `references/15-artifact-identity.md` |
| Symbol Recovery | `references/16-symbol-recovery.md` |
| Structure Recovery | `references/17-structure-recovery.md` |
| Function-level Emulation | `references/18-function-level-emulation.md` |
| Unity / IL2CPP Route | `references/19-unity-il2cpp.md` |
| Version Diff | `references/20-version-diff.md` |
| Android Framework Routing | `references/21-android-framework-routing.md` |
| Routing SSoT / regression cases | `references/22-routing-ssot-regression.md` |
| 通用语义/能力路由 | `references/23-capability-routing.md` |
| 数据流/协议还原 | `references/24-data-flow-and-protocol.md` |
| 独立架构技能的可选协作 | `references/25-cross-skill-handoff.md` |
| 证据来源与分析断点 | `references/26-evidence-provenance-and-checkpoint.md` |
| 有界工具检索与上下文预算 | `references/27-bounded-tool-and-context-budget.md` |
| 大 Trace / 跨运行时 / 差分验证 | `references/28-deep-trace-boundary-and-differential.md` |
| 去符号 PE/ELF 无安装只读初筛 | `references/29-stripped-native-toolchain.md` |

## 正式任务可用性与验收边界

**正式使用的是按目标、按问题受限的逆向工作流，而不是所有目标全自动动态还原承诺。** 每个新目标必须经过：读取并固定真实样本身份 → 能力路由 → 使用当前环境实际可用的工具取得目标级证据 → 必要的独立负例或交叉校验 → 输出 Observation / Inference / Unknown。历史 4 个专项的测试结果只能证明已测试固定样本的边界，不会自动证明新目标通过。

- **可立即使用**：只读目标识别、路由、静态元数据、已适配格式的定点指令/方法级分析、证据溯源和受界语义恢复。`scripts/native-triage.py` 可自动发现 Canonical 已有的 scoped Capstone；轻量部署若没有该包，可由执行方以 `RE_CAPSTONE_ROOT` 指向已授权、已存在的 Capstone 目录；**不要求更改 PATH、在线安装或额外常驻服务**。实际目标解码必须成功，不能用“已发现工具”替代结果。
- **必须另行验证的能力**：任意 Native 间接调用/全程序 SSA、固件物理启动/Flash/网络协议真实交互、iOS Swift runtime Witness 实例化/ObjC 实际接收者派发/Async 调度。只有当授权目标与隔离环境存在，并实际观测到相应边界时，单独标记该动态假设的 PASS；否则该**案例的动态子结论**必须标记 PARTIAL/BLOCKED/UNKNOWN，不能把整个通用 Skill 误判为无法用于其他正常静态任务。
- **禁止假阳性**：daemon 父进程 exit(0)、编译文件中存在 Selector/Witness 描述符、GOT 静态链接、路由 `planned` 或历史回归全绿，均不能直接充当目标动态行为的成功证据。诊断工具能力缺失应明确降级或停止，不额外堆叠 Router/Harness。正式发布前检查当前生产测试、独立研究样本、按需真实入口 smoke 和全部受管 Agent manifest 哈希；例行普通任务不必每次重复全量四专项。

## 最小完成条件

一次任务产出与当前问题成比例的必要结果：

- 可追溯的目标身份（跨版本或二进制结论必须单独 Fingerprint）；
- 任务语义、已选能力以及跳过能力的理由；
- 只覆盖本题所需的 surface / flow / hypothesis（不是每次全量展开）；
- 关键 Observation / Inference / Unknown 和未验证边界；
- 有证据支持的 finding、必要的 next path 或停止条件。

修改/重新部署前执行 `node --test scripts/test-routing.mjs scripts/test-routing-hardening.mjs`，并同步 `routing.md`、配置、回归规则；不要改变其他 Agent 的身份、记忆与 Runtime。
