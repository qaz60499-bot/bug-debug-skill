# Routing Matrix

## 0. Source of Truth

This file is the human-readable routing SSoT for `universal-reverse-engineering`.

Machine-checkable companion files:

- `config/routing-v2.json`
- `routing-regression-cases.md`

Any Agent/router copy must preserve these decisions:

- semantic intent + evidence-based capability selection before tool choice;
- artifact fingerprint before cross-version or cross-build claims;
- Observation / Inference / Unknown before Finding;
- dynamic analysis only as a bounded hypothesis test;
- framework-generated code must be separated from app-owned logic.

## 1. 先理解真实问题，再路由能力，不先选工具

```text
授权与用户问题
→ Task Descriptor：goal / scope / depth / constraints
→ 需要证明的机制与证据类型
→ 最小目标识别（artifact kind / verified signals / identity）
→ Capability Registry：功能能力 + 可选平台适配
→ 前置证据门槛 / 依赖拓扑 / 可用工具
→ 最小证据验证 / 按需升级 / 停止
```

`depth` 与 `scope` 是用户意图/验证强度，不是 Quick/Deep 两个路由。源码工程、运行机制、JS、协议、编译目标和硬件都只是可能的分析对象。不要把通用逆向技能变成移动/设备专用技能。

Do not use a high-power tool because it is available. Use it only when it answers the current smallest question. Clear small tasks can skip the planner; otherwise prefer `--compact` to avoid repeating execution-policy prose.

## 2. 目标适配路由（不是唯一功能能力）

| 信号 | PRIMARY | SECONDARY |
|---|---|---|
| Unknown file or mixed folder | triage | tool-selection |
| PE/EXE/DLL + native | native | packed/anti-analysis, dynamic |
| ELF/SO | native | protocol, dynamic |
| Mach-O (已见 Swift/ObjC metadata) | native + iOS reference overlay | witness/async/ObjC bridge；仅泛用 Mach-O 则 Native |
| APK/AAB/DEX | Android | Android framework route, native for `.so`, dynamic |
| IPA/App + ObjC/Swift | iOS/macOS | native, dynamic |
| CLR metadata / C# | .NET | packed/anti-analysis, Unity only with Unity evidence |
| Electron/asar/JS bundle | thick-client | protocol/API, native addon |
| Browser extension (CRX/unpacked manifest) | browser-extension / JS source | content/background messaging, native messaging only with evidence |
| IDE extension (VS Code/etc.) | ide-extension / JS source | extension host, webview/IPC, native host only with evidence |
| Flutter | thick-client | native for AOT/high-value path |
| bin/img/squashfs/UBI | firmware | native/protocol |
| wasm | WASM/VM | host imports, dynamic |
| custom bytecode/opcode dispatch | WASM/VM | native/dynamic |
| high-entropy section, abnormal entry, packer signature | packed/anti-analysis | native/dynamic |
| UnityPlayer, global-metadata.dat, il2cpp symbols, Unity assets | Unity/IL2CPP | native, Android/iOS route |
| two or more known versions/builds | version-diff | symbol/structure recovery |
| small pure transform/checksum/decoder function | function-level-emulation | native/dynamic |

## 3. 任务驱动能力组合（可选多个，不默认全开）

- “软件这个行为机制如何运作？” → 真实入口/状态所有者 → 控制与数据流 → 必要时动态验证。
- “它调用了什么服务/协议？” → strings/imports → xref → network/protocol。
- “这个函数到底做什么？” → decompile → callers/callees → types → disassembly verify。
- “值从哪来/到哪去？” → data flow / xref / runtime watch。
- “长 Trace / 超大日志如何还原状态？” → 已识别 traceArtifact → trace-reduction → 有界查询与因果校验。
- “消息跨进程、语言或 IPC 为什么变化？” → 已验证边界信号 → data-flow → boundary-tracing。
- “两个受控输入/观测有什么真正不同？” → 两个独立案例 → differential-verification；版本比较另需 version-diff 的独立 Fingerprint。
- “为什么静态看不到？” → unpack/decrypt-at-runtime hypothesis。
- “为什么行为只在运行时出现？” → dynamic。
- “客户端隐藏了哪些接口？” → platform static map → endpoint/route extraction。
- “这是编译器噪声还是业务逻辑？” → language/runtime fingerprints + cross-decompiler check。
- “命名太差无法导航？” → Symbol Recovery。
- “去符号 PE 目标且原生反汇编后端缺失？” → 静态证据/函数边界可选 `scripts/native-triage.py`；已有验证通过的 Capstone 后端时可选 `--disasm-at <RVA>` 限量解码。候选 IAT 调用与线性解码均不等于真实可达调用图；指令语义未证实则保留 Unknown。
- “字段/对象看不懂？” → Structure Recovery。
- “版本之间改了什么？” → Artifact Fingerprint for each version → Version Diff。
- “Android 混合框架？” → Android Framework Routing → generated/app-owned separation。
- “WASM/ASAR/APK 没有可用专用工具，先看目标结构？” → 已固定 SHA 的真实文件 → 现有 `scripts/container-triage.py` 按需获取结构/导入导出/原生 ABI；需行为语义时升级既有平台模块，不能把元数据认作完整逆向。
- “APK 的 Java/Kotlin native 如何连接 ELF？” → DEX native 方法声明 → `.so` ELF32/ELF64 `.dynsym` JNI 导出 → 对齐架构/签名 → 必要时定点调用流证据，绝不从 `.so` 存在直接推断执行。
- “Unity/IL2CPP？” → Unity evidence check → IL2CPP metadata/native bridge route。

## 3a. 项目级语义目标与多技术层（原 Router 的增量输入）

Agent 先检查真实项目，再选 `needs`；如果目标可以明确归类，可选提供 `objectives`，由同一个规划器补齐**最少**已登记的能力依赖。两者可并存，不匹配任何已知调查目标时继续人工语义判断，禁止从文件后缀/问题关键词直接推断所有能力。可用目标：`identify-target`, `explain-call-chain`, `trace-data`, `explain-state`, `reconstruct-protocol`, `trace-runtime-boundary`, `compare-builds`, `observe-runtime`, `recover-algorithm`。例：Working 卡住→已确认状态问题→`explain-state`→control-flow + data-flow；这不自动触发 `dynamic-observation`。

主 `artifact.kind` 描述当前主要项目。只有实际检查过、与本题关联的跨栈子组件，才列在 `artifact.surfaces: [{kind, evidenceRef}]`；`evidenceRef` 必须指向真实文件/哈希/位置，不能用模型猜的文字代替实证。比如 Chrome Extension 的 service worker→Native Messaging Host，可把 `browser-extension` 作为主对象，并为已查明的 host EXE 附 `binary-pe` surface；Android JNI 可附 `binary-elf`；Electron 仅调查 UI 时不加入无关 native addon。任何 surface 未知或缺证据 → partial + triage，不装载那一层 reference。规划器只检查结构，不自行读取或验证 evidenceRef；执行 Agent 必须核对真实磁盘证据。

`objectives` 和 `surfaces` 都是**可选的原 Router 字段**，不是新的语义分类器、第二层 Router、独立模型调用或自动扫描；未知自然语言需求仍先做有限 triage。验证过路线 ≠ 工具后端已就绪 ≠ 项目逆向完成。

## 3b. Swift / iOS 的证据驱动专项深化

单个 Swift Mach-O 的通用 Native reference 不足以指导 Witness/Async/ObjC 深度还原；已有的 `platform_evidence_overlays` 仅在 `binary-macho` 实查 `swift-metadata` / `objc-metadata` / `swift-async` / `objc-selector` 时**额外加载** `references/04-ios-macos.md`；当源码项目同时观测 `swift-source` + `ios-target`，或 `objc-source` + `ios-target` 时也加载；纯 Objective-C UIKit 工程不能误走仅通用 Source 路由。覆盖层仅补参考，不执行工具、不改变主 artifact.kind，未知信号不加载。按目标选 `swift-protocol-dispatch` / `swift-async-lifecycle` / `objc-swift-bridge` / `ios-runtime-dispatch`；后两者仍严格服从 interop/动态授权门槛。泛型 Witness runtime table、ObjC 真实 receiver 和 Swift task 调度无真机证据时为 Unknown。此增强只更新现有 Semantic Router，不构成新专项运行时或第二套工具链。

## 4. Evidence gates

Before accepting a finding:

1. At least one decisive Observation is recorded.
2. Decompiler output is cross-checked against lower-level evidence when it is central.
3. Inferences name their supporting Observation IDs and confidence.
4. Unknowns remain visible instead of being guessed away.
5. Cross-version evidence is never merged without separate fingerprints.

## 5. 禁止的路由错误

- APK 一上来全局 Frida Hook。
- native 文件只看 decompiler，不看汇编/xref。
- 看到 UPX/混淆就立刻尝试 patch；先判断是否需要解壳才能回答问题。
- 为了“工具高级”而从 CLI 切到 GUI。
- 反编译器输出冲突时，靠猜测选一个；应回到底层字节/汇编/运行时证据。
- 看到 C# 或 metadata 就直接判定 Unity。
- 把 framework-generated glue 当作业务逻辑。
- 把一个 build 的结构/符号结论套到另一个 build。
- 用 function-level emulation 结果代表完整应用行为。

## 6. Cross-route

一个任务可保留一个目标适配 PRIMARY，同时选择多个功能能力。功能能力不是“SECONDARY=不重要”，而是依据具体目标决定：

```text
Android → framework route → JNI .so → native → runtime parameter → dynamic
Electron → IPC → native addon → native
Firmware → filesystem → service ELF → native → proprietary protocol
.NET → native interop → native
Unity/IL2CPP → metadata → native function map → platform route
WASM → host imports → JS/native host
Version diff → symbol recovery → structure recovery → targeted dynamic check
```

## 7. 独立技能的可选配合

- `architecture-review` 与本逆向技能各自独立，既不合并路由，也不复制实现。
- 仅当用户要求结构评审，或逆向证据出现状态所有权、重复控制器、异步恢复等跨模块结构性问题时，才建议专项协作。
- `architecture-review` 交来的文件/依赖候选仍属结构性线索，不等于低层行为已被证明；本技能只处理需要还原的具体机制。
- 交接使用 `references/25-cross-skill-handoff.md`，保留各自 workspace / snapshot / runtime instance / Observation-Inference-Unknown，不创建第二套 Router / daemon。

## 8. 结构化能力匹配约束

`config/routing-v2.json` 登记能力 ID、依赖、证据门槛和 reference 路径。由 Agent 根据真实任务语义产生所需能力列表；`scripts/route-capabilities.mjs` 只检查其可用性并按依赖组织，不是自然语言关键词分类器，也不会自动调用外部 Skills。

- 未知目标：只做有限 triage，不启动所有模块。
- 项目分类应基于实际入口、manifest/magic、依赖与原始工件证据，不能由文件扩展名、用户提到的工具名或运行平台单独决定；源代码项目按待解释机制选能力，不强行反编译。
- 任务同时涉及几个实际运行时，使用**有范围**的 `artifact.surfaces` 明确所需适配；不要对仓库内全部语言、依赖、二进制做无关广域扫描。
- 通过 Agent 识别的 `objectives` 补最少的候选 `needs`，仍服从原有授权、指纹、动态及跨边界证据门槛；规划成功不是语义理解准确率测量。
- 混淆 / 加壳：需实际观测到保护信号才进入 deobfuscation。
- Dynamic：需明确运行时假设及可执行授权。
- Unity/IL2CPP：需可靠框架证据，不能从 C# 文本猜测。
- Version Diff：每份样本单独 Fingerprint 后才比较。
- Source-control/Protocol：围绕问题局部追踪，不要求先做完整设备或平台分析。
- 结束后只报告已经得到的证据、范围缺口和必要下一步，禁止因深度要求而无边界扩展。
- 大型 Trace 优先索引/分页/限定范围，过宽查询返回命中数与截断提示，不把整个结果塞进上下文。
- 反编译数据库中的 Agent 旧注释属于推断来源，不可用于独立证实同一推断；详见 `references/26-evidence-provenance-and-checkpoint.md`。
- 工具选择记录可用性、只读/修改属性、输出体积、失效原因及替代路径；按需用已有 `scripts/preflight.ps1 -ToolNames rea` 等检查目标后端。REA 只作为已安装时的可选 CLI/MCP 后端，不自动 setup、下载、注册或替换 Router；相同失败形态重复两次后停止盲目调参；详见 `references/11-tool-selection.md` 和 `references/27-bounded-tool-and-context-budget.md`。
- 在没有专用格式后端时，WASM/ASAR/APK 可优先用只读 `scripts/container-triage.py` 作容量有限的第一遍地图；只有需要具体函数/IPC/JNI 路径时才升级到相应分析工具。对 stripped native，优先读 PE unwind/ELF32/ELF64 元数据、动态导出与有界字符串；如无真实反汇编/反编译后端，不允许把能力规划成功、导入存在或字节候选匹配报告为完整行为已还原。详见 `references/29-stripped-native-toolchain.md`。

## 9. 跨平台验证等级（防止逐项目修补与验收越级）

`config/routing-v2.json.fixture_validation.by_artifact` 记录**历史样本的最高验证层次**，不声明所有新样本可用，更不代表当前后端已安装。机器规划同时报告 `verification`：`fixtureLevel` 只是过往案例，`backend=not_probed` 只说明规划器从未验证后端，`currentTarget=unverified` 表示新目标尚未验收。严格区分：**格式识别 → 指令/符号/关联 → 可重现的局部语义 → 完整端到端语义**。任一步证据不足，应保留 Unknown 或标记 Unsupported；不能用更多测试通过数量代替深度正确率。新增平台/能力必须有独立真实样本与阴性输入的对应证据，未验证平台只能登记 `routing_only`。

## 10. Regression expectations

The routing must pass the cases in `routing-regression-cases.md`. If a new rule changes behavior, update both this file and the regression cases in the same change.
