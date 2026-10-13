# 11 — Tool Selection

## 原则

选择“最短、可重复、可核验”的证据路径，而不是默认选择最复杂 GUI。

## 分层

### Triage
文件类型、哈希、字符串、归档结构、metadata、imports/exports。

### CLI / Headless
适合批量、脚本化、结构化输出和自动验收。

### GUI / Deep Analysis
适合人工理解复杂控制流、类型和交叉引用。

### Agent / MCP
适合让 Agent 调用已有分析数据库获取确定性的反编译、xref、类型、调用图等结果。

## 工具选择九问

1. 要回答哪个问题？
2. 能否离线完成？
3. 输入是什么？
4. 输出能否结构化？
5. 结果是否可重复？
6. 是否会修改样本或工程？
7. 处理不可信输入是否需要隔离？
8. 是否与现有工具重复？
9. 失败后的替代路径是什么？

## 无完整反汇编工具时的降级

先检查实际环境与分析数据库。可调用 `python scripts/native-triage.py <file-or-.b64> --max-items 24` 获取 PE64/ELF64 元数据和 stripped PE64 unwind 函数边界；若已有经过真实 smoke-test 的 Capstone，可额外使用 `--disasm-at <PE-RVA-or-ELF-VA> --max-instructions 12` 定点线性解码。两者均非反编译器或 CFG，候选字节位置与未验证可达性必须显式标注。没有解码后端时应报告 `deep_disassembly_status=UNAVAILABLE` 和尚未证明的行为。具体见 `references/29-stripped-native-toolchain.md`。

## 已有 REA 的按需复用（不是第二套 Skill）

先用现有 `scripts/preflight.ps1 -ToolNames rea` 定点检测可执行文件（支持 `-ToolNames rea,node` 一次查询），不要运行 `npx`、`setup` 或自动写入 Agent MCP 配置。返回 `readiness=discovered_unverified` 只表示 PATH 可发现；`smoke_validated=false` 与 `target_validated=false` 不得计入验收。REA 已就绪时才根据实际问题运行 `rea doctor --provider ghidra --json`（或 `rea providers --json`），对结果单独记录引擎是否健康及目标是否受支持。REA 在 Windows 上的部分 Reference Source 导入功能可能不支持，不能因 JS 分析可用就假设所有功能可用。仅当前问题确实需要模块图、IPC 或反编译时再调用已安装的工具：

- 静态 JS/Electron（允许本地文件读取时）：`rea analyze-javascript-application <authorized-path> --json`。先用现成文件/字符串搜索缩小范围；只在跨模块、preload/IPC 或 Source Map 关系影响结论时使用完整图分析。
- Native 二进制：先 `rea providers --json` 确认具体 Ghidra/IDA/Hopper provider 和目标支持，再使用 `rea function <path> <name-or-address> --provider <id> --json` 或小范围 `rea xrefs`；不要从包存在推断 engine ready。原生全量 `rea analyze` 会产生更大启动成本，只有确实需要时才用。
- 可重复的同输入分析：若目标字节、provider、选项完全一致且确有重用机会，使用 REA 已有 `--snapshot`，不开发本地第二套缓存。
- 读 CLI 退出码、响应的错误/警告/coverage 和 Evidence；退出码 0 也不等于全量证据完备。保存原始输出到授权任务目录，向 Agent 只提供经过有界筛选的证据和确切引用。缺失/不兼容时降级现有 CLI 或报告 Unknown，不自动安装。
- 运行时/浏览器捕获、代码变更、程序执行和重建验证依然要独立授权与假设；不会因为 REA 存在自动发生。

参照 REA 官方 `docs/cli.md` 和 `docs/mcp-contracts.md`；这些是适配方法，不复制其大量 MCP schemas。

## 非原生容器的最短证据路径

当问题仅需 WASM 导入导出、ASAR Archive Entry、APK DEX/ABI 清单而专用后端未就绪时，已有 `scripts/container-triage.py` 作为无依赖、无执行、限量 JSON 的第一阶段替代；不做 WASM 函数反编译、ASAR IPC 还原或 APK DEX/JNI 运行时证明。若专用后端已能更快提供等价的准确证据，优先现有后端而非重复解析。对于 Android 原生库，再按需求定点交 `scripts/native-triage.py`，不要全量递归解包所有成员。

## 按需升级到成熟深层引擎的门槛

Native CFG/SSA、跳转表和符号执行优先复用已就绪的 Ghidra/angr/Rizin，必须先确认具体目标架构和函数范围，再区分指令、基本块边、静态候选与运行时已证事实。`.NET` 高级异步/异常/混淆只有实际可用的 `ilspycmd`/专业去混淆器及独立样本 Oracle 才可标 L3；`ilspycmd` 不使用 `--ignore-decompilation-errors` 掩盖局部失败。Firmware 只有完整镜像与每层哈希、受限解包、init→service ELF 证据才可声称完整链；WASM 专业 `wasm-tools validate` 仅证明模块格式/类型有效，不证明 indirect-call 可达性或 Host 副作用。每条路径默认不启动全部引擎、不复制上游分析器。

## .NET/CIL 的受限方法字节证据（仅按需）

只有确认 PE CLR Header+Metadata Root 有效时，按 `references/05-dotnet.md` 使用 `scripts/dotnet-cil-triage.py` 对具体 MethodDef 读 IL/branch/token，做不执行目标的基础语义定位；高级 EH、async、反射或混淆仍需要已实际验证的专业后端和独立 Oracle。默认不对全部方法解析，不把 CIL 字节解码当作可达性、全部类型恢复或完整反编译。

## MIPS32 ELF 的只读间接调用专用恢复（不依赖工具安装）

只有当 ELF32 MIPS 的已固定目标问题需要恢复 GP/GOT/PLT 间接导入调用时，按 `references/29-stripped-native-toolchain.md` 调用 `python scripts/native-call-targets.py <sample-or-b64> --max-items 16`。此标准库程序可使用 PT_LOAD/PT_DYNAMIC 处理大小端及无节表输入，但对静态程序头、链接器 Stub、GP 值和未重定位 GOT 有严格前提；结果只是 Static Candidate，不是动态调用图。失败保持 Unknown，**不应自动对所有 native 文件扫描**。

## 隔离的本机反汇编后端

CLI/Python 包的名称或 `find_spec` 结果只能作为**发现线索**；必须使用已知 x86/x64 指令测试真实 decoder，再对样本特定 RVA 定点分析，并分别记录 `backend_ready`、`linear_decode`、`validated_instruction_boundary`、`verified_runtime_flow`。四者不能混同。

Windows 项目研究环境可使用可回滚的依赖 `research/toolchain/capstone-5.0.9`，该目录只供 Canonical 单独测试，不自动同步到 Agent；如需重新准备可显式运行 `python scripts/setup_native_capstone.py --install`。来源为 PyPI 的 capstone 5.0.9 Windows x64 wheel，SHA256 `732cedbbb56d42e723f14d7af6387f1454194a820b4b96b56d1e53f865ef85d0`，以 smoke-test 的实际结果决定可用性。Capstone 只负责解码，不是 Ghidra/IDA 等反编译后端，也不能单独解决 VM 动态状态。

## 有界查询与成本纪律

优先在工具端按 function/address/process/time 过滤、分页并返回 `count / coverage / truncated`。大型 Trace 不直接载入聊天上下文；先看总量，再取问题相关窗口。工具适配器记录真实可用性、具体版本、读写权限、输入与输出模式、失败原因、启动和调用成本。不可因为某个 MCP 名字在文档出现就推断其已安装。重复相同失败形态两次后停止参数微调，转为修正假设或受支持的备用路径。完整规则参见 `references/27-bounded-tool-and-context-budget.md`。

## 纪律

不要猜工具路径；不要因 MCP/Agent 存在就省略底层证据复核；模型生成的符号名和类型推断必须标注为推断。
