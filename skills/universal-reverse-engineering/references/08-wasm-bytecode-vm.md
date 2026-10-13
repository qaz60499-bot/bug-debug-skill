# 08 — WASM / Bytecode / Custom VM

> 用于自有或明确授权程序的格式理解、互操作、调试和安全审计。

## WASM

先记录 imports/exports、function/type table、memory/table、data segments、custom/name sections 与 host bindings。重点理解模块与宿主之间的数据和能力边界。若当前只需要确认结构且没有可用 WABT 等后端，使用现有 `scripts/container-triage.py <module.wasm> --max-items 16` 只读固定 section、函数体数量、imports/exports；不实例化或运行模块。结构结果绝不能被当成计算语义。遇到单个函数体极大（例如 5 KB+ 的扁平状态机）时只路由具体函数的控制流/数据流与已授权验证；没有反编译器/语义证据就保留 Unknown，禁止猜测算法或声称已破解。

## WASM 函数级静态分析

按需运行 `scripts/wasm-call-targets.py`，通过 `--local-function` 指定本地函数索引，核查 Type、Import、Table、Element、call_indirect。仅输出静态候选；动态 Table 写入、未支持的指令或非法节顺序均不能升级为已验证调用。普通容器初筛仍使用 container-triage。运行时行为需独立 Oracle。

## 专业 Validator 的边界

若 `wasm-tools` 在本机经过实际验证且有模块级语义需求，可以在隔离环境对已固定 SHA256 的样本运行 `wasm-tools validate`，并对指定函数使用 `print`/`dump` 交叉核对。模块格式和类型验证通过并不证明 Table 未被其他函数或宿主修改，也不证明调用路径可达；必须独立记录 Host Import 与 Memory 的输入输出证据。没有专业工具时仍按上节的受限本地分析并保留 Unknown，不安装额外默认运行时。

## Bytecode

先确定：

- 指令宽度；
- operand encoding；
- stack/register model；
- constant pool；
- branch/call encoding；
- exception/state model。

## Custom VM

从解释器主循环的结构入手，逐步建立 opcode 表。每条记录：

`opcode / operands / stack effect / state effect / branch semantics / evidence location`

先证明少量核心 opcode，再扩展；不要一开始就尝试生成完整反编译器。

## 运行时观测

当静态结构无法确认状态变化时，可对自有/授权样本做最小 trace，并把 trace 与具体 opcode/函数证据关联。
