# 02 — Native PE / ELF / Mach-O

## 静态顺序

1. headers / sections / segments；
2. imports / exports / relocations / symbols；
3. strings 与 xref；
4. entrypoint / init / constructors；
5. 高价值函数的 caller/callee；
6. decompile；
7. 回到 disassembly 验证关键分支、算术、指针和调用约定。

## 反编译器使用原则

伪代码是“重建模型”，不是源码。以下情况必须回看汇编：

- integer width/sign；
- pointer arithmetic；
- switch/jump table；
- tail call；
- SIMD/crypto；
- exception/unwind；
- compiler intrinsic；
- decompiler 给出异常类型或控制流。

## Windows/PE

若去符号 PE 目标且 Ghidra/IDA/objdump/radare2/Capstone 均不可用，`scripts/native-triage.py` 可离线只读地恢复 PE x64 `.pdata` unwind 函数范围、imports、有限字符串和候选 IAT 字节位置；但不具有指令边界验证和反编译能力。应按 `references/29-stripped-native-toolchain.md` 把尚未证明的功能标注 Unknown，而不能从 `VirtualProtect` 等 import 单独推断执行了动态加载。

关注：

- imports 与 delay imports；
- TLS callbacks；
- resources/version；
- COM/WinRT；
- services/drivers；
- named pipe/RPC/ALPC/local IPC；
- updater/plugin/module loading。

## ELF

关注：

- dynamic symbols/PLT/GOT；
- constructors；
- rpath/runpath；
- capabilities；
- JNI/native service；
- daemon/config/protocol parser。

实际目标为 ELF32 MIPS、且具体问题要求恢复间接外部调用时，可**按需**使用 `scripts/native-call-targets.py`，依据文件中的 PT_DYNAMIC、GP、GOT、PLT Stub 和 dynsym 给出带前提的静态候选边（支持 LE/BE/缺节表），不能把候选映射当作实际可达性或完整 CFG。深层数据流/跨块寄存器和更广 ABI 仍优先使用已验证 Ghidra/angr 后端；详细限制见 `references/29-stripped-native-toolchain.md`。

## Mach-O

关注：

- load commands；
- ObjC selectors/classes；
- Swift metadata；
- entitlements/Frameworks；
- XPC/URL scheme/helper tools。

## 证据

函数结论至少绑定：地址/名称 + xref/caller + 关键反汇编或运行时事实。
