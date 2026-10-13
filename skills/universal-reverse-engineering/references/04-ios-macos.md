# 04 — iOS / macOS：Swift / ObjC 深度机制还原

这是通用逆向 Skill 的平台适配，不是第二套 Parser/Router/Harness。静态与来源证据优先；实际运行时观测必须满足用户授权、环境兼容和明确的待验证假设。

## 路由门槛

- IPA、已确认的 iOS/macOS 应用或 Framework：进入此平台参考。
- 独立 Mach-O：只有观察到 Swift metadata、ObjC metadata、Swift async 或 ObjC selector 证据，才将 iOS 专项叠加到 Native 分析；仅文件类型或用户提到 Swift 不足以触发。
- Swift / Objective-C 源码：须有实际 `.swift` 或 `.m/.mm` 文件以及 iOS target/Package/Xcode 项目证据，才以 `swift-source` 或 `objc-source` 搭配 `ios-target` 叠加本参考。纯 Objective-C UIKit 应正常进入此路由；不能因为没有 Swift 元数据就遗漏 ObjC 项目。源码优先代码调用与行为验证，不做无意义反编译。
- 结构化任务目标：swift-protocol-dispatch 选择控制流+结构恢复；swift-async-lifecycle 选择控制流+数据流；objc-swift-bridge 选择控制流+跨边界跟踪（仍需要已验证 interop 信号）；ios-runtime-dispatch 选择动态观测（仍需要具体假设及授权）。全部复用原 Router。

## 输入身份与最小静态地图

先固定 SHA256、Bundle ID/build（若 USB 上仅查到安装信息，须核对本地 IPA 内 `Info.plist` 的 Build；不一致时禁止跨 Build 拼接推论）、FAT slice/arm64/arm64e、Mach-O 载入命令、LC_BUILD_VERSION、LC_DYLD_CHAINED_FIXUPS、dSYM UUID、符号、Swift __swift5_* 元数据、ObjC class/method/selector/IMP、entitlements、Frameworks、实际调用入口。针对 IPA、Framework、dSYM、dyld shared cache，分别固定来源/版本，不能从不同 build 拼出一条链。按真实原始字节校对 VA 与 file offset；PAC 和未应用 dyld chained fixups 的静态地址只能标候选。

## 四条高价值深度分析链

1. **Swift Protocol / Witness / 泛型**：从 __swift5_proto、ConformanceDescriptor、类型/协议描述符、relative witness/accessor、resilient witness records 到 thunk 和具体方法指令/调用点。严格区分静态 Conformance、Accessor、编译期 Witness Pattern 与真正的运行时 Witness Table；泛型实例化、Existential、Associated Type 的动态槽位无法仅靠描述符证明。对照 Swift 官方 ABI 和 MetadataValues，再看原始字节。
2. **Swift Async / Actor / Task**：根据真实入口追踪 Task 构造、capture/context、swift_task_alloc、continuation、TY/TQ resume、swift_task_switch、任务结果/错误/取消、actor executor/MainActor 边界。静态 continuation 和分支只证明候选关系，不证明实际调度、时序、网络响应或 race。源码项目首先沿 State Owner、Task 生命周期和调用链追踪，不直接采用固定编译器布局假设。
3. **ObjC 动态派发与 Swift 桥**：ObjC class→method list/selector→IMP→Swift @objc thunk→Swift body/返回数据；对具体 objc_msgSend site 核对调用参数与 selector。静态 IMP 与导出名不证明 runtime receiver、method swizzling、category 覆盖或真实 dyld fixup；需要动态证据才得出最终派发结论。
4. **iOS 应用实际机制**：根据目标真正使用的框架，选择 UI 事件→ViewModel/Actor→Service/Repository→网络/本地存储/IPC→结果→UI 的有界路径，核对状态写入所有者、重复回调、取消、重试、跨线程返回和错误分支。Keychain、URLSession、WebView、TrollStore 等只能是待核实的候选，不默认所有 App 都存在。

## GitHub 专业参考与按需工具

- Swift ABI 真正的一手规范：https://github.com/swiftlang/swift/blob/main/docs/ABI/TypeMetadata.rst 和 https://github.com/swiftlang/swift/blob/main/include/swift/ABI/MetadataValues.h；需要符号 demangle 时优先已有本机专业工具，不由名字推出行为。
- blacktop/ipsw：https://github.com/blacktop/ipsw。已有并实际 smoke 过时，按实际目标使用 macho info 的 Swift/fixups 选项、swift-dump 或 dyld class-dump，核对独立输出；其中 Swift dump 是实验性功能，不假定完整泛型支持。无此工具时沿 Rizin/Capstone 等已有可用证据走，不自动安装。
- frida/frida-swift-bridge：https://github.com/frida/frida-swift-bridge；frida/frida-objc-bridge：https://github.com/frida/frida-objc-bridge。仅在授权可调试设备、兼容 bridge/运行时、目标调用点明确时用于 receiver/IMP、Swift metadata 与 Task 的最小观测；Swift bridge 仍具有实验性限制。默认先选应用日志和现有可调试构建；禁止未经额外授权自动安装、越狱、全局 Hook、变更设备服务/代理。
- 先实际检测专业工具存在、版本/依赖、权限与目标 Smoke；工具列在 GitHub 并不代表当前 Windows/USB 设备有对应能力。任何下载、附加运行进程或真机操作应与静态只读分析明确分离。

## 分级验收与停止条件

- L1：真实输入身份、架构、metadata/selector；仅识别。
- L2：原始字节与独立后端一致的具体静态调用/指针/continuation 候选；不可宣称 runtime。
- L3：同一个真实样本入口→具体函数/数据/状态路径，至少一个独立语义 Oracle 和错误地址/假 Witness/IMP/续体等负例通过；目标级静态深度 PASS。
- L4：同一个授权可运行 build 在真机/兼容运行时观测 receiver 与 IMP、动态 Witness/泛型实例或 Async continuation/executor，具真实输入变化和负例；USB 设备被发现、进程退出码为零、Frida 可连接、工具返回成功均不是 L4 的充分条件。

每条结论需有 Observation/Inference/Unknown、SHA/slice、地址、工具版本、证据、覆盖和必要停机条件。对未安装工具、不可调试 IPA、无法达到实际 Dispatch site 明确 PARTIAL/BLOCKED/UNKNOWN，不自动升级权限。现有真实固定样本证据在 research/live-tests/20261009-cross-platform/SWIFT-FOURTH-SPECIALTY-EVIDENCE.md：13 项正反测试证明的是该目标 L3 静态边界，不能继承为任意 iOS 16/17/18 运行时 L4。
