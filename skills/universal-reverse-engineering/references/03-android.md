# 03 — Android

本文件提炼通用 Android 逆向；SRC 场景继续复用原目录：
`../../10-SRC-BugBounty-专项/03-移动端与逆向/skills/`

## 推荐顺序

```text
Manifest/resources
→ JADX 主反编译
→ APKTool/smali 互证
→ API/route/model/feature map
→ JNI/.so（仅高价值路径）
→ Frida 定点验证（必要时）
```

## 第一遍地图

- package/version/minSdk/targetSdk；
- exported components；
- permissions；
- deep/app links；
- network security config；
- WebView/bridge；
- Retrofit/OkHttp/gRPC/WebSocket；
- base URL / environment；
- auth/session model；
- feature flags；
- local storage；
- native libraries。

## 双视角原则

复杂 Java/Kotlin 代码可用 JADX + 另一 Java decompiler/字节码视角互证；关键结论必要时回 Smali。

## JNI

真实混合 ABI APK 可先用 `python scripts/container-triage.py <apk> --max-items 16` 只读确认 DEX 和 ARM32/ARM64/x86/x86-64 native 成员；需要证据时从授权副本提取指定 `.so` 后交 `scripts/native-triage.py` 读取 ELF32/ELF64 `.dynsym`（不自动执行）。先对齐 DEX `ACC_NATIVE` 方法及其类/签名与 `Java_...` 导出，必要时分析 `RegisterNatives` 动态绑定。此证据只是链接候选，不能从符号匹配推断真实运行时调用，更不能因为 APK 有四种 ABI 就全部动态执行。

先定位：

```text
Java native declaration
→ JNI binding/register
→ .so function
→ strings/xrefs/call graph
```

不要因为 APK 内有 .so 就全量 native 深挖。

## 动态分析

Frida 只用于具体问题：运行时参数、动态拼接、加解密边界、实际返回值、Java↔JNI 交互。避免全局 Hook。

## 输出

优先形成“客户端功能 → 调用链 → endpoint/protocol → trust assumption”的结构。
