# 01 — Target Triage

## 目标

在 5–10 分钟内回答“这是什么、从哪里下手、是否需要隔离”。

## 最小检查

- SHA-256、文件大小、扩展名与 magic 是否一致；
- PE/ELF/Mach-O/DEX/ZIP/CLR/WASM/固件容器；
- x86/x64/ARM/ARM64；
- 签名、时间戳、build/version 元数据；
- sections/segments 熵和异常权限；
- imports/exports/symbols；
- embedded archives/resources；
- packer/runtime/language fingerprints。

## 高价值语言指纹

- Go：runtime/type metadata、长函数名或 build info；
- Rust：panic/formatting/lang item 痕迹；
- Swift/ObjC：metadata/selectors；
- .NET：CLR header/metadata；
- Electron：asar、Chromium/Node；
- Flutter：Dart/Flutter assets、AOT snapshot；
- Python：PyInstaller/pyc；
- WASM：`\0asm` magic、imports/exports。

## 隔离触发

未知来源二进制、APK、固件、文档或带自解压行为的样本，默认不在敏感工作目录直接执行。解析器本身也属于攻击面。

## 输出

```text
Target:
SHA256:
Format:
Arch:
Runtime/Language:
Protection:
Primary Route:
Reason:
Next 3 checks:
```
