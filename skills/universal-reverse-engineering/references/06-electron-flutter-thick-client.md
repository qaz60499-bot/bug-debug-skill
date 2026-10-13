# 06 — Electron / Flutter / Thick Client

> 用于自有或明确授权客户端的兼容性、安全与行为分析。

## Electron

按信任边界建立地图：

```text
Web/Remote Content
↔ Renderer
↔ preload/contextBridge
↔ IPC
↔ Main
↔ OS/native capability
```

优先读取 app.asar/bundle/source map、preload、IPC channel、contextIsolation、custom protocol、updater、配置和 native addon。结论必须绑定实际代码位置和调用关系。先用本机文件/字符串检索回答局部问题；只有需要跨模块的 preload → IPC → main 调用证据时，才尝试现有 REA 的静态 `analyze-javascript-application`（参见 `references/11-tool-selection.md`）。其未安装或输出不完整时回退原有静态链路，不能直接升格为动态运行；重建功能必须以独立输入/输出或可复现实验验证。

若仅需 ASAR 包内文件/偏移，已有 `@electron/asar` 优先；不存在时可用 `scripts/container-triage.py <app.asar> --max-items 16` 做有界只读列举。Pickle Header 的 JSON 字节长度、对齐填充和数据开始位置必须分别验证；不得将不合理 offset 的内容当 JS，亦不得跟随 archive 内 symlink。文件存在不等于 preload/IPC 调用链完整，复杂路径仍需原有 JS/REA 有限分析。

## Browser / IDE extensions（并非 Electron 的别名）

对于浏览器扩展，先核对真正的 `manifest.json`、MV2/MV3、background/service worker、content script、page script、permissions/host permissions、web-accessible resources、storage 和消息入口；追踪 UI/content → worker → network/storage，只有观测到真实 nativeMessaging host manifest、进程或调用证据才增加 Native/跨进程分支。不要把文件内提到某个 API 当成运行时调用证明，也不要仅因 CRX/ZIP 名称就假定可安全执行。

对于 VS Code 等 IDE 扩展，核对扩展 manifest/`package.json` 的 `main`/`browser`/activation events、Extension Host、Webview 消息与实际宿主执行边界。仅当存在被本任务触及的 native helper、子进程或 IPC 证据才追加 Native/Boundary adapter。源码通常先按真实入口追踪，既不默认 Electron，也不做无意义反编译。

## Flutter

优先 assets/config、API host、route/deeplink、feature flag、platform channel、WebView 和 network behavior。只有这些信息不足以回答当前问题时，才继续分析 AOT/native 部分。

## 其他厚客户端

先识别 .NET、Qt、Java 或 native 技术栈，再切换对应 reference。共同记录 updater、plugin/module、file import/export、local IPC、custom URI、WebView/native bridge 与协议/API。

## 本地复用

可继续读取：
`../../10-SRC-BugBounty-专项/03-移动端与逆向/skills/Flutter-Electron-桌面客户端攻击面.md`
