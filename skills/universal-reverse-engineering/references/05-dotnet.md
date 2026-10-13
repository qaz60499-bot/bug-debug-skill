# 05 — .NET / C#

> 用于自有软件、获得授权的软件分析、兼容性调试与安全审计。

## 分析顺序

1. 读取 CLR 与程序集元数据。
2. 建立 namespace、type、entrypoint、resource 与配置地图。
3. 使用反编译结果理解业务结构。
4. 沿调用关系定位与当前问题直接相关的代码。
5. 对重要判断回到 IL 做一致性核对。

## 无 CLR Runtime 的可移植 MethodDef/CIL 局部后端

仅当先前实际 PE 元数据证明 `managed_cli=true`、且本题需要方法级证据时，可按需运行标准库只读解析：

```bash
python scripts/dotnet-cil-triage.py <CLR-PE-or-explicit-b64> --method Main --max-methods 4 --max-instructions 128
```

这个工具通过 PE Section 映射真实 CLR Metadata Root，读取 #~/#Strings、TypeDef/MethodDef、Tiny/Fat IL 头、受限指令/branch target/token；不执行目标、不开端口、不安装依赖。严格区分 `STATIC_IL_DECODED`、`STATIC_IL_PARTIAL`、`METHOD_NOT_FOUND` 和 `REJECTED`。不支持的 IL OpCode 和异常处理语义必须标 Unknown，不可把 MethodDef token 匹配当成动态反射/代理调用确定性、不能将它当作完整 CFG/反编译、de4dot/ILSpy、async/混淆去除。只有要回答的问题确实需高级数据流时才检查已就绪的 ILSpy/de4dot/专业后端；不得默认安装。测试：`python -m unittest discover -s scripts -p test_dotnet_cil_triage.py -v`（Agent 合成例可运行，真实研究样本只在 Canonical）。

## 高级语义验证门槛

遇到异常处理、异步状态机与复杂方法控制流时，优先选用实际可用的 ILSpyCmd，保留程序集 SHA256、IL offset、反编译结果与失败区域。高级工具的退出码成功或生成 C# 并不等于原始程序行为已验证；还需要独立样本及可复现的外部结果。若工具未就绪，继续保持 Unknown，不将基础 IL 解析宣称为完整语义恢复。

## 关注区域

- 网络/API 客户端；
- 配置与资源；
- 序列化模型；
- managed/native interop；
- updater/plugin；
- local IPC；
- feature/config state。

## 输出

记录程序集、类型、方法、调用关系、证据位置、置信度和仍未确认的问题。只分析回答当前问题所需范围，避免无目的全量展开。
