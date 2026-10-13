# 12 — Evidence Model

## Evidence → Finding → Path

### Evidence

可直接复核的事实，例如：

- SHA-256；
- address/function；
- import/export；
- string + xref；
- decompiler location；
- disassembly location；
- runtime args/return；
- packet/frame；
- manifest/entitlement。

### Finding

对 Evidence 的解释，标记为：

- Confirmed；
- Strongly supported；
- Hypothesis；
- Unknown。

### Path

下一条最短动作，或明确“证据已足够，停止”。

## 来源独立性与长任务断点

每条 Evidence 可按原始样本、工具派生、Agent 提议、独立外部验证分层，标明指纹、工具版本、分析 DB 状态、原位置与截断范围。模型写回 Ghidra/IDA 的名称、类型或注释再被查询出来，仍然是同一推断的派生，不算独立证明。跨会话断点只保留可追溯依据，恢复时先验证样本和 DB 版本。细则见 `references/26-evidence-provenance-and-checkpoint.md`。

## Function Note

```text
Function:
Address:
Role:
Inputs:
Outputs:
Callers:
Callees:
Key xrefs:
Evidence:
Confidence:
Open questions:
```

## Finding Note

```text
ID:
Question:
Evidence:
Interpretation:
Counter-evidence:
Confidence:
Next minimal test:
Stop condition:
```

## 重命名纪律

任何函数/变量重命名都保留原地址/原符号、新名称、命名依据和 confidence，避免推断覆盖原始事实。
