# 10 — Dynamic Analysis

> 仅用于自有或明确授权目标的调试、兼容性研究与安全审计。

## 启用条件

动态分析必须回答一个具体问题，例如：

- 某参数运行时真实值；
- 某字符串何时出现；
- 哪个函数构造某请求；
- 某个分支在什么输入下变化；
- Java/ObjC/managed 与 native 边界传递什么；
- 某协议字段如何编码。

## 优先级

1. 应用自身日志或可观察 trace；
2. debugger breakpoint/watchpoint；
3. API/syscall/network trace；
4. 定点 instrumentation；
5. memory snapshot。

## 最小观测原则

只观测已通过静态分析定位的函数、方法、selector 或 API，并记录目标位置、参数、返回值、调用上下文、输入和时间。

## 单变量差分

```text
input A → observation A
input B → observation B
delta → update hypothesis
```

## 失败处理

连接或符号定位失败时，依次核对架构、权限、启动时机、符号/地址、运行时版本和目标进程，不随机修改大量环境变量。
