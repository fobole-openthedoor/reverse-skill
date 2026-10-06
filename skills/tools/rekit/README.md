# rekit — omp 逆向特化工具包

rekit 是随 reverse-skill 分发的 Python 工具(包代码在 `rekit/`,经 `python3 -m rekit` 调用),为 omp 逆向环境提供三件事:

1. **ELF 快速预检(triage)** — numpy 向量化扫描 + sha256 缓存,大二进制/固件秒级出排序候选,不必先开 Ghidra/IDA 全量分析。
2. **语义函数语料(corpus)** — fastembed 嵌入函数特征,自然语言搜函数;`match` 做跨版本候选预筛,是 binary-diff 的前置。
3. **findings registry** — SQLite 结构化发现登记,CWE 化条目可 confirm / export / import,与 field-journal 的叙事经验互补。

clean-room 实现,未使用 GPL 代码。

## 安装

```bash
# Linux / macOS / Kali
bash skills/tools/rekit/install.sh

# Windows
powershell -File skills/tools/rekit/install.ps1
```

install 脚本:pip 安装 `fastembed==0.8.1`(可选依赖)→ 在 `~/.local/bin/rekit`(Windows: `%USERPROFILE%\.local\bin\rekit.cmd`)写 shim → 预下载嵌入模型 → `rekit --version` 验证。幂等,可重复执行。

## 依赖

- 必需:python3.10+、numpy、capstone、lief
- 可选:fastembed — 缺失时 `corpus build/search/similar`、`match`、`findings similar` 不可用,其余子命令不受影响

## 子命令

| 命令 | 说明 |
|---|---|
| `rekit --version` | 打印版本 |
| `rekit scan <binary>` | 文件面扫描:格式/架构/段/熵/可疑区域 |
| `rekit funcs <binary>` | 函数清单(地址、大小、结构特征) |
| `rekit strings <binary>` | 向量化字符串提取 |
| `rekit xrefs <binary>` | 交叉引用 |
| `rekit calls <binary>` | 调用图 |
| `rekit disasm <binary>` | 反汇编切片 |
| `rekit triage <binary>` | 综合预检,输出排序后的候选函数(`-k` 控制数量) |
| `rekit corpus build <binary>` | 建立/更新该二进制的函数嵌入语料 |
| `rekit corpus search <binary> "<query>"` | 自然语言搜函数 |
| `rekit corpus similar <binary>` | 相似函数检索 |
| `rekit match <old> <new> [-k K]` | 跨版本候选匹配,输出带 confidence(HIGH/MEDIUM/LOW) |
| `rekit findings add / list / show` | 登记 / 列出 / 查看结构化发现 |
| `rekit findings confirm / unconfirm` | 确认状态流转 |
| `rekit findings search / similar` | 关键词 / 语义检索已有发现 |
| `rekit findings export / import` | 导出 / 导入(团队协作、跨机迁移) |

多数子命令支持 `--json`,供脚本与 agent 消费。

## 典型用法

大固件先圈候选,再精读:

```bash
rekit scan firmware.bin
rekit triage firmware.bin -k 20 --json              # 排序候选地址
rekit corpus search firmware.bin "xtea decrypt"     # 按概念搜函数
# → Ghidra/IDA 只精读候选地址
rekit findings add ...                              # 分析完沉淀结构化发现
```

binary-diff 前先机器预筛,省下 LLM 逐函数比对:

```bash
rekit match old.so new.so -k 50 --json
# HIGH/MEDIUM 直接采纳或抽检;LOW/无候选的函数才走 LLM 比对
```

## 缓存与数据

| 路径 | 用途 |
|---|---|
| `REKIT_HOME`(默认 `~/.cache/rekit`) | sha256 扫描缓存、嵌入语料、模型文件 |
| `REKIT_FINDINGS_DB`(默认 `~/.local/share/rekit/findings.db`) | findings SQLite 库 |

清缓存删 `REKIT_HOME` 即可;findings 库独立存放,不受影响。
