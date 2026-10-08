# rekit — omp 逆向特化工具包

当前版本 0.2.0。rekit 是随 reverse-skill 分发的 Python 工具(包代码在 `rekit/`,经 `python3 -m rekit` 调用),为 omp 逆向环境提供五件事:

1. **二进制快速预检(triage)** — ELF/PE 解析 + numpy 向量化扫描 + sha256 缓存,大二进制/固件秒级出排序候选,不必先开 Ghidra/IDA 全量分析。
2. **语义函数语料(corpus)** — fastembed 嵌入函数特征,自然语言搜函数;`match` 做跨版本候选预筛,是 binary-diff 的前置。
3. **findings registry** — SQLite 结构化发现登记,CWE 化条目可 confirm / export / import,与 field-journal 的叙事经验互补。
4. **crypto 小套件** — 滑窗熵图 + 重复密钥 XOR 恢复(keylen 猜测 / 列频率攻击 / crib 已知明文攻击),补固件自钥 XOR 解密缺口。
5. **electron 静态构图** — ASAR 完整性校验(inventory)与 Electron 安全边界提取(boundary:webPreferences / IPC 通道配对 / contextBridge 暴露面)。

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

## 格式支持

| 格式 | 架构 | 支持面 |
|---|---|---|
| ELF | x86-64 | 全量:PLT stub 反查、call graph(0xE8)、字符串 xref、endbr64/prologue 兜底 |
| ELF | arm64 | 部分:符号+PLT 函数表、BL call graph、adrp/add 字符串 xref(capstone 配对) |
| ELF | arm32 | 基础:符号函数表、字符串提取 |
| PE | x86-64 | imports(IAT 槽充当 PLT,含 import thunk 归并)、.pdata 函数表、导出、call graph(0xE8 + `ff 15`)、字符串 xref |
| Mach-O | — | 未支持 |

其他 PE 机器类型(ARM64 等):仍可扫描(字符串 / IAT imports / 导出 / .pdata),`arch` 报 `unknown` 并打印 warning,不做反汇编与调用图。

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
| `rekit crypto entropy <file>` | 滑窗 Shannon 熵图,定位高熵(加密/压缩)区域 |
| `rekit crypto xor <file>` | 重复密钥 XOR 恢复:keylen 猜测 / 列频率攻击 / 已知明文(crib)攻击 |
| `rekit electron inventory <app.asar|目录>` | ASAR 完整性校验:逐 entry 重算 SHA-256(含分块与 unpacked 伴生文件),contradictions 单列且绝不静默 |
| `rekit electron boundary <app.asar|目录>` | 提取安全边界:webPreferences、IPC 通道配对(paired/unpaired/ambiguous)、contextBridge key、危险模式 |

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

## crypto 小套件

固件 XOR 解密(cortex-m 自钥 XOR、FortiOS 升级包这类场景)的两步工作流:

```bash
# 1. 熵图定位高熵区(加密段熵 >= 7.2,明文/代码段远低于此)
rekit crypto entropy firmware.bin
#    → regions: 0x00012000-0x0008f000  peak 7.61

# 2a. 已知明文(魔数/固件头)恢复密钥 — crib 滑窗 + IoC 排名,对机器码明文同样稳健
rekit crypto xor firmware.bin --offset 0x12000 --magic 7f454c46
#    → #1 offset=0x0 keylen=16 ioc=0.0812 key=...

# 2b. 无已知明文:keylen Hamming 猜测 + 列频率攻击(面向文本/配置类明文)
rekit crypto xor firmware.bin --offset 0x12000 --size 0x10000

# 3. 用最优候选密钥导出解密区域(打印 sha256 供校验)
rekit crypto xor firmware.bin --offset 0x12000 --magic 7f454c46 --out fw.dec
```

- `--offset`/`--size` 支持 `0x` 前缀;`--magic`(hex)/`--magic-str`/`--crib` 三选一
- crib 候选按 IoC(重合指数)排名:真 key 还原明文结构,IoC 显著高于噪声;不受明文字节分布(文本 / 机器码 / 零填充)影响
- 无 crib 的列频率攻击依赖明文可打印性,机器码密集区域请走 crib 模式

## electron 静态构图

```bash
rekit electron inventory app.asar          # 逐 entry 校验 SHA-256(含 blocks 与 .asar.unpacked 伴生文件)
rekit electron boundary app.asar --json    # webPreferences / IPC 配对 / contextBridge / 危险模式
rekit electron boundary extracted_dir/     # 解包目录同样可用(inventory 的 integrity 标 n/a)
```

boundary 是正则级静态提取:动态拼接的通道名计入 `ambiguous`,压缩/打包代码(单行 >10KB)会追加一条 limitation。

## 证据字段约定(confidence / limitations)

`--json` 输出顶层统一携带两个证据字段(0.2.0 起):

- `confidence`: `"observed"` = 确定性提取(反汇编字节、字符串内容、ASAR 哈希校验);`"heuristic"` = 启发式推断(调用图、xref、triage 排名、boundary 正则提取)。
- `limitations`: 字符串数组,按实际数据来源动态给出,例如:
  - `direct calls only; indirect calls unresolved`(存在调用边时)
  - `approximate sites: disp32 sliding-window scan`(x86-64 xref)/ `ADRP+ADD linear pairing; ...`(arm64 xref)
  - `heuristic prologue scan used when no eh_frame/.pdata/symbols`(启发式函数发现占多数时)
  - `import calls remapped through MinGW thunks`(PE 发生 thunk 归并时)
  - `heuristic ranking, not a vulnerability verdict`(triage)

人类可读输出不改表格式,仅在 stderr 追加一行 `confidence=...; limitations: ...`。

## 缓存与数据

| 路径 | 用途 |
|---|---|
| `REKIT_HOME`(默认 `~/.cache/rekit`) | sha256 扫描缓存、嵌入语料、模型文件 |
| `REKIT_FINDINGS_DB`(默认 `~/.local/share/rekit/findings.db`) | findings SQLite 库 |

清缓存删 `REKIT_HOME` 即可;findings 库独立存放,不受影响。
扫描缓存与 corpus meta 均携带 `rekit_version`;rekit 升级后旧缓存自动失效重建(stderr 打 `cache invalidated by rekit version`)。
