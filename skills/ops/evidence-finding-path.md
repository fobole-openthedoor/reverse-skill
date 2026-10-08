# Evidence → Finding → Path 证据链

> 灵感来自 Z3r0 Evidence Plane，落地为 **Markdown 字段契约**。  
> reverse-skill 特色：与 `docs-generator` 报告模板、`field-journal` 脱敏回写、可复现命令绑定。

## 1. Evidence（不可变观察）

每条证据独立一段或表行：

```markdown
### E-{nnn}
- title:
- observed_at:
- source_type: command | screenshot | file | log | memory | network | manual
- source_ref: {path or command id}
- content_hash: {sha256 of artifact if file, else n/a}
- artifact_path: {relative path under case root when content_hash is recorded, else n/a}
- repro_command: |
    {exact command}
- raw_excerpt: |
    {脱敏摘录}
- linked_workitem: WI-{nnn} | n/a
- supersedes: E-{nnn} | none
```

**MUST**：Finding 引用的 Evidence 至少 1 条；`repro_command` 第三方可跑或标明离线限制。

**CLI helper**（写入 `work/<case>/evidence/E-*.md`）：

```powershell
powershell -File skills/scripts/append-evidence.ps1 -CaseRoot work/<case> `
  -Id E-001 -Title "..." -ReproCommand "..." -Severity info -Status observed
```

When the evidence is a case-local file, pass `-ArtifactPath` to record a SHA-256 fixity value and a relative artifact path. Review the complete case graph before handoff:

```bash
python3 skills/case-review/scripts/review_case.py work/<case> --verify-hashes --strict
```

The review is read-only and checks scope fields, Evidence records, work item and timeline references, structured Findings, Paths, and artifact hash matches.

## 2. Finding（安全/逆向结论）

```markdown
### F-{nnn}
- title:
- severity: critical | high | medium | low | info | n/a_re
- category: vuln | misconfig | design | reverse_algo | bypass | other
- status: candidate | validated | false_positive | accepted_risk
- evidence_ids: [E-001, E-002]
- location: {file:line | addr | url | class.method}
- impact:
- confidence: high | medium | low
- repro_steps:
  1.
  2.
- remediation: {or n/a for pure RE}
- optional_attack: {ATT&CK ID or empty}
```

**MUST**：`evidence_ids` 非空；`status=validated` 时 confidence 不得为 low（除非标注 residual risk）。

## 3. Path（攻击路径 / 调用路径 / 解题路径）

统一叫 **Path**，按任务类型解释：

| 任务 | Path 含义 |
|------|-----------|
| 渗透 / 攻击链 | 攻击路径步骤 |
| 逆向 | 关键调用/数据流步骤 |
| CTF | 解题步骤 |

```markdown
### P-{nnn}
- title:
- path_type: attack | callflow | solve
- start:
- goal:
- steps:
  1. action: — evidence: E-xxx — finding: F-xxx | none
  2. action: — evidence: E-xxx — finding: F-yyy | none
- residual_risks:
```

**MUST**：每步可关联 Evidence；攻击路径终点 Finding 若声明「已拿权限/数据」必须有 validated 证据。

## 4. 报告中的位置

`docs-generator` 安全报告 **MUST** 含：

1. Scope 摘要（链到 case `scope.md`）  
2. Evidence 表或章节  
3. Findings 列表（含 evidence_ids）  
4. 至少 1 条 Path（攻击/调用/解题）  
5. Timeline 摘要（可选全文链到 `timeline.md`）

详见 `docs-generator/references/security-report-templates.md` 中 **Evidence Chain** 节。

## 5. field-journal 挂钩

回写 journal 时 **SHOULD** 摘录：

- 3 条内关键 Evidence id + 命令  
- 1 条核心 Finding  
- 可复用 Path 模式一句话  

完整敏感内容只在用户项目报告中；journal **MUST** 脱敏（`anonymization.md`）。

## 6. 与 Z3r0 的差异（特色）

| Z3r0 | reverse-skill |
|------|----------------|
| PG 不可变行 + API | Markdown 文件 + hash 字段 |
| UI 审阅队列 | 报告 + next-step 菜单 + journal |
| ATT&CK 深度绑定 | 可选标签，不强制 UI |


## Validated sufficiency (Issue #77 / R4*)

Global bind rule remains: every Finding references **>=1** Evidence.

Promotion to status=validated is stricter (decision cookbook):

| status | Evidence bar |
|--------|----------------|
| preliminary / candidate | >=1 (unchanged) |
| **validated** | **SHOULD >=2 independent** Evidence (best: 1 static + 1 dynamic). A single Evidence item alone MUST NOT silently promote to validated — keep candidate/preliminary, or record residual_risk + human confirm. |
| blocked promotion | record Evidence E-insufficient-evidence |

Full recipes: [nalysis-decision-framework.md](analysis-decision-framework.md) (R4*, R1, R41, R44).

## Weighted evidence scoring (confirmation rubric)

判定 Finding 的 `confidence` 与是否达到确认线时，按证据 family 加权，禁止"一条强证据定终身"，也禁止同族证据堆数量：

| family | 典型 Evidence | weight |
|--------|---------------|--------|
| behavioral | 调试器/Frida/trace 的运行时观察 | 1.0 |
| data_flow | 污点路径、切片、符号执行可达性 | 0.9 |
| structural | 反汇编/伪代码、CFG、调用关系核实 | 0.75 |
| constant_sig | 魔数/常量/字节签名匹配 | 0.6 |
| semantic | 嵌入相似、命名/角色推断（含 `rekit corpus`/`match` 结果） | 0.25 |

规则：

- 同 family 第 n 条证据按 `1/(1+ln n)` 折减，防重复计数；
- **确认线**（`confidence: high` / `rekit findings confirm` 前置条件）：综合分 ≥0.75，**且**至少 1 条 behavioral 或 data_flow 强族证据，**且**覆盖 ≥2 个不同 family，**且**反证合计 <0.2；
- 任一 family 反证 ≥0.8 → 直接驳回（标 `false_positive` 或回退 candidate），不得用支持证据对冲；
- semantic family **永远不能单独**支撑确认——相似度高不等于语义等价（与 `rekit match` 的"结构分不达标不给 HIGH"同源）；
- 达不到确认线但方向正确 → 保持 candidate，记录 residual_risk 与缺口（缺哪个 family 的证据）。

与上方 "Validated sufficiency" 的关系：该节是 Evidence **条数**硬规则，本节是 **质量/多样性**标尺，两者同时满足才可 validated。

## Evidence 分级轴与 limitations 必填（contract-level）

每条 Evidence 记录 SHOULD 标注两个正交轴（借鉴 REA 的 evidence envelope，见其 `src/domain/evidence.ts`）：

- **confidence（获取方式）**：`observed`（直接观察：反汇编字节、命令输出、文件内容）| `derived`（由观察推导：xref 归属、污点路径、调用图）| `inferred`（模式/语义猜测：rekit triage 排名、嵌入相似度、命名推断）
- **authority（权威来源）**：`shipped-artifact`（目标二进制本身）| `controlled-replay`（受控重放/动态调试）| `historical-reference`（历史源码/旧版符号）| `external-service`（威胁情报等外部源）| `analyst-inference`（分析者推断）

规则：

- 工具输出带 `confidence`/`limitations` 结构字段时（rekit ≥0.2.0 起），Evidence 记录 **MUST** 照抄这些字段；把 heuristic 输出写成 observed 事实 = 证据造假；
- `inferred` / `analyst-inference` 证据永远不能单独支撑 validated（与 semantic family 规则同源）；
- Finding 引用的 Evidence 若带工具声明的 limitations，Finding 正文 **MUST** 复述关键 limitation（防止"引用了结论就算免责"）；
- 分析引擎选择遵循 RULES.md「歧义即错误」：多引擎可用时显式选定并记入 scope.md，任务中禁止静默切换。
