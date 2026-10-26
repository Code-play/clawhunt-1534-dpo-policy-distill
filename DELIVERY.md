# 交付清单与验收对照（订单 #1534 企业 Agent 系统 47/50｜DPO 偏好与 Policy 蒸馏）

本文件回答四件事：交付了什么（逐文件职责）、验收怎么对上（逐条对照）、怎么复现（命令与预期）、
证据在哪（产物与记录的位置）。

## 一、交付清单

### 1. 配置（6 份 JSON，唯一事实来源）

| 文件 | 职责 | 关键内容 |
|---|---|---|
| `config/pipeline_config.json` | 流水线总口径 | 版本 `dpo-policy-1.0.0`；逻辑时钟起点 `2026-10-26T00:00:00Z` + 步长 30s；来源策略（许可白名单/黑名单）；脱敏 salt 与残留策略 `block`；偏好对 9 条筛选口径；蒸馏适配器与目标类型；回归配置入口 |
| `config/source_registry.json` | 授权登记表（6 条来源） | `source_id + version` 主键、许可（customer-authorized / internal-approved）、内容指纹、授权编号 `AUTH-2026-0041..0046`、生效日期、留存天数 |
| `config/redaction_rules.json` | 脱敏规则 | 9 条替换规则（邮箱/手机/身份证/银行卡/IP/令牌/带凭据 URL/人名/机构名）+ 8 条残留检测模式（含刻意未覆盖的 `wechat_id`）+ 策略 `block` |
| `config/policy_rules.json` | 策略规则库（8 条） | `R-CITE-01` 引用可回溯、`R-AUTH-01` 未授权拒绝、`R-PII-01` 脱敏前置、`R-REFUSE-02` 缺证不猜、`R-VER-01` 版本锁定、`R-PREF-01` 偏好对可解释、`R-DISTILL-02` 蒸馏依据可读、`R-REG-01` 离线回归闸门 |
| `config/regression_config.json` | 回归判据 | 引用标记格式 `[S:<source_id>@<version>]`；两种"答不了"的动作映射；泄漏口径；闸门阈值（通过率 >= 90%、回退 <= 0）；基线（14/16、违规 2）与逐例基线结果 |
| `config/report_templates/regression_report.md.tpl` | 回归报告模板（订单验收项） | 结论、逐例表、基线对比、失败明细、判据来源、复跑方式；占位符未填完会直接报错 |

配置在加载期做三层校验（文件可解析 -> 单文件自洽 -> 跨文件一致）：枚举取值、数值区间、正则可编译、
主键唯一、时刻可解析、许可白名单与黑名单不重叠、蒸馏/回归引用的规则必须存在于规则库。
任何一处写错都在启动阶段抛 `CONFIG_INVALID`（退出码 3），不会被伪装成"数据不达标"。

### 2. 实现（`dpo_policy/`，11 个模块）

| 模块 | 职责 |
|---|---|
| `model.py` | 五类记录（来源/候选/偏好对/三元组/策略卡）、回归结果类型、规范化 JSON、两层哈希口径、逻辑时钟、稳定错误码与退出码映射 |
| `config.py` | 三份配置 + 三份登记表的加载、三层校验、交叉校验、口径摘要 |
| `provenance.py` | 授权与版本闸门：白名单解析、版本/指纹/许可/授权编号四类拒绝、语料批量复核、登记表统计 |
| `anonymize.py` | 稳定伪名脱敏（重叠匹配按长优先）、深层映射、残留扫描、block 模式整条拒绝、映射摘要 |
| `pairs.py` | 偏好对构建：候选校验、脱敏、九条筛选规则、决定性对比轴、跨轴反超、去重、漏斗统计 |
| `distill.py` | 两种轨迹适配器（messages / tool_trace）、三元组生成、目标类型判定、依据压缩、规则聚合为策略卡 |
| `regression.py` | 策略引擎（三值动作）、逐例判定（六类稳定违规 token）、汇总指标、基线对比、闸门判定 |
| `validate.py` | 记录级字段校验（类型/长度/枚举/正则/引用/指纹/时刻），产物写盘前统一过检 |
| `store.py` | 只追加 JSONL、原子落盘、单进程只允许一次 flush、产物清单与字节数 |
| `report.py` | 三类 Markdown 报告（偏好对审计 / 策略卡 / 回归报告），模板填充带残留占位符检测 |
| `cli.py` | 六个子命令与 demo 主流程；退出码 0/2/3；`--out-dir` `--var-dir` `--samples-dir` 支持隔离复跑 |

### 3. 样例（`samples/`，8 份文件）

| 文件 | 内容 | 期望结果 |
|---|---|---|
| `sources.jsonl` | 6 篇授权资料（工单分级/退款口径/脱敏规范/故障手册/客服禁区/合同条款） | 6 条全部通过授权闸门 |
| `sources_unauthorized.jsonl` | 2 条未授权资料（公开网页摘录、未生效内部草稿） | **全部被拒**（SOURCE_UNKNOWN） |
| `generations.jsonl` | 16 条候选生成、40 条候选：8 条正常成对 + 8 条各触发一种筛选规则 | 产出 8 对，漏斗 9 条规则各被触发 |
| `generations_unauthorized.jsonl` | 3 条引用未授权来源的候选生成 | **0 对产出**，3 条拒绝记录 |
| `traces_messages.jsonl` | 6 条对话格式轨迹（含 2 条 DPO） | 6 条三元组 |
| `traces_tool.jsonl` | 5 条工具轨迹（含 2 条 DPO） | 5 条三元组 |
| `traces_invalid.jsonl` | 4 条坏轨迹（缺最终回答/未知适配器/非法规则引用/无步骤） | **全部被拒**，0 条三元组 |
| `golden_cases.jsonl` | 16 条回归用例（13 应答 + 2 拒答 + 1 abstain） | 16/16 通过 |

### 4. 脚本、测试与验收

| 文件 | 职责 | 结果 |
|---|---|---|
| `scripts/gen_samples.py` | 确定性生成 6 份派生素材并自检（指纹/结构/闸门/回归四项） | 复跑逐字节相同；`--check` 退出码 0 |
| `tests/harness.py` | 零依赖测试收集器（断言即用例，自统计） | — |
| `tests/test_core.py` | 模型/配置/存储/校验/报告模板/命令行契约 | 49/49 |
| `tests/test_pairs.py` | 授权闸门、脱敏、偏好对九条规则、确定性 | 97/97 |
| `tests/test_distill.py` | 两种适配器、坏轨迹、目标类型、策略卡、回归引擎与闸门 | 90/90 |
| `tests/test_runner.py` | 子进程跑三份测试并汇总 | `TOTAL: 236/236 tests passed` |
| `verify/run_verification.py` | A..J 十组独立断言：完整性/配置/测试/demo/确定性/负向/匿名化/报告/样例/卫生 | 见 `verify/records/` 末行断言统计 |
| `verify/records/commands.md` | 本次真实验收执行的命令与退出码 | 自动生成 |
| `verify/records/tests_output.txt` | 测试子进程原始输出 | 自动生成 |
| `verify/records/verification_output.txt` | 逐条断言日志 | 自动生成 |

### 5. 产物（`out/`，9 份文件，由 `python -m dpo_policy demo` 生成）

| 产物 | 内容 |
|---|---|
| `anonymized_samples.jsonl` | **匿名偏好样例 8 条**（订单验收项），含 prompt/chosen/rejected/对比规格/来源绑定 |
| `preference_pairs.jsonl` | 偏好对 8 条（机器可读全字段） |
| `pair_audit.md` | 偏好对审计：漏斗（9 条规则各拦多少）、对比轴分布、授权来源表、未授权负样例表、匿名化摘要、样例对 |
| `distill_triples.jsonl` | 蒸馏三元组 11 条（SFT 7 / DPO 4；messages 6 / tool_trace 5） |
| `policy_card.md` | 策略卡 5 张（按三元组引用聚合）+ 蒸馏统计 + 脱敏样本节选 |
| `regression_report.md` | 离线回归报告（订单验收项「回归报告模板」的填充实例）：16/16、基线对比、零回退 |
| `regression_metrics.json` | 同一份回归结果的机器可读版本 |
| `pipeline_run.json` | 运行清单（配置口径、计数、闸门、负向对照、8 份产物路径与 sha256 摘要）+ 自身共 9 份 |
| `demo.log` | 六步执行日志与负向对照结论 |

`var/` 放工作数据（`sources_index.json`、`pairs.json`、`pairs_stats.json`、`triples.json`、
`distill_stats.json`、`regression.json`、`anonymization.json`、`run_state.json`），不随交付发布：
其中 `anonymization.json` 只有映射条数与 sha256 摘要，**不保存映射原文**。

## 二、验收对照

| 订单验收标准 | 对应交付 | 可复核的证据 |
|---|---|---|
| 提交匿名偏好样例 | `out/anonymized_samples.jsonl`（8 条）+ `out/preference_pairs.jsonl` | 产物经残留扫描 0 命中；无明文手机号/邮箱/人名/机构名；伪名稳定；映射不交付 |
| 配置 | `config/` 6 份 JSON | `validate-config` 通过；写坏任一关键字段即退出码 3；登记表指纹与语料逐条比对一致 |
| 回归报告模板 | `config/report_templates/regression_report.md.tpl` | 模板含结论/逐例/基线/失败明细/复跑；填充实现遇残留占位符报错；`out/regression_report.md` 是真实填充结果 |
| 保留授权 | 登记表 + 五种拒绝码 + 未授权负样例 | 2 条未授权来源被拒；3 条未授权候选 0 对产出；demo 有命令级负向（全量未授权 -> 退出码 2） |
| 保留版本 | `SourceBinding` + 内容指纹 + 版本/指纹漂移拒绝 | 两条漂移负向对照均被拒（`SOURCE_VERSION_MISMATCH` / `SOURCE_HASH_MISMATCH`） |
| 保留离线回归 | `regression.py` + 16 条固定用例 + 基线 | 16/16 通过（基线 14/16）；修复 2 条基线失败用例；回退 0 |

## 三、怎么复现

```bash
python scripts/gen_samples.py --check     # 期望最后一行：自检通过
python -m dpo_policy validate-config      # 期望：配置校验通过 + 口径摘要
python -m dpo_policy demo                 # 期望：退出码 0，out/ 下 9 份文件
python tests/test_runner.py               # 期望：TOTAL: 236/236 tests passed
python verify/run_verification.py         # 期望：末行 N/N assertions passed，退出码 0
```

隔离复跑（不覆盖仓库内 `out/`，用来验证确定性）：

```bash
python -m dpo_policy --root . --out-dir %TEMP%\cph-out --var-dir %TEMP%\cph-var demo
```

两遍运行产出的 9 份文件应逐字节相同；`verify/run_verification.py` 的 E 组断言就是这件事。

## 四、退出码与"哪些算失败"

| 退出码 | 含义 | 是否要人工介入 |
|---|---|---|
| 0 | 通过 | 否 |
| 2 | 业务闸门拒绝（未授权来源 / 版本漂移 / 指纹漂移 / 脱敏残留 / 坏轨迹 / 回归闸门不通过） | 是：看打印的错误码与拒绝记录 |
| 3 | 用法或配置问题、内部不变量被破坏 | 是：先查参数与 `config/` |

## 五、已知限制与后续接入点

1. **不含真实模型调用与训练代码**：候选与轨迹是确定性模拟数据（`simulated: true`），
   接入真实模型时替换产出处即可，闸门/脱敏/回归判据不变。
2. **脱敏是规则驱动的**：规则覆盖常见直接标识；生产环境把 NER 或员工名册接到 `Anonymizer` 同一接口，
   并把新增的残留模式加到 `leak_scan` 即可。`wechat_id` 那条刻意没有对应替换规则，用来长期验证第二道防线。
3. **回归集 16 条是起点**：扩集往 `samples/golden_cases.jsonl` 加行，同时在
   `config/regression_config.json` 更新基线与阈值；判分逻辑不用改。
4. **不含第三方依赖**：若后续要接向量库或训练框架，它们应落在 `scripts/` 的适配层，`dpo_policy/`
   保持标准库与"无真实时钟"约束，否则确定性验收会失效。
