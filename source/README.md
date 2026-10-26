# 企业 Agent 系统 47/50｜DPO 偏好与 Policy 蒸馏

本仓库是 ClawHunt 订单 **#1534「企业 Agent 系统 47/50｜DPO 偏好与 Policy 蒸馏」** 的交付物：
一套**可运行、可复跑、零第三方依赖**的偏好对构建 + 策略蒸馏 + 离线回归骨架。

订单验收标准是「提交匿名偏好样例、配置与回归报告模板」。本仓库把这句话落成三件可检验的东西：

1. **匿名偏好样例**：`out/anonymized_samples.jsonl`（8 条，正文经稳定伪名脱敏，可直接训练）；
2. **配置**：`config/` 下 6 份 JSON——流水线口径、授权登记表、脱敏规则、策略规则库、回归判据、报告模板；
3. **回归报告模板**：`config/report_templates/regression_report.md.tpl`，由流水线填充成 `out/regression_report.md`。

## 一、三步上手

```bash
python scripts/gen_samples.py --check     # 1. 自检样例（指纹/结构/闸门/回归四项）
python -m dpo_policy demo                 # 2. 跑全流程，产出 9 份文件到 out/
python tests/test_runner.py               # 3. 跑全部单元测试
```

Python 3.9+，仅标准库；无网络访问；不读真实时钟（时刻来自 `config/pipeline_config.json` 里的逻辑时钟）。
复跑结果应与仓库内 `out/` 逐字节一致——这是"可复跑"的硬证据，不是说法。

## 二、常用命令

| 命令 | 作用 | 主要产物 |
|---|---|---|
| `python -m dpo_policy validate-config` | 只校验配置（自洽 + 跨文件一致） | 屏幕输出 |
| `python -m dpo_policy sources` | 授权闸门：索引语料、复核指纹、驱动未授权负样例 | `var/sources_index.json` |
| `python -m dpo_policy pairs` | 构建偏好对（筛选漏斗 + 去重 + 脱敏） | `out/preference_pairs.jsonl`、`out/pair_audit.md` |
| `python -m dpo_policy distill` | 教师轨迹 → 蒸馏三元组 → 策略卡 | `out/distill_triples.jsonl`、`out/policy_card.md` |
| `python -m dpo_policy regress` | 离线回归（闸门不通过时退出码 2） | `out/regression_report.md`、`out/regression_metrics.json` |
| `python -m dpo_policy demo` | 全流程 + 四组负向对照 + 产物清单 | `out/` 全量 9 份 |
| `python scripts/gen_samples.py` | 重新生成样例并自检（幂等） | `samples/*.jsonl` |
| `python tests/test_runner.py` | 全部单元测试 | 汇总行 `TOTAL: X/Y tests passed` |
| `python verify/run_verification.py` | 独立验收：重新执行并断言（含确定性比对） | `verify/records/` |

公共参数可放在子命令前后：`--root`、`--out-dir`、`--var-dir`、`--samples-dir`。
把它们指向临时目录即可做隔离复跑（`verify/run_verification.py` 就是这么比确定性的）。

## 三、目录结构

```
1534-dpo-policy-distill/
  config/     pipeline_config.json     流水线口径（版本/时钟/路径/来源策略/匿名化/筛选阈值/蒸馏参数）
              source_registry.json     授权登记表（来源 + 版本 + 许可 + 内容指纹 + 授权编号 + 生效日期）
              redaction_rules.json     9 条脱敏规则 + 8 条残留检测模式（含刻意未覆盖的 wechat_id）
              policy_rules.json        8 条策略规则（偏好对/三元组/回归共用同一套 rule_id）
              regression_config.json   回归判据（引用标记、两种拒绝语义、泄漏口径、闸门阈值、基线成绩）
              report_templates/regression_report.md.tpl   回归报告模板
  dpo_policy/ model.py                  领域模型与哈希/时钟口径
              config.py                 配置加载与三层校验
              provenance.py             授权与版本闸门（白名单制）
              anonymize.py              稳定伪名脱敏 + 残留扫描
              pairs.py                  偏好对构建（候选选择/决定性轴/质量过滤/去重）
              distill.py                轨迹适配器（messages / tool_trace）→ 三元组 → 策略卡
              regression.py             策略引擎 + 逐例判定 + 基线对比 + 闸门
              validate.py               记录级字段校验
              store.py                  只追加 JSONL + 原子落盘
              report.py                 三类 Markdown 报告渲染
              cli.py                    命令行与 demo 主流程
  samples/    sources.jsonl（6）sources_unauthorized.jsonl（2）
              generations.jsonl（16）generations_unauthorized.jsonl（3）
              traces_messages.jsonl（6）traces_tool.jsonl（5）traces_invalid.jsonl（4）
              golden_cases.jsonl（16）
  scripts/    gen_samples.py            确定性样例生成器（生成后自检）
  tests/      harness.py               最小测试收集器
              test_core.py / test_pairs.py / test_distill.py / test_runner.py
  verify/     run_verification.py      独立验收（A..J 十组断言）
              records/                 本次验收的真实命令、测试输出与断言日志
  out/        9 份产物（样例外还可直接读的报告）
  var/        工作数据（含脱敏映射摘要；不交付）
```

## 四、核心概念

| 概念 | 含义 | 落在哪 |
|---|---|---|
| 授权登记表 | 来源 → 版本 → 许可 → 内容指纹 → 授权编号；**白名单制**，不在表内即拒 | `config/source_registry.json`、`provenance.py` |
| 内容指纹 | `sha256(canonical({source_id, version, title, text}))`，不含授权元数据 | `model.SourceRecord.content_sha256` |
| 决定性对比轴 | 每条偏好对必须有一个唯一轴，chosen 在该轴领先 ≥ 0.10，其它轴反超 ≤ 0.15 | `pairs.py`、`config/pipeline_config.json` |
| 稳定伪名 | `<email:1a2b3c4d>`，由 `HMAC(salt, kind|原值)` 派生；同原文同伪名，映射表不交付 | `anonymize.py` |
| 残留闸门 | 脱敏后再扫一遍；命中即**整条拒绝**（block），不是打码放行 | `anonymize.assert_clean` |
| 蒸馏三元组 | instruction + output + rationale + policy_refs + 来源绑定 + target(sft/dpo) | `distill.py`、`model.DistillTriple` |
| 策略卡 | 由三元组按 rule_id 聚合：支撑条数 + 涉及来源 + 执行方式 | `distill.build_policy_cards` |
| 离线回归 | 策略引擎在 16 条固定用例上跑动作判定，比对基线（无回退）+ 通过率下限（≥90%） | `regression.py` |
| 逻辑时钟 | 配置起点 + 固定步长；同输入复跑得到同一时刻序列 | `model.LogicalClock` |

## 五、产物说明

| 文件 | 内容 |
|---|---|
| `out/preference_pairs.jsonl` | 8 条偏好对（chosen/rejected/对比规格/来源绑定/去重键/逻辑时刻） |
| `out/anonymized_samples.jsonl` | 8 条匿名偏好样例（订单验收项「匿名偏好样例」） |
| `out/pair_audit.md` | 偏好对审计：漏斗（每条筛选规则拦了多少）、对比轴分布、授权来源表、未授权负样例表、匿名化摘要 |
| `out/distill_triples.jsonl` | 11 条蒸馏三元组（6 条 messages 轨迹 + 5 条 tool_trace 轨迹，含 4 条 DPO） |
| `out/policy_card.md` | 策略卡：蒸馏统计、规则支撑计数、规则原文、脱敏样本节选 |
| `out/regression_report.md` | 离线回归报告（由模板填充，含逐例结果、基线对比、失败明细、复跑方式） |
| `out/regression_metrics.json` | 同一份回归结果的机器可读版本 |
| `out/pipeline_run.json` | 运行清单：口径、计数、闸门、负向对照、产物路径与 sha256 摘要 |
| `out/demo.log` | 六步执行日志（含每组负向对照的拦截结论） |

## 六、退出码

| 退出码 | 含义 | 典型场景 |
|---|---|---|
| 0 | 通过 | 全流程与闸门都过 |
| 2 | 业务闸门拒绝 | 未授权来源、版本/指纹漂移、脱敏残留、坏轨迹、回归闸门不通过 |
| 3 | 用法/配置/环境问题 | 参数写错、配置缺文件或写坏、内部不变量被破坏 |

把 2 与 3 分开是有意的：复跑的人要能一眼区分"数据不合格"和"我自己敲错了"。

## 七、边界与已知限制

- **不含真实模型调用**：建模的是"偏好对与蒸馏数据的生产与校验流水线"，候选/轨迹是确定性模拟数据；
  接入真实模型时只需替换 `GenerationRecord` / `TraceRecord` 的产出处，闸门与判据不变。
- **脱敏是规则的、不是万能的**：`config/redaction_rules.json` 里的规则覆盖常见直接标识；
  `leak_scan` 刻意留了一条未覆盖 `wechat_id` 的模式，用来证明"第二道防线真的存在"（整条拒绝）。
  生产环境应把 NER 或员工名册接到同一接口（`Anonymizer`）上。
- **蒸馏是骨架**：三元组格式、目标类型、依据条数与规则引用都已固定并受闸门约束，
  但不含 LoRA/Adapter 训练代码——训练算力与模型费用不在本单预算内。
- **回归集是固定的小集**：16 条用例覆盖三类动作与多来源引用；扩集只需往
  `samples/golden_cases.jsonl` 加行，基线在 `config/regression_config.json` 里同步维护。

## 八、交付说明

- `SOLUTION.md`：需求理解、核心设计、数据模型、验收对照、真实验证输出；
- `DELIVERY.md`：逐文件交付清单、验收对照表、复现步骤、证据位置。
