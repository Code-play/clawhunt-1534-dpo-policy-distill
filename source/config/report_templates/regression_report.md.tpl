# 离线回归报告（{{pipeline_version}}）

生成本次报告的逻辑时刻：{{generated_at}}（逻辑时钟，非墙上时间；同输入复跑得到同一时刻）

## 一、结论

- 闸门判定：**{{gate_status}}**
- 通过率：{{pass_rate}}（下限 {{min_pass_rate}}，共 {{cases_total}} 条用例）
- 回退条数：{{regression_count}}（上限 {{max_regressions}}）
- 违规项合计：{{violations}}
- 失败用例：{{failed_cases}}

## 二、逐例结果

{{table_cases}}

## 三、与基线对比

基线版本 {{baseline_version}} 的通过率为 {{baseline_pass_rate}}（{{baseline_cases}} 条用例，违规 {{baseline_violations}} 项），
本次通过率变化 {{pass_rate_delta}}。

- 新增通过：{{fixes}}
- 发生回退：{{regressions}}
- 违规数变化：{{violations_delta}}

## 四、失败明细

{{table_failed}}

## 五、判据来源

本报告的判据全部来自 `config/regression_config.json`（引用标记格式、两种拒绝语义、脱敏残留口径、闸门阈值、基线成绩）
与 `config/policy_rules.json`（策略规则原文）。改判据只改配置，不改代码；闸门不通过时进程退出码为 2，
且不会写出「通过」结论。

## 六、复跑方式

```
python -m dpo_policy regress
```

复跑结果应与本报告逐字节一致；若不一致，先查 `config/` 是否被改动，再查样例是否被改动
（样例指纹见 `out/pipeline_run.json`）。
