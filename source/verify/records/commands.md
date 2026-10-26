# 验收命令与结果（订单 #1534）

本文件由 `verify/run_verification.py` 在执行结束时自动生成；所有命令都在本机实际执行过。

## 一、执行过的命令

| 命令 | 退出码 |
|---|---|
| `python tests/test_runner.py` | 0 |
| `python -m dpo_policy demo（隔离目录 run1）` | 0 |
| `python -m dpo_policy demo（隔离目录 run2）` | 0 |
| `python -m dpo_policy demo（全部未授权来源的样例）` | 2 |
| `python -m dpo_policy validate-config（缺配置目录）` | 3 |
| `python scripts/gen_samples.py --check` | 0 |
| `python scripts/gen_samples.py（重新生成）` | 0 |

## 二、等价的手工复跑顺序

```bash
python scripts/gen_samples.py --check      # 样例自检（指纹/结构/闸门/回归）
python -m dpo_policy validate-config       # 配置自洽与交叉校验
python -m dpo_policy sources               # 授权闸门（含未授权负样例）
python -m dpo_policy demo                  # 全流程 + 四组负向对照
python tests/test_runner.py                # 全部单元测试
python verify/run_verification.py          # 本脚本：独立复核
```

## 三、结果

- 断言：131/131 通过
- 退出码约定：0 通过；2 业务闸门拒绝；3 用法/配置问题
- 验收脚本只写 `verify/records/` 与系统临时目录，不改任何受测文件
