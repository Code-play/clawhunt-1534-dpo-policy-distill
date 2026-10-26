"""DPO 偏好与 Policy 蒸馏骨架。

交付物按"一层只回答一个问题"切分，任何一层都不越界替上层做决定：

- :mod:`dpo_policy.model` —— 领域模型：偏好对、蒸馏三元组、回归用例、策略卡、逻辑时钟、哈希口径；
- :mod:`dpo_policy.config` —— 三份配置 + 三份登记表的加载与自洽/交叉校验；
- :mod:`dpo_policy.provenance` —— 授权与版本闸门（白名单制，拒绝即落稳定错误码）；
- :mod:`dpo_policy.anonymize` —— 稳定伪名脱敏 + 残留扫描（命中即整条拒绝）；
- :mod:`dpo_policy.pairs` —— 偏好对构建：候选选择、决定性对比轴、质量过滤与去重；
- :mod:`dpo_policy.distill` —— 教师轨迹 -> 蒸馏三元组 -> 策略卡，支持多种轨迹适配器；
- :mod:`dpo_policy.regression` —— 离线回归：策略引擎、逐例判定、基线对比与闸门；
- :mod:`dpo_policy.validate` —— 记录级字段校验（产物与样例共用一套口径）；
- :mod:`dpo_policy.store` —— 只追加 JSONL 存储与原子落盘；
- :mod:`dpo_policy.report` —— Markdown 报告渲染（偏好对审计、策略卡、回归报告）；
- :mod:`dpo_policy.cli` —— 命令行入口与 demo 主流程。

运行环境：Python 3.9+，仅标准库，无网络，不读真实时钟（时刻来自配置里的逻辑时钟）。
"""

from __future__ import annotations

from .model import PIPELINE_VERSION

__all__ = ["PIPELINE_VERSION", "__version__"]

__version__ = "1.0.0"
