"""离线回归层：策略引擎、逐例判定、基线对比与发布闸门。

本模块回答一个问题："这次改完，策略引擎还能不能守住上一版的成绩"。它明确不做的事：

- 不产生训练数据（那是 :mod:`dpo_policy.distill` 与 :mod:`dpo_policy.pairs` 的事）；
- 不读文件、不连网络、不读真实时钟（用例由调用方喂进来，时刻来自 ``LogicalClock``）；
- 不判来源是否授权（引擎只看用例声明的 ``available_sources``，授权真值以授权登记表为准，
  回归只验"引擎在给定授权状态下会不会用错"）；
- 不对自由文本打分。判分只看动作、引用标记、必引来源、禁用模式与脱敏残留 —— 让"好回答"这种
  主观判断进回归，闸门就会随措辞漂移。

为什么动作空间只有三值（``answer_with_citation`` / ``abstain`` / ``refuse_unauthorized``）：
两种"答不了"必须分开。来源未授权是**不敢用**，授权来源里没依据是**不会答**，
把它们都写成 abstain，买家就分不清是授权问题还是资料问题（见配置里的 refusal 段）。

阈值纪律：``min_pass_rate`` / ``max_regressions`` 一律从 ``cfg.regression`` 读，代码里不写死；
判定结果用稳定 violation token 表达（``ACTION_MISMATCH(expected=X,actual=Y)`` 这类），
措辞与顺序都不参与判分，只参与阅读。

确定性：用例按 ``case_id`` 排序处理，所有聚合按显式排序输出，``Decision.to_dict()`` 的键序固定，
同一输入两次调用得到逐字节相同的结果。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from .model import (
    ACTION_ABSTAIN,
    ACTION_ANSWER,
    ACTION_REFUSE,
    ACTIONS,
    GoldenCase,
    LogicalClock,
    PipelineError,
    PolicyCard,
    RegressionCaseResult,
    RegressionReport,
    ErrorCode,
)

if TYPE_CHECKING:  # pragma: no cover - 只给类型检查用
    from .anonymize import Anonymizer
    from .config import Config

__all__ = [
    "Decision",
    "PolicyEngine",
    "judge_case",
    "run_regression",
]

#: 规则引用恒定值：引擎给出的动作都必须在回复里点明它依据的是哪条策略。
RULE_CITE = "R-CITE-01"
RULE_AUTH = "R-AUTH-01"
RULE_REFUSE = "R-REFUSE-02"

#: ``authorized`` 字段的"真"取值集合：配置里允许写 bool，也允许写字符串（轨迹常来自 JSON/YAML 混用）。
_TRUE_TOKENS = frozenset({"true", "1", "yes", "y", "on"})


def _is_authorized(value: Any) -> bool:
    """把 ``authorized`` 归一成布尔；缺失/假值一律视为未授权（授权是白名单制）。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in _TRUE_TOKENS
    return False


def _source_display(source: Mapping[str, Any]) -> str:
    return f"{source.get('source_id', '')}@{source.get('version', '')}"


# ---------------------------------------------------------------- 决策


@dataclass(frozen=True)
class Decision:
    """策略引擎对一个用例的决策：动作 + 回复正文 + 引用 + 规则 + 原因。"""

    action: str
    answer: str
    citations: tuple[Mapping[str, str], ...]
    policy_refs: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        # 键序与 citations 的顺序都在这里钉死，保证"同输入两次逐字节相同"
        return {
            "action": self.action,
            "answer": self.answer,
            "citations": [
                {"source_id": str(item.get("source_id", "")), "version": str(item.get("version", ""))}
                for item in self.citations
            ],
            "policy_refs": list(self.policy_refs),
            "reasons": list(self.reasons),
        }


# ---------------------------------------------------------------- 策略引擎


class PolicyEngine:
    """只带策略卡与配置的确定性策略引擎。

    ``cards`` 在构造时就按 ``(-support, rule_id)`` 排好：同支持度时按规则号升序，
    这样"取支持度最高的前两条"在任何输入顺序下都得到同一结果，不依赖调用方传参顺序。
    """

    def __init__(self, cards: Iterable[PolicyCard], cfg: "Config") -> None:
        self._cfg = cfg
        self._regression: Mapping[str, Any] = cfg.regression
        self._cards: tuple[PolicyCard, ...] = tuple(
            sorted(cards, key=lambda card: (-int(card.support), str(card.rule_id)))
        )

    @property
    def cards(self) -> tuple[PolicyCard, ...]:
        return self._cards

    @property
    def version(self) -> str:
        return str(self._cfg.pipeline_version)

    # -- 内部 -----------------------------------------------------------------

    def _top_cards(self, limit: int = 2) -> tuple[PolicyCard, ...]:
        return self._cards[:limit]

    def _normalized_sources(self, case: GoldenCase) -> tuple[dict[str, Any], ...]:
        out: list[dict[str, Any]] = []
        for item in case.available_sources:
            out.append(
                {
                    "source_id": str(item.get("source_id", "")),
                    "version": str(item.get("version", "")),
                    "authorized": _is_authorized(item.get("authorized")),
                }
            )
        # 排序去重：同一来源声明两次只算一次，顺序不影响结论
        unique: dict[tuple[str, str], dict[str, Any]] = {}
        for item in out:
            unique[(item["source_id"], item["version"])] = item
        return tuple(unique[key] for key in sorted(unique))

    # -- 主逻辑 ---------------------------------------------------------------

    def act(self, case: GoldenCase) -> Decision:
        """按配置给定的判据决定动作。所有阈值/动作名都来自 ``cfg.regression``。"""
        citation_cfg = self._regression.get("citation", {})
        refusal_cfg = self._regression.get("refusal", {})
        sources = self._normalized_sources(case)

        unauthorized = [item for item in sources if not item["authorized"]]
        if unauthorized:
            action = str(refusal_cfg.get("actions_for_unauthorized", ACTION_REFUSE))
            ids = sorted({item["source_id"] for item in unauthorized if item["source_id"]})
            tail = f"未授权来源：{'、'.join(ids)}。" if ids else ""
            answer = (
                "涉及未授权来源，按 R-AUTH-01 拒绝。"
                + tail
                + "请先补齐授权或改用已授权资料；我不对未授权内容做任何推断。"
            )
            return Decision(
                action=action,
                answer=answer,
                citations=(),
                policy_refs=(RULE_AUTH,),
                reasons=(RULE_AUTH,),
            )

        if not sources:
            action = str(refusal_cfg.get("actions_for_missing_source", ACTION_ABSTAIN))
            answer = "授权来源中无依据，暂不回答。已检索来源：（无）。请补充可授权资料后再问。"
            return Decision(
                action=action,
                answer=answer,
                citations=(),
                policy_refs=(RULE_REFUSE,),
                reasons=(RULE_REFUSE,),
            )

        # -- 可以回答：给出引用标记 + 引用清单 + 前两条策略要点
        citations: tuple[Mapping[str, str], ...] = tuple(
            {"source_id": item["source_id"], "version": item["version"]} for item in sources
        )
        version_by_id: dict[str, str] = {}
        for item in sources:
            version_by_id.setdefault(item["source_id"], item["version"])

        reasons: list[str] = []
        markers: list[str] = []
        for source_id in sorted({str(item) for item in case.required_source_ids}):
            version = version_by_id.get(source_id)
            if version is None:
                # 不能编造版本号：记下缺口，让回归报告能看见"这题缺证据"
                reasons.append(f"MISSING_SOURCE:{source_id}")
                continue
            markers.append(f"[S:{source_id}@{version}]")
        if not markers:
            # 没有必引来源时至少引一条已授权来源，保证 answer_with_citation 有可回溯依据
            first = citations[0]
            markers.append(f"[S:{first['source_id']}@{first['version']}]")

        parts: list[str] = ["依据授权资料回答：", " ".join(markers)]
        parts.append("引用来源：" + "、".join(_source_display(item) for item in citations) + "。")
        top = self._top_cards(2)
        if top:
            parts.append("策略要点：" + "；".join(f"{card.rule_id} {card.title}" for card in top) + "。")
        answer = " ".join(parts)

        return Decision(
            action=ACTION_ANSWER,
            answer=answer,
            citations=citations,
            policy_refs=(RULE_CITE,),
            reasons=tuple(reasons),
        )


# ---------------------------------------------------------------- 判定


def _marker_pattern(cfg: "Config") -> re.Pattern[str]:
    raw = str(cfg.regression["citation"]["marker_pattern"])
    try:
        return re.compile(raw)
    except re.error as exc:  # pragma: no cover - 加载期已校验
        raise PipelineError(ErrorCode.CONFIG_INVALID, "citation.marker_pattern 不可编译", detail=str(exc)) from exc


def _pattern_hit(text: str, pattern: str, *, as_regex: bool, case_sensitive: bool) -> bool:
    """约定：正则写错时退化成子串匹配，而不是让整批判定崩掉（用例是数据，不是配置）。"""
    if as_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            return re.search(pattern, text, flags) is not None
        except re.error:
            pass
    if case_sensitive:
        return pattern in text
    return pattern.lower() in text.lower()


def judge_case(
    case: GoldenCase,
    decision: Decision,
    cfg: "Config",
    anonymizer: "Anonymizer",
) -> RegressionCaseResult:
    """对一条用例的决策做判定，返回带稳定 violation token 的结果。"""
    regression = cfg.regression
    citation_cfg = regression["citation"]
    leak_cfg = regression["leak_checks"]
    judge_cfg = regression["judge"]
    text = decision.answer
    violations: list[str] = []
    notes: list[str] = []

    # 1) 动作
    if decision.action != case.expected_action:
        violations.append(f"ACTION_MISMATCH(expected={case.expected_action},actual={decision.action})")

    # 2) 引用（只看"期望动作要求引用"的用例）
    pattern = _marker_pattern(cfg)
    markers = tuple(sorted({f"{m.group('source_id')}@{m.group('version')}" for m in pattern.finditer(text)}))
    cited_ids = tuple(sorted({item.split("@", 1)[0] for item in markers}))
    require_actions = tuple(str(item) for item in citation_cfg.get("require_for_actions", ()))
    if case.expected_action in require_actions:
        if not markers:
            violations.append("MISSING_CITATION")
        for required in sorted({str(item) for item in case.must_cite}):
            if required not in cited_ids:
                violations.append(f"MISSING_REQUIRED_CITATION:{required}")
        if bool(citation_cfg.get("require_visible_source", True)):
            visible = {str(item.get("source_id", "")) for item in case.available_sources}
            for source_id in cited_ids:
                if source_id not in visible:
                    violations.append(f"CITED_SOURCE_NOT_VISIBLE:{source_id}")

    # 3) 禁用模式（按配置决定正则/子串、大小写）
    as_regex = bool(judge_cfg.get("forbidden_patterns_are_regex", True))
    case_sensitive = bool(judge_cfg.get("forbidden_match_case_sensitive", False))
    for raw_pattern in case.forbidden_patterns:
        pattern_text = str(raw_pattern)
        if pattern_text and _pattern_hit(text, pattern_text, as_regex=as_regex, case_sensitive=case_sensitive):
            violations.append(f"FORBIDDEN_PATTERN:{pattern_text}")

    # 4) 脱敏残留：policy=block 才算违规，warn 只进 notes
    forbidden_kinds = {str(item) for item in leak_cfg.get("forbidden_kinds", ())}
    leak_policy = str(leak_cfg.get("policy", "block"))
    hits = anonymizer.scan(text)
    leak_kinds = sorted({str(getattr(hit, "kind", "")) for hit in hits})
    for kind in leak_kinds:
        if not kind or kind not in forbidden_kinds:
            continue
        if leak_policy == "block":
            violations.append(f"LEAK:{kind}")
        else:
            notes.append(f"LEAK_WARN:{kind}")

    # 5) 拒答/弃答时不得出现引用标记（否则等于"用不可用来源作答"）
    if case.expected_action in (ACTION_ABSTAIN, ACTION_REFUSE) and markers:
        violations.append("UNEXPECTED_CITATION")

    return RegressionCaseResult(
        case_id=case.case_id,
        expected_action=case.expected_action,
        actual_action=decision.action,
        passed=not violations,
        violations=tuple(violations),
        citations=markers,
        notes=tuple(notes),
    )


# ---------------------------------------------------------------- 回归主流程


def _validate_cases(cases: Iterable[GoldenCase]) -> tuple[GoldenCase, ...]:
    """先校验用例本身：用例写错属于配置/用法问题，必须抛 ``REGRESSION_CASE_INVALID``。

    为什么先校验再跑：把"用例写错"混进"引擎答错"，报告会把环境问题读成模型退步。
    """
    validated: list[GoldenCase] = []
    seen: set[str] = set()
    if cases is None:
        cases = ()
    for index, case in enumerate(cases):
        if not isinstance(case, GoldenCase):
            raise PipelineError(ErrorCode.REGRESSION_CASE_INVALID, f"cases[{index}] 必须是 GoldenCase")
        case_id = str(case.case_id or "").strip()
        if not case_id:
            raise PipelineError(ErrorCode.REGRESSION_CASE_INVALID, f"cases[{index}].case_id 不能为空")
        if case_id in seen:
            raise PipelineError(
                ErrorCode.REGRESSION_CASE_INVALID,
                "case_id 不允许重复",
                record_id=case_id,
            )
        seen.add(case_id)
        if case.expected_action not in ACTIONS:
            raise PipelineError(
                ErrorCode.REGRESSION_CASE_INVALID,
                "expected_action 必须是 answer_with_citation/abstain/refuse_unauthorized 之一",
                record_id=case_id,
            )
        for j, source in enumerate(case.available_sources):
            if not isinstance(source, Mapping):
                raise PipelineError(
                    ErrorCode.REGRESSION_CASE_INVALID,
                    f"available_sources[{j}] 必须是对象",
                    record_id=case_id,
                )
            source_id = source.get("source_id")
            version = source.get("version")
            if not isinstance(source_id, str) or not source_id.strip():
                raise PipelineError(
                    ErrorCode.REGRESSION_CASE_INVALID,
                    f"available_sources[{j}].source_id 必须是非空字符串",
                    record_id=case_id,
                )
            if not isinstance(version, str) or not version.strip():
                raise PipelineError(
                    ErrorCode.REGRESSION_CASE_INVALID,
                    f"available_sources[{j}].version 必须是非空字符串",
                    record_id=case_id,
                )
            authorized = source.get("authorized")
            if authorized is not None and not isinstance(authorized, (bool, str)):
                raise PipelineError(
                    ErrorCode.REGRESSION_CASE_INVALID,
                    f"available_sources[{j}].authorized 只能是布尔或 true/false 字符串",
                    record_id=case_id,
                )
        validated.append(case)
    return tuple(sorted(validated, key=lambda item: str(item.case_id)))


def run_regression(
    cases: Iterable[GoldenCase],
    engine: PolicyEngine,
    cfg: "Config",
    clock: LogicalClock,
    anonymizer: "Anonymizer",
) -> RegressionReport:
    """跑完整个回归集：逐例决策 + 判定 + 汇总 + 基线对比 + 闸门。"""
    validated = _validate_cases(cases)
    results: list[RegressionCaseResult] = []
    for case in validated:
        decision = engine.act(case)
        results.append(judge_case(case, decision, cfg, anonymizer))

    regression = cfg.regression
    citation_cfg = regression["citation"]
    require_actions = {str(item) for item in citation_cfg.get("require_for_actions", ())}

    total = len(results)
    passed = sum(1 for item in results if item.passed)
    violations_total = sum(len(item.violations) for item in results)
    pass_rate = round(passed / total, 4) if total else 0.0

    # 指标描述的是"这一批用例"的构成（期望口径），这样引擎退化时指标不会跟着一起漂
    by_action = {action: 0 for action in ACTIONS}
    by_tag: dict[str, int] = {}
    unauthorized_cases = 0
    abstain_cases = 0
    citation_required = 0
    citation_covered = 0
    for case, result in zip(validated, results):
        by_action[case.expected_action] = by_action.get(case.expected_action, 0) + 1
        for tag in case.tags:
            key = str(tag)
            by_tag[key] = by_tag.get(key, 0) + 1
        if any(not _is_authorized(item.get("authorized")) for item in case.available_sources):
            unauthorized_cases += 1
        if case.expected_action == ACTION_ABSTAIN:
            abstain_cases += 1
        if case.expected_action in require_actions:
            citation_required += 1
            if result.citations:
                citation_covered += 1

    citation_coverage = round(citation_covered / citation_required, 4) if citation_required else 1.0
    metrics: dict[str, Any] = {
        "cases": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": pass_rate,
        "violations": violations_total,
        "by_action": dict(sorted(by_action.items())),
        "by_tag": dict(sorted(by_tag.items())),
        "unauthorized_cases": unauthorized_cases,
        "abstain_cases": abstain_cases,
        "citation_coverage": citation_coverage,
    }

    baseline_raw = regression.get("baseline", {})
    baseline = dict(baseline_raw) if isinstance(baseline_raw, Mapping) else {}
    baseline_cases = baseline.get("case_pass", {})
    if not isinstance(baseline_cases, Mapping):
        baseline_cases = {}
    base_pass_rate = float(baseline.get("pass_rate", 0.0) or 0.0)
    regressions = sorted(
        result.case_id
        for result in results
        if baseline_cases.get(result.case_id) is True and not result.passed
    )
    fixes = sorted(
        result.case_id
        for result in results
        if baseline_cases.get(result.case_id) is False and result.passed
    )
    deltas: dict[str, Any] = {
        "pass_rate": round(pass_rate - base_pass_rate, 4),
        "regressions": regressions,
        "fixes": fixes,
        "violations_delta": violations_total - int(baseline.get("violations", 0) or 0),
    }

    thresholds = regression.get("thresholds", {})
    min_pass_rate = float(thresholds.get("min_pass_rate", 0.0) or 0.0)
    max_regressions = int(thresholds.get("max_regressions", 0) or 0)
    gate: dict[str, Any] = {
        "ok": bool(pass_rate >= min_pass_rate and len(regressions) <= max_regressions),
        "min_pass_rate": min_pass_rate,
        "max_regressions": max_regressions,
        "pass_rate": pass_rate,
        "regression_count": len(regressions),
        "failed_case_ids": sorted(result.case_id for result in results if not result.passed),
    }

    return RegressionReport(
        generated_at=clock.now(),
        cases=tuple(results),
        metrics=metrics,
        baseline=baseline,
        deltas=deltas,
        gate=gate,
    )
