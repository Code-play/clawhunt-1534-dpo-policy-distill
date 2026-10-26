"""记录级字段校验：产物与样例共用一套口径。

本模块回答一个问题："这条记录符不符合规范"。它不判业务价值（偏好对的对比是否可信是
:mod:`dpo_policy.pairs` 的事），只判字段的类型/长度/枚举/引用/指纹格式是否成立。

为什么产物还要再校验一遍：产物是"要交给买家、要进回归、要被复跑"的东西，任何一次
手工改动或半途失败都可能写出一条结构上不完整的记录。校验放在写盘之前，失败落到
``SCHEMA_INVALID``，比等到买家发现少字段强。

错误信息里只放字段名、期望与实际问题码，**不放正文**：校验报告本身不应该成为泄漏点。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Sequence

from . import model
from .config import Config

__all__ = [
    "Issue",
    "validate_bundle",
    "validate_generation",
    "validate_golden_case",
    "validate_pair",
    "validate_report",
    "validate_source_record",
    "validate_triple",
    "assert_bundle_valid",
]

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_PAIR_ID = re.compile(r"^pair_[0-9a-f]{16}$")
_TRIPLE_ID = re.compile(r"^tri_[0-9a-f]{16}$")
_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_SOURCE_ID = re.compile(r"^[A-Z][A-Z0-9-]{2,40}$")


@dataclass(frozen=True)
class Issue:
    """一条校验问题：位置 + 字段 + 期望 + 实际。"""

    record_id: str
    field: str
    expected: str
    actual: str
    code: str = model.ErrorCode.SCHEMA_INVALID

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "record_id": self.record_id,
            "field": self.field,
            "expected": self.expected,
            "actual": self.actual,
        }

    def __str__(self) -> str:  # pragma: no cover - 只影响日志
        return f"{self.code} {self.record_id}.{self.field}: 期望 {self.expected}，实际 {self.actual}"


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _non_empty_str(value: Any) -> bool:
    return isinstance(value, str) and value.strip() != ""


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _short(value: Any, limit: int = 40) -> str:
    """把实际值压成短串进报告，避免把正文带进校验信息。"""
    if value is None:
        return "None"
    if isinstance(value, str):
        return f"<str:{len(value)}B>"
    if isinstance(value, (list, tuple)):
        return f"<{type(value).__name__}:{len(value)}>"
    if isinstance(value, Mapping):
        return f"<dict:{len(value)}>"
    return str(value)[:limit]


def _check_binding(raw: Any, where: str, issues: list[Issue], *, record_id: str, cfg: Config) -> None:
    if not isinstance(raw, Mapping):
        issues.append(Issue(record_id, f"{where}", "SourceBinding 对象", _short(raw)))
        return
    if not _non_empty_str(raw.get("source_id")) or not _SOURCE_ID.match(str(raw.get("source_id"))):
        issues.append(Issue(record_id, f"{where}.source_id", "形如 SRC-XXX-001 的来源编号", _short(raw.get("source_id"))))
    if not _non_empty_str(raw.get("version")):
        issues.append(Issue(record_id, f"{where}.version", "非空版本号", _short(raw.get("version"))))
    license_name = raw.get("license")
    if not _non_empty_str(license_name):
        issues.append(Issue(record_id, f"{where}.license", "非空许可名", _short(license_name)))
    elif not cfg.license_allowed(str(license_name)):
        issues.append(Issue(record_id, f"{where}.license", "允许清单内的许可", str(license_name)))
    digest = raw.get("content_sha256")
    if not _is_str(digest) or not _HEX64.match(digest):
        issues.append(Issue(record_id, f"{where}.content_sha256", "64 位小写 hex", _short(digest)))
    if not _non_empty_str(raw.get("authorization_ref")):
        issues.append(Issue(record_id, f"{where}.authorization_ref", "非空授权编号", _short(raw.get("authorization_ref"))))


def validate_source_record(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = str(raw.get("source_id") or "<source>")
    for field in ("source_id", "version", "license", "title", "text"):
        if not _non_empty_str(raw.get(field)):
            issues.append(Issue(record_id, field, "非空字符串", _short(raw.get(field))))
    if not _SOURCE_ID.match(str(raw.get("source_id") or "")):
        issues.append(Issue(record_id, "source_id", "形如 SRC-XXX-001", _short(raw.get("source_id"))))
    declared = raw.get("content_sha256")
    if declared is not None:
        try:
            actual = model.SourceRecord.from_dict(raw).content_sha256()
        except Exception:  # noqa: BLE001 - 字段坏了就没法复算，下面另有字段级问题
            actual = ""
        if declared != actual:
            issues.append(Issue(record_id, "content_sha256", "可由正文复算的指纹", "不一致"))
    return tuple(issues)


def validate_generation(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = str(raw.get("prompt_id") or "<generation>")
    if not _non_empty_str(raw.get("prompt_id")):
        issues.append(Issue(record_id, "prompt_id", "非空字符串", _short(raw.get("prompt_id"))))
    if not _non_empty_str(raw.get("prompt")):
        issues.append(Issue(record_id, "prompt", "非空字符串", _short(raw.get("prompt"))))
    ref = raw.get("source_ref")
    if not isinstance(ref, Mapping):
        issues.append(Issue(record_id, "source_ref", "对象", _short(ref)))
    else:
        if not _non_empty_str(ref.get("source_id")):
            issues.append(Issue(record_id, "source_ref.source_id", "非空字符串", _short(ref.get("source_id"))))
        if not _non_empty_str(ref.get("version")):
            issues.append(Issue(record_id, "source_ref.version", "非空字符串", _short(ref.get("version"))))
    candidates = raw.get("candidates")
    if not isinstance(candidates, (list, tuple)) or len(candidates) < 1:
        issues.append(Issue(record_id, "candidates", "至少 1 条候选（<2 条由偏好对闸门拒绝）", f"<{type(candidates).__name__}>"))
    else:
        seen: set[str] = set()
        for i, cand in enumerate(candidates):
            if not isinstance(cand, Mapping):
                issues.append(Issue(record_id, f"candidates[{i}]", "对象", _short(cand)))
                continue
            cid = cand.get("candidate_id")
            if not _non_empty_str(cid):
                issues.append(Issue(record_id, f"candidates[{i}].candidate_id", "非空字符串", _short(cid)))
            elif cid in seen:
                issues.append(Issue(record_id, f"candidates[{i}].candidate_id", "同一 prompt 内唯一", str(cid)))
            else:
                seen.add(str(cid))
            if not _non_empty_str(cand.get("text")):
                issues.append(Issue(record_id, f"candidates[{i}].text", "非空字符串", _short(cand.get("text"))))
            score = cand.get("score")
            if not _is_number(score) or not (0.0 <= float(score) <= 1.0):
                issues.append(Issue(record_id, f"candidates[{i}].score", "0..1 的数字", _short(score)))
            axes = cand.get("axes")
            if not isinstance(axes, Mapping):
                issues.append(Issue(record_id, f"candidates[{i}].axes", "对象", _short(axes)))
            else:
                # 这里只要求"给了的轴是数字"；覆盖全部轴是偏好对闸门的职责（缺轴 -> PAIR_SCHEMA_INVALID），
                # 免得把一条数据问题升级成"整份样例不可用"。
                for axis, value in axes.items():
                    if not _is_number(value):
                        issues.append(Issue(record_id, f"candidates[{i}].axes.{axis}", "数字", _short(value)))
    return tuple(issues)


def validate_pair(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = str(raw.get("pair_id") or "<pair>")
    if not _is_str(raw.get("pair_id")) or not _PAIR_ID.match(str(raw.get("pair_id"))):
        issues.append(Issue(record_id, "pair_id", "pair_ + 16 位 hex", _short(raw.get("pair_id"))))
    for field in ("prompt_id", "dedupe_key"):
        if not _non_empty_str(raw.get(field)):
            issues.append(Issue(record_id, field, "非空字符串", _short(raw.get(field))))
    if not _non_empty_str(raw.get("prompt")):
        issues.append(Issue(record_id, "prompt", "非空字符串", _short(raw.get("prompt"))))
    for side in ("chosen", "rejected"):
        cand = raw.get(side)
        if not isinstance(cand, Mapping):
            issues.append(Issue(record_id, side, "候选对象", _short(cand)))
            continue
        if not _non_empty_str(cand.get("candidate_id")):
            issues.append(Issue(record_id, f"{side}.candidate_id", "非空字符串", _short(cand.get("candidate_id"))))
        if not _non_empty_str(cand.get("text")):
            issues.append(Issue(record_id, f"{side}.text", "非空字符串", _short(cand.get("text"))))
        if not _is_number(cand.get("score")) or not (0.0 <= float(cand.get("score", -1)) <= 1.0):
            issues.append(Issue(record_id, f"{side}.score", "0..1 的数字", _short(cand.get("score"))))
        axes = cand.get("axes")
        if not isinstance(axes, Mapping):
            issues.append(Issue(record_id, f"{side}.axes", "对象", _short(axes)))
        else:
            for axis in cfg.axes:
                if not _is_number(axes.get(axis)):
                    issues.append(Issue(record_id, f"{side}.axes.{axis}", "数字", _short(axes.get(axis))))
    contrast = raw.get("contrast")
    if not isinstance(contrast, Mapping):
        issues.append(Issue(record_id, "contrast", "对象", _short(contrast)))
    else:
        axis = contrast.get("axis")
        if axis not in cfg.axes:
            issues.append(Issue(record_id, "contrast.axis", f"属于 {list(cfg.axes)}", _short(axis)))
        margin = contrast.get("margin")
        if not _is_number(margin) or float(margin) < 0.0:
            issues.append(Issue(record_id, "contrast.margin", "非负数字", _short(margin)))
        elif float(margin) + 1e-9 < float(cfg.pairs["required_axis_delta"]):
            issues.append(Issue(record_id, "contrast.margin", f">= {cfg.pairs['required_axis_delta']}", str(margin)))
        deltas = contrast.get("axis_deltas")
        if not isinstance(deltas, Mapping):
            issues.append(Issue(record_id, "contrast.axis_deltas", "对象", _short(deltas)))
        else:
            for axis_name in cfg.axes:
                if not _is_number(deltas.get(axis_name)):
                    issues.append(Issue(record_id, f"contrast.axis_deltas.{axis_name}", "数字", _short(deltas.get(axis_name))))
    _check_binding(raw.get("source"), "source", issues, record_id=record_id, cfg=cfg)
    if raw.get("pipeline_version") != cfg.pipeline_version:
        issues.append(Issue(record_id, "pipeline_version", cfg.pipeline_version, _short(raw.get("pipeline_version"))))
    if not _is_str(raw.get("created_at")) or not _TS.match(str(raw.get("created_at"))):
        issues.append(Issue(record_id, "created_at", "YYYY-MM-DDTHH:MM:SSZ", _short(raw.get("created_at"))))
    if raw.get("anonymized") is not True:
        issues.append(Issue(record_id, "anonymized", "True（产物必须是脱敏后的）", _short(raw.get("anonymized"))))
    return tuple(issues)


def validate_triple(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = str(raw.get("triple_id") or "<triple>")
    if not _is_str(raw.get("triple_id")) or not _TRIPLE_ID.match(str(raw.get("triple_id"))):
        issues.append(Issue(record_id, "triple_id", "tri_ + 16 位 hex", _short(raw.get("triple_id"))))
    for field in ("trace_id", "instruction", "output", "dedupe_key"):
        if not _non_empty_str(raw.get(field)):
            issues.append(Issue(record_id, field, "非空字符串", _short(raw.get(field))))
    min_answer = int(cfg.distill["min_answer_chars"])
    if _is_str(raw.get("output")) and len(str(raw["output"])) < min_answer:
        issues.append(Issue(record_id, "output", f">= {min_answer} 字符", f"<{len(str(raw['output']))}B>"))
    rationale = raw.get("rationale")
    lo = int(cfg.distill["min_rationale_steps"])
    hi = int(cfg.distill["max_rationale_steps"])
    if not isinstance(rationale, (list, tuple)) or not (lo <= len(rationale) <= hi):
        issues.append(Issue(record_id, "rationale", f"{lo}..{hi} 条", _short(rationale)))
    else:
        for i, item in enumerate(rationale):
            if not _non_empty_str(item):
                issues.append(Issue(record_id, f"rationale[{i}]", "非空字符串", _short(item)))
    refs = raw.get("policy_refs")
    known = set(cfg.policy_rule_index())
    if not isinstance(refs, (list, tuple)) or not refs:
        issues.append(Issue(record_id, "policy_refs", "非空数组", _short(refs)))
    else:
        for ref in refs:
            if str(ref) not in known:
                issues.append(Issue(record_id, "policy_refs", "规则库内的 rule_id", _short(ref)))
    if raw.get("target") not in tuple(cfg.distill["targets"]):
        issues.append(Issue(record_id, "target", f"属于 {list(cfg.distill['targets'])}", _short(raw.get("target"))))
    if raw.get("adapter") not in cfg.adapters:
        issues.append(Issue(record_id, "adapter", f"属于 {list(cfg.adapters)}", _short(raw.get("adapter"))))
    _check_binding(raw.get("source"), "source", issues, record_id=record_id, cfg=cfg)
    if raw.get("pipeline_version") != cfg.pipeline_version:
        issues.append(Issue(record_id, "pipeline_version", cfg.pipeline_version, _short(raw.get("pipeline_version"))))
    if not _is_str(raw.get("created_at")) or not _TS.match(str(raw.get("created_at"))):
        issues.append(Issue(record_id, "created_at", "YYYY-MM-DDTHH:MM:SSZ", _short(raw.get("created_at"))))
    return tuple(issues)


def validate_golden_case(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = str(raw.get("case_id") or "<case>")
    if not _non_empty_str(raw.get("case_id")):
        issues.append(Issue(record_id, "case_id", "非空字符串", _short(raw.get("case_id"))))
    if not _non_empty_str(raw.get("prompt")):
        issues.append(Issue(record_id, "prompt", "非空字符串", _short(raw.get("prompt"))))
    if raw.get("expected_action") not in model.ACTIONS:
        issues.append(Issue(record_id, "expected_action", f"属于 {list(model.ACTIONS)}", _short(raw.get("expected_action"))))
    sources = raw.get("available_sources")
    if not isinstance(sources, (list, tuple)):
        issues.append(Issue(record_id, "available_sources", "数组（可以为空）", _short(sources)))
    else:
        seen: set[str] = set()
        for i, src in enumerate(sources):
            if not isinstance(src, Mapping):
                issues.append(Issue(record_id, f"available_sources[{i}]", "对象", _short(src)))
                continue
            sid = src.get("source_id")
            if not _non_empty_str(sid) or not _SOURCE_ID.match(str(sid)):
                issues.append(Issue(record_id, f"available_sources[{i}].source_id", "形如 SRC-XXX-001", _short(sid)))
            elif str(sid) in seen:
                issues.append(Issue(record_id, f"available_sources[{i}].source_id", "同一用例内唯一", str(sid)))
            else:
                seen.add(str(sid))
            if not _non_empty_str(src.get("version")):
                issues.append(Issue(record_id, f"available_sources[{i}].version", "非空版本号", _short(src.get("version"))))
            if "authorized" in src and not isinstance(src.get("authorized"), (bool, str)):
                issues.append(Issue(record_id, f"available_sources[{i}].authorized", "布尔或字符串", _short(src.get("authorized"))))
    for field in ("required_source_ids", "must_cite", "forbidden_patterns"):
        value = raw.get(field, [])
        if not isinstance(value, (list, tuple)):
            issues.append(Issue(record_id, field, "数组", _short(value)))
    return tuple(issues)


def validate_report(raw: Mapping[str, Any], cfg: Config) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    record_id = "regression_report"
    if not _is_str(raw.get("generated_at")) or not _TS.match(str(raw.get("generated_at"))):
        issues.append(Issue(record_id, "generated_at", "YYYY-MM-DDTHH:MM:SSZ", _short(raw.get("generated_at"))))
    metrics = raw.get("metrics")
    if not isinstance(metrics, Mapping):
        issues.append(Issue(record_id, "metrics", "对象", _short(metrics)))
    else:
        for field in ("cases", "passed", "failed", "pass_rate", "violations"):
            if field not in metrics:
                issues.append(Issue(record_id, f"metrics.{field}", "必填", "缺失"))
        rate = metrics.get("pass_rate")
        if not _is_number(rate) or not (0.0 <= float(rate) <= 1.0):
            issues.append(Issue(record_id, "metrics.pass_rate", "0..1", _short(rate)))
    gate = raw.get("gate")
    if not isinstance(gate, Mapping) or "ok" not in gate:
        issues.append(Issue(record_id, "gate", "含 ok 的对象", _short(gate)))
    cases = raw.get("cases")
    if not isinstance(cases, (list, tuple)) or not cases:
        issues.append(Issue(record_id, "cases", "非空数组", _short(cases)))
    else:
        for i, item in enumerate(cases):
            if not isinstance(item, Mapping) or not _non_empty_str(item.get("case_id")):
                issues.append(Issue(record_id, f"cases[{i}].case_id", "非空字符串", _short(item)))
                continue
            if item.get("actual_action") not in model.ACTIONS:
                issues.append(Issue(record_id, f"cases[{i}].actual_action", f"属于 {list(model.ACTIONS)}", _short(item.get("actual_action"))))
            if not isinstance(item.get("passed"), bool):
                issues.append(Issue(record_id, f"cases[{i}].passed", "布尔", _short(item.get("passed"))))
    return tuple(issues)


_VALIDATORS: Mapping[str, Callable[[Mapping[str, Any], Config], tuple[Issue, ...]]] = {
    "source": validate_source_record,
    "generation": validate_generation,
    "pair": validate_pair,
    "triple": validate_triple,
    "golden_case": validate_golden_case,
    "report": validate_report,
}

#: 需要检查主键唯一性的记录类型 -> 主键字段。
_ID_FIELDS: Mapping[str, str] = {
    "source": "source_id",
    "generation": "prompt_id",
    "pair": "pair_id",
    "triple": "triple_id",
    "golden_case": "case_id",
}


def validate_bundle(kind: str, records: Iterable[Mapping[str, Any]], cfg: Config) -> tuple[Issue, ...]:
    """校验一整批记录：逐条字段校验 + 主键唯一。``kind`` 见 ``_VALIDATORS``。"""
    validator = _VALIDATORS.get(kind)
    if validator is None:
        raise model.PipelineError(model.ErrorCode.SCHEMA_INVALID, f"未知记录类型: {kind}", detail=sorted(_VALIDATORS))
    issues: list[Issue] = []
    seen: dict[str, int] = {}
    for raw in records:
        if not isinstance(raw, Mapping):
            issues.append(Issue("<bundle>", kind, "对象", _short(raw)))
            continue
        issues.extend(validator(raw, cfg))
        id_field = _ID_FIELDS.get(kind)
        if id_field:
            value = str(raw.get(id_field) or "")
            seen[value] = seen.get(value, 0) + 1
            if seen[value] == 2:
                issues.append(Issue(value, id_field, "整批唯一", f"重复 {id_field}"))
    return tuple(issues)


def assert_bundle_valid(kind: str, records: Sequence[Mapping[str, Any]], cfg: Config) -> None:
    """校验不通过就抛 ``SCHEMA_INVALID``；通过则静默返回。"""
    issues = validate_bundle(kind, records, cfg)
    if issues:
        raise model.PipelineError(
            model.ErrorCode.SCHEMA_INVALID,
            f"{kind} 产物校验未通过：{len(issues)} 处问题",
            record_id=issues[0].record_id,
            detail=[issue.to_dict() for issue in issues[:10]],
        )
