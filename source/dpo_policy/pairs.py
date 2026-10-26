"""偏好对构建：把同一 prompt 的多条候选筛成一条可解释的 chosen / rejected。

本模块只回答一个问题："这一对候选能不能当训练用的偏好对，凭什么"。它不读文件、
不写产物、不判授权、不做脱敏、不碰墙上时间。

明确不做的事：

- **不自己造来源绑定**：``source`` 一律来自 :meth:`SourceRegistry.resolve`，
  授权闸门的判定结果原样带进产物，不做"降级成无来源"的兜底；
- **不自己脱敏**：所有正文（prompt 与候选）先过 :class:`Anonymizer`，
  再 ``assert_clean``；复检命中就整条 prompt 拒绝，不存在"打码后继续"的路径；
- **不因单条数据有问题而中断整批**：字段缺失、来源未授权、分数不够、长度失衡、
  去重命中，都只进 ``rejected`` 与 ``stats``；只有配置/用法问题（例如 ``cfg.pairs``
  缺键）才抛 ``PipelineError``；
- **不做"多轴综合打分"**：一条偏好对只声明一个决定性轴，其它轴只用于"反超检查"。
  多轴混成一个总分就无法解释"为什么选它"，训练信号也会变得不可审计。

为什么先脱敏再比较：长度上下界、去重键、``pair_id`` 都必须基于"真正要交付的正文"。
如果先用原文算、再替换，同一对候选会因为原文与伪名的长度差得到不同结论，复跑不可比。
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable, Mapping

from .anonymize import Anonymizer
from .config import Config
from .model import (
    Candidate,
    ContrastSpec,
    ErrorCode,
    GenerationRecord,
    LogicalClock,
    PipelineError,
    PreferencePair,
    SourceBinding,
    as_float,
    as_int,
    make_pair_id,
    normalize_text,
    text_fingerprint,
)
from .provenance import SourceRegistry

__all__ = ["PairBuildResult", "build_pairs"]

#: 偏好对的对比规则编号，指向 ``config/policy_rules.json`` 里的 R-PREF-01，
#: 产物只引用编号不复制条文，规则改一次三处产物同步变。
PREF_RULE_ID = "R-PREF-01"


@dataclass(frozen=True)
class PairBuildResult:
    """一次构建的完整结果：产物、统计、以及每条被拒记录的原因。

    ``rejected`` 的每一项形如 ``{"prompt_id", "reason", "detail"}``；
    ``detail`` 只放候选 id、长度、分差这类元信息，不放正文。
    """

    pairs: tuple[PreferencePair, ...]
    stats: Mapping[str, Any]
    rejected: tuple[Mapping[str, Any], ...]


# ---------------------------------------------------------------- 配置口径


@dataclass(frozen=True)
class _Params:
    """``cfg.pairs`` 的类型化快照，避免在循环里反复 ``dict.get`` 与隐式转换。"""

    axes: tuple[str, ...]
    min_margin: float
    required_axis_delta: float
    cross_axis_tolerance: float
    min_score: float
    max_length_ratio: float
    min_chars: int
    max_chars: int
    max_pairs_per_prompt: int
    dedupe_min_chars: int


def _read_params(cfg: Config) -> _Params:
    """读取并做最小上限校验；缺键或类型不对属于配置问题，直接抛 ``CONFIG_INVALID``。

    这里不重复配置层的区间校验（那是 ``config.py`` 的职责），只保证本模块拿到的
    每个键都存在且是本模块能安全算术的类型，避免把 ``KeyError``/``TypeError``
    当成业务拒绝吞掉。
    """
    raw = cfg.pairs
    if not isinstance(raw, Mapping):
        raise PipelineError(ErrorCode.CONFIG_INVALID, "cfg.pairs 必须是对象")

    axes_raw = raw.get("axes")
    axes = tuple(str(axis) for axis in axes_raw) if isinstance(axes_raw, (list, tuple)) else ()
    if not axes:
        raise PipelineError(ErrorCode.CONFIG_INVALID, "cfg.pairs.axes 必须是非空数组")

    def number(key: str) -> float:
        value = as_float(raw.get(key))
        if value is None:
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"cfg.pairs.{key} 必须是数字", detail=raw.get(key))
        return value

    def integer(key: str, *, default: int | None = None) -> int:
        if key not in raw and default is not None:
            return default
        value = as_int(raw.get(key))
        if value is None:
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"cfg.pairs.{key} 必须是整数", detail=raw.get(key))
        return value

    dedupe_raw = raw.get("dedupe")
    dedupe = dedupe_raw if isinstance(dedupe_raw, Mapping) else {}
    dedupe_min_chars = as_int(dedupe.get("min_chars"))
    if dedupe_min_chars is None:
        raise PipelineError(ErrorCode.CONFIG_INVALID, "cfg.pairs.dedupe.min_chars 必须是整数", detail=dedupe.get("min_chars"))

    return _Params(
        axes=axes,
        min_margin=number("min_margin"),
        required_axis_delta=number("required_axis_delta"),
        cross_axis_tolerance=number("cross_axis_tolerance"),
        min_score=number("min_score"),
        max_length_ratio=number("max_length_ratio"),
        min_chars=integer("min_chars"),
        max_chars=integer("max_chars"),
        max_pairs_per_prompt=integer("max_pairs_per_prompt"),
        dedupe_min_chars=int(dedupe_min_chars),
    )


# ---------------------------------------------------------------- 内部结果类型


@dataclass(frozen=True)
class _Rejection:
    """一条候选对被某个闸门挡下：码 + 元信息（保证不含正文）。"""

    code: str
    detail: Mapping[str, Any]


@dataclass(frozen=True)
class _Seed:
    """已通过全部筛选、等待排序与时间戳的偏好对原料。"""

    pair_id: str
    prompt_id: str
    prompt: str
    chosen: Candidate
    rejected: Candidate
    contrast: ContrastSpec
    source: SourceBinding
    dedupe_key: str
    axis_margin: float
    score_margin: float


@dataclass(frozen=True)
class _Outcome:
    """单条 prompt 的处理结果。"""

    rejections: tuple[Mapping[str, Any], ...]
    seeds: tuple[_Seed, ...]
    duplicates: int
    record_rejected: bool


# ---------------------------------------------------------------- 入口


def build_pairs(
    generations: Iterable[GenerationRecord],
    registry: SourceRegistry,
    anonymizer: Anonymizer,
    cfg: Config,
    clock: LogicalClock,
) -> PairBuildResult:
    """构建偏好对。

    步骤与理由对应如下：

    1. 按 ``prompt_id`` 排序：输入可能来自 JSONL、也可能来自调用方拼的列表，
       排序后"先到先得"的去重语义才有确定的含义；
    2. 逐条做记录级校验：不合法只影响这条 prompt；
    3. 来源解析走授权闸门，抛什么码就记什么码（不降级、不静默放行）；
    4. 先脱敏再判残留，命中即整条拒绝；
    5. 候选对筛选（分数、长度、文本、决定性轴、反超、总分差、去重、每 prompt 上限）；
    6. 组装 ``PreferencePair``，时刻由逻辑时钟按最终排序逐条发放。
    """
    params = _read_params(cfg)
    records = _sorted_records(generations)

    rejected: list[dict[str, Any]] = []
    filter_counts: dict[str, int] = {}
    seeds: list[_Seed] = []
    emitted_keys: set[str] = set()
    duplicates = 0
    record_rejections = 0
    candidates_total = 0

    for record in records:
        candidates_total += len(tuple(record.candidates or ()))
        outcome = _process_record(record, params, registry, anonymizer, emitted_keys)
        for item in outcome.rejections:
            rejected.append(dict(item))
            code = str(item["reason"])
            filter_counts[code] = filter_counts.get(code, 0) + 1
        if outcome.record_rejected:
            record_rejections += 1
        duplicates += outcome.duplicates
        seeds.extend(outcome.seeds)

    # 先按 pair_id 排序，再逐条取时刻：这样 created_at 与产物顺序同向单调，
    # 且与输入顺序无关（同一批数据无论怎么喂进来都得到同一串时间戳）。
    ordered_seeds = sorted(seeds, key=lambda seed: seed.pair_id)
    pairs: list[PreferencePair] = []
    for seed in ordered_seeds:
        pairs.append(
            PreferencePair(
                pair_id=seed.pair_id,
                prompt_id=seed.prompt_id,
                prompt=seed.prompt,
                chosen=seed.chosen,
                rejected=seed.rejected,
                contrast=seed.contrast,
                source=seed.source,
                pipeline_version=cfg.pipeline_version,
                created_at=clock.now(),
                dedupe_key=seed.dedupe_key,
                anonymized=True,
            )
        )
    pair_tuple = tuple(pairs)

    axis_counts: dict[str, int] = {}
    for pair in pair_tuple:
        axis_counts[pair.contrast.axis] = axis_counts.get(pair.contrast.axis, 0) + 1

    stats: dict[str, Any] = {
        "generations": len(records),
        "candidates": candidates_total,
        "emitted": len(pair_tuple),
        # rejected_records 只数"整条 prompt 被拒"（记录级），pair 级过滤单独进 filters，
        # 否则"三条候选全被过滤"和"prompt 字段非法"会被混成一个数字。
        "rejected_records": record_rejections,
        "filters": {code: filter_counts[code] for code in sorted(filter_counts)},
        "axes": {axis: axis_counts.get(axis, 0) for axis in params.axes},
        "duplicates": duplicates,
        "avg_axis_margin": _mean([pair.contrast.margin for pair in pair_tuple]),
        "avg_score_margin": _mean([_num(pair.chosen.score) - _num(pair.rejected.score) for pair in pair_tuple]),
    }
    return PairBuildResult(pairs=pair_tuple, stats=stats, rejected=tuple(rejected))


# ---------------------------------------------------------------- 单条 prompt


def _process_record(
    record: GenerationRecord,
    params: _Params,
    registry: SourceRegistry,
    anonymizer: Anonymizer,
    emitted_keys: set[str],
) -> _Outcome:
    """处理一条 generation：要么给出最多 ``max_pairs_per_prompt`` 条原料，要么给出拒绝原因。

    函数内不会抛业务异常：记录级问题在这里就地转成 ``_Outcome``。只有配置/用法
    异常（例如脱敏规则本身不可用）才继续向上抛。
    """
    prompt_id = str(record.prompt_id or "").strip()
    prompt_raw = record.prompt
    rejections: list[dict[str, Any]] = []

    def drop(code: str, detail: Mapping[str, Any]) -> _Outcome:
        rejections.append(_entry(prompt_id, code, detail))
        return _Outcome(tuple(rejections), (), 0, True)

    if not prompt_id:
        return drop(ErrorCode.PAIR_SCHEMA_INVALID, {"field": "prompt_id"})
    if not isinstance(prompt_raw, str) or not prompt_raw.strip():
        return drop(ErrorCode.PAIR_SCHEMA_INVALID, {"field": "prompt"})

    source_ref = record.source_ref if isinstance(record.source_ref, Mapping) else {}
    ref_id = source_ref.get("source_id")
    ref_version = source_ref.get("version")
    if not (isinstance(ref_id, str) and ref_id.strip() and isinstance(ref_version, str) and ref_version.strip()):
        # 引用本身不成形状属于记录级 schema 问题，和"引用了不存在来源"分开记码：
        # 前者是数据造错了，后者是授权面不够。
        return drop(ErrorCode.PAIR_SCHEMA_INVALID, {"field": "source_ref"})

    raw_candidates = tuple(record.candidates or ())
    if len(raw_candidates) < 2:
        return drop(ErrorCode.PAIR_NO_CANDIDATE, {"candidates": len(raw_candidates)})

    problem = _candidate_schema_problem(raw_candidates, params.axes)
    if problem is not None:
        return drop(ErrorCode.PAIR_SCHEMA_INVALID, problem)

    # 第 3 步：授权闸门。抛什么码就记什么码，不把未授权来源"降级"成可用来源。
    try:
        binding = registry.resolve(record.source_ref, record_id=prompt_id)
    except PipelineError as exc:
        return drop(exc.code, {"source_id": str(ref_id).strip(), "version": str(ref_version).strip()})

    # 第 4 步：先脱敏再自检。复检命中就整条拒绝，不保留任何"打过码"的正文。
    try:
        prompt_clean = anonymizer.redact_text(prompt_raw)
        anonymizer.assert_clean(prompt_clean, record_id=prompt_id)
        clean_candidates: list[Candidate] = []
        for candidate in raw_candidates:
            text_clean = anonymizer.redact_text(candidate.text)
            anonymizer.assert_clean(text_clean, record_id=prompt_id)
            clean_candidates.append(replace(candidate, text=text_clean))
    except PipelineError as exc:
        if exc.code != ErrorCode.ANON_LEAK:
            raise
        return drop(ErrorCode.ANON_LEAK, {"kinds": _kinds_of(exc)})

    # 第 5 步：候选对筛选。候选先按 candidate_id 排序，保证枚举顺序与输入顺序无关。
    ordered = tuple(sorted(clean_candidates, key=lambda item: item.candidate_id))
    available: list[_Seed] = []
    duplicates = 0
    for left in range(len(ordered)):
        for right in range(left + 1, len(ordered)):
            outcome = _evaluate_pair(
                ordered[left],
                ordered[right],
                params=params,
                prompt_id=prompt_id,
                prompt=prompt_clean,
                binding=binding,
            )
            if isinstance(outcome, _Rejection):
                rejections.append(_entry(prompt_id, outcome.code, outcome.detail))
                continue
            if _dedupe_applies(outcome, params) and outcome.dedupe_key in emitted_keys:
                duplicates += 1
                rejections.append(
                    _entry(
                        prompt_id,
                        ErrorCode.PAIR_DUPLICATE,
                        {
                            "candidate_ids": [outcome.chosen.candidate_id, outcome.rejected.candidate_id],
                            "axes": outcome.contrast.axis,
                        },
                    )
                )
                continue
            available.append(outcome)

    if not available:
        return _Outcome(tuple(rejections), (), duplicates, False)

    # 每 prompt 上限：在可用对里取(轴分差更大, 总分差更大)的那条，其余不记拒绝——
    # "被上限挤掉"不是数据缺陷，记进 rejected 会把过滤统计污染成噪声。
    available.sort(key=lambda seed: (-seed.axis_margin, -seed.score_margin, seed.pair_id))
    kept = tuple(available[: params.max_pairs_per_prompt])
    for seed in kept:
        if _dedupe_applies(seed, params):
            emitted_keys.add(seed.dedupe_key)
    return _Outcome(tuple(rejections), kept, duplicates, False)


def _entry(prompt_id: str, reason: str, detail: Mapping[str, Any]) -> dict[str, Any]:
    return {"prompt_id": prompt_id, "reason": reason, "detail": dict(detail)}


def _kinds_of(exc: PipelineError) -> list[str]:
    detail = exc.detail
    if isinstance(detail, Mapping):
        kinds = detail.get("kinds")
        if isinstance(kinds, (list, tuple)):
            return [str(kind) for kind in kinds]
    return []


def _dedupe_applies(seed: _Seed, params: _Params) -> bool:
    """只有长度达到 ``dedupe.min_chars`` 的正文才参与去重。

    太短的文本重复出现不代表语义重复（例如同一句模板话术），把它们并成一条
    会凭空减少样本；这个阈值就是"从多长开始，重复才算重复"的口径。
    """
    floor = params.dedupe_min_chars
    return len(seed.chosen.text) >= floor and len(seed.rejected.text) >= floor


def _candidate_schema_problem(candidates: tuple[Candidate, ...], axes: tuple[str, ...]) -> dict[str, Any] | None:
    """候选级 schema 检查：返回第一个问题的说明，全部合格返回 ``None``。

    先查完所有候选再进入配对，避免"坏候选"在配对阶段炸成 TypeError；
    检查项与契约一一对应（id 唯一非空、text 非空、score 在 [0,1]、轴覆盖齐全）。
    """
    seen: set[str] = set()
    for candidate in candidates:
        cid = getattr(candidate, "candidate_id", "")
        if not isinstance(cid, str) or not cid.strip():
            return {"field": "candidate_id", "candidates": len(candidates)}
        cid = cid.strip()
        if cid in seen:
            return {"field": "candidate_id", "candidate_id": cid, "problem": "duplicate"}
        seen.add(cid)

        text = getattr(candidate, "text", "")
        if not isinstance(text, str) or not text.strip():
            return {"field": "text", "candidate_id": cid}

        score = as_float(getattr(candidate, "score", None))
        if score is None or not (0.0 <= score <= 1.0):
            return {"field": "score", "candidate_id": cid}

        axes_raw = getattr(candidate, "axes", None)
        if not isinstance(axes_raw, Mapping):
            return {"field": "axes", "candidate_id": cid}
        for axis in axes:
            if as_float(axes_raw.get(axis)) is None:
                return {"field": "axes", "candidate_id": cid, "axis": axis}
    return None


def _evaluate_pair(
    left: Candidate,
    right: Candidate,
    *,
    params: _Params,
    prompt_id: str,
    prompt: str,
    binding: SourceBinding,
) -> _Seed | _Rejection:
    """判定一对候选：通过则返回原料，否则返回带码的拒绝说明。

    检查顺序固定为"便宜且无方向的先做"（分数、长度、文本是否相同），
    再做"必须先定出决定性轴才能做"的检查（分差、反超、总分差）。
    顺序固定是为了让同一份坏数据永远落到同一个错误码上，可复现。
    """
    lengths = [len(left.text), len(right.text)]
    meta: dict[str, Any] = {
        "candidate_ids": [left.candidate_id, right.candidate_id],
        "lengths": lengths,
        "scores": [_num(left.score), _num(right.score)],
    }

    if _num(left.score) < params.min_score or _num(right.score) < params.min_score:
        return _Rejection(ErrorCode.PAIR_SCORE_TOO_LOW, {**meta, "min_score": params.min_score})

    if min(lengths) < params.min_chars or max(lengths) > params.max_chars:
        return _Rejection(
            ErrorCode.PAIR_LENGTH_OUT_OF_BOUNDS,
            {**meta, "min_chars": params.min_chars, "max_chars": params.max_chars},
        )

    # min(lengths) 已保证 >= min_chars >= 1，这里不会除零。
    ratio = max(lengths) / min(lengths)
    if ratio > params.max_length_ratio:
        return _Rejection(
            ErrorCode.PAIR_LENGTH_IMBALANCE,
            {**meta, "ratio": round(ratio, 6), "max_length_ratio": params.max_length_ratio},
        )

    if normalize_text(left.text) == normalize_text(right.text):
        return _Rejection(ErrorCode.PAIR_IDENTICAL_TEXT, {**meta, "fingerprint": text_fingerprint(left.text)})

    # 决定性轴：|delta| 最大者；并列时保留声明顺序靠前的轴（结果与遍历方式无关）。
    raw_deltas = {axis: _num(left.axis(axis)) - _num(right.axis(axis)) for axis in params.axes}
    deltas = {axis: round(raw_deltas[axis], 6) for axis in params.axes}
    best_axis = params.axes[0]
    best_abs = abs(deltas[best_axis])
    for axis in params.axes[1:]:
        candidate_abs = abs(deltas[axis])
        if candidate_abs > best_abs:
            best_axis, best_abs = axis, candidate_abs

    # 比较在四舍五入后的值上做：浮点尾差不能让同一份数据在不同解释器上换一种结论。
    if best_abs < params.required_axis_delta:
        return _Rejection(
            ErrorCode.PAIR_AXIS_NOT_DECISIVE,
            {**meta, "axis": best_axis, "axis_delta": best_abs, "required_axis_delta": params.required_axis_delta},
        )

    if deltas[best_axis] >= 0:
        chosen, rejected_candidate, sign = left, right, 1.0
    else:
        chosen, rejected_candidate, sign = right, left, -1.0
    axis_deltas = {axis: round(raw_deltas[axis] * sign, 6) for axis in params.axes}
    axis_margin = round(abs(raw_deltas[best_axis]), 6)

    for axis in params.axes:
        if axis_deltas[axis] < -params.cross_axis_tolerance:
            return _Rejection(
                ErrorCode.PAIR_CROSS_AXIS_REVERSAL,
                {
                    **meta,
                    "decisive_axis": best_axis,
                    "axis": axis,
                    "chosen_delta": axis_deltas[axis],
                    "cross_axis_tolerance": params.cross_axis_tolerance,
                },
            )

    score_margin = round(_num(chosen.score) - _num(rejected_candidate.score), 6)
    if score_margin < params.min_margin:
        return _Rejection(
            ErrorCode.PAIR_LOW_MARGIN,
            {**meta, "decisive_axis": best_axis, "score_margin": score_margin, "min_margin": params.min_margin},
        )

    dedupe_key = f"{text_fingerprint(chosen.text)}|{text_fingerprint(rejected_candidate.text)}"
    contrast = ContrastSpec(axis=best_axis, margin=axis_margin, axis_deltas=axis_deltas, rule=PREF_RULE_ID)
    return _Seed(
        pair_id=make_pair_id(prompt_id, chosen.text, rejected_candidate.text, best_axis),
        prompt_id=prompt_id,
        prompt=prompt,
        chosen=chosen,
        rejected=rejected_candidate,
        contrast=contrast,
        source=binding,
        dedupe_key=dedupe_key,
        axis_margin=axis_margin,
        score_margin=score_margin,
    )


# ---------------------------------------------------------------- 小工具


def _sorted_records(generations: Iterable[GenerationRecord]) -> tuple[GenerationRecord, ...]:
    """按 (prompt_id, prompt) 排序，并把映射形态的输入统一成模型对象。

    加 prompt 作第二排序键，是为了在"同一 prompt_id 出现两次"的坏输入下也有确定顺序：
    pair_id 由内容决定，但"谁先占住去重键"必须可复现。
    """
    normalized: list[GenerationRecord] = []
    for item in generations:
        if isinstance(item, GenerationRecord):
            normalized.append(item)
        elif isinstance(item, Mapping):
            normalized.append(GenerationRecord.from_dict(item))
        else:
            raise PipelineError(
                ErrorCode.PAIR_SCHEMA_INVALID,
                "build_pairs 只接受 GenerationRecord 或其映射",
                detail={"type": type(item).__name__},
            )
    return tuple(sorted(normalized, key=lambda item: (str(item.prompt_id), str(item.prompt))))


def _num(value: Any) -> float:
    """把已通过 schema 检查的分值转成 float；不合格的当成 0.0。"""
    parsed = as_float(value)
    return 0.0 if parsed is None else parsed


def _mean(values: list[float]) -> float:
    """均值，四舍五入到 6 位；空集合记 0.0（报告里不能出现 NaN）。"""
    if not values:
        return 0.0
    return round(sum(values) / len(values), 6)
