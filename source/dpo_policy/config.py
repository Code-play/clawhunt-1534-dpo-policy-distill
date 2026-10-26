"""配置层：加载、自洽校验、交叉校验。

本模块回答一个问题："这次运行的规则是什么"。所有业务阈值、授权元数据、脱敏规则、
策略规则都从 JSON 来，代码里不写死任何一种阈值；配置文件写错时在**启动阶段**就抛
``CONFIG_INVALID``，不允许带着错配置往下跑、最后把错误伪装成"数据不达标"。

三份配置 + 三份登记表（都放在 ``config/``）：

- ``pipeline_config.json``：流水线总配置（版本、逻辑时钟、路径、来源策略、匿名化、
  偏好对筛选阈值、蒸馏参数、回归阈值入口）；
- ``source_registry.json``：授权登记表（每个来源的版本、许可、内容指纹、授权编号、
  生效日期）——这是"只使用获授权或脱敏资料"这条要求的机器化表达；
- ``redaction_rules.json``：脱敏规则（正则 + 掩码）；
- ``policy_rules.json``：策略规则库（偏好对与蒸馏都按 rule_id 引用它）；
- ``regression_config.json``：离线回归的判据（引用标记、拒绝语义、闸门阈值）。

加载期校验分三层，**任何一层不过都不进入业务阶段**：

1. 文件层：文件存在、JSON 可解析；
2. 单文件自洽层：枚举取值、数值区间、正则可编译、主键唯一、时刻可解析；
3. 跨文件一致层：允许/禁止许可不重叠、每个来源条目都有授权编号、红/白名单都非空、
   蒸馏适配器与回归动作都在支持集合内。

显式不做的事：本模块不读样例数据、不判授权、不判偏好对质量 —— 那些是业务闸门，
失败要落到具体错误码上，不能混成"配置错"。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping

from .model import (
    ACTIONS,
    ErrorCode,
    PipelineError,
    TARGETS,
    is_hash_hex,
    parse_ts,
)

__all__ = [
    "Config",
    "PolicyRule",
    "RedactionRule",
    "RegistryEntry",
    "SUPPORTED_ADAPTERS",
    "SUPPORTED_AXES",
    "load_config",
    "load_json_file",
]

#: 支持的做法集合：新增适配器必须同时改这里、distill.py 与配置，避免"配置写了但没人实现"。
SUPPORTED_ADAPTERS: tuple[str, ...] = ("messages", "tool_trace")

#: 支持的打分轴。偏好对的"决定性对比轴"必须落在这个集合里。
SUPPORTED_AXES: tuple[str, ...] = (
    "evidence_citation",
    "policy_compliance",
    "redaction_safety",
    "instruction_following",
)

_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SOURCE_ID_RE = re.compile(r"^[A-Z][A-Z0-9-]{2,40}$")
_RULE_ID_RE = re.compile(r"^R-[A-Z]{2,10}-\d{2}$")


def load_json_file(path: Path, *, label: str) -> Mapping[str, Any]:
    """读一份 JSON 配置；缺文件或解析失败都转成 ``CONFIG_INVALID``。"""
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise PipelineError(ErrorCode.CONFIG_MISSING, f"缺少配置文件: {path.name}", detail=str(exc)) from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipelineError(
            ErrorCode.CONFIG_INVALID,
            f"配置文件不是合法 JSON: {path.name}（第 {exc.lineno} 行）",
            detail=str(exc),
        ) from exc
    if not isinstance(data, Mapping):
        raise PipelineError(ErrorCode.CONFIG_INVALID, f"配置文件顶层必须是对象: {path.name}", detail=label)
    return data


def _require(cond: bool, message: str, *, detail: Any = None) -> None:
    if not cond:
        raise PipelineError(ErrorCode.CONFIG_INVALID, message, detail=detail)


def _require_str(raw: Mapping[str, Any], key: str, *, label: str, allow_empty: bool = False) -> str:
    value = raw.get(key)
    _require(isinstance(value, str) and (allow_empty or value.strip() != ""), f"{label}.{key} 必须是非空字符串", detail=value)
    return str(value)


def _require_number(raw: Mapping[str, Any], key: str, *, label: str, lo: float | None = None, hi: float | None = None) -> float:
    value = raw.get(key)
    _require(isinstance(value, (int, float)) and not isinstance(value, bool), f"{label}.{key} 必须是数字", detail=value)
    out = float(value)
    if lo is not None:
        _require(out >= lo, f"{label}.{key} 必须 >= {lo}", detail=out)
    if hi is not None:
        _require(out <= hi, f"{label}.{key} 必须 <= {hi}", detail=out)
    return out


def _require_int(raw: Mapping[str, Any], key: str, *, label: str, lo: int = 1) -> int:
    value = raw.get(key)
    _require(isinstance(value, int) and not isinstance(value, bool), f"{label}.{key} 必须是整数", detail=value)
    out = int(value)
    _require(out >= lo, f"{label}.{key} 必须 >= {lo}", detail=out)
    return out


# ---------------------------------------------------------------- 登记表条目


@dataclass(frozen=True)
class RegistryEntry:
    """授权登记表里的一条：来源身份 + 版本 + 许可 + 内容指纹 + 授权凭据。"""

    source_id: str
    version: str
    title: str
    license: str
    content_sha256: str
    authorization_ref: str
    effective_at: str
    tags: tuple[str, ...] = ()
    retention_days: int = 365
    notes: str = ""

    def key(self) -> tuple[str, str]:
        return (self.source_id, self.version)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "version": self.version,
            "title": self.title,
            "license": self.license,
            "content_sha256": self.content_sha256,
            "authorization_ref": self.authorization_ref,
            "effective_at": self.effective_at,
            "tags": list(self.tags),
            "retention_days": self.retention_days,
            "notes": self.notes,
        }


@dataclass(frozen=True)
class RedactionRule:
    """一条脱敏规则：正则 + 掩码。命中即替换，替换不保留任何原文片段。"""

    kind: str
    pattern: str
    replacement: str
    flags: str = ""
    description: str = ""

    def compile(self) -> re.Pattern[str]:
        try:
            return re.compile(self.pattern, re.IGNORECASE if "i" in self.flags else 0)
        except re.error as exc:  # pragma: no cover - 加载期已校验
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"脱敏正则不可编译: {self.kind}", detail=str(exc)) from exc


@dataclass(frozen=True)
class PolicyRule:
    """策略规则库的一条。偏好对与蒸馏都只按 rule_id 引用，不复制原文。"""

    rule_id: str
    title: str
    statement: str
    enforcement: str = "offline-regression"
    applies_to: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "statement": self.statement,
            "enforcement": self.enforcement,
            "applies_to": list(self.applies_to),
        }


# ---------------------------------------------------------------- 总配置


@dataclass(frozen=True)
class Config:
    """一次运行的完整配置快照（不可变）。"""

    root: Path
    pipeline: Mapping[str, Any]
    pipeline_version: str
    clock_start: str
    clock_tick_seconds: int
    hash_algorithm: str
    hash_normalization: str
    license_allowlist: tuple[str, ...]
    deny_licenses: tuple[str, ...]
    registry: tuple[RegistryEntry, ...]
    redaction_rules: tuple[RedactionRule, ...]
    leak_patterns: tuple[tuple[str, str], ...]
    anon_salt: str
    pseudonym_len: int
    leak_policy: str
    pairs: Mapping[str, Any]
    distill: Mapping[str, Any]
    regression: Mapping[str, Any]
    policy_rules: tuple[PolicyRule, ...]
    paths: Mapping[str, Path]
    source_files: Mapping[str, str]

    # -- 查询 ---------------------------------------------------------------

    def path(self, key: str) -> Path:
        try:
            return self.paths[key]
        except KeyError as exc:  # pragma: no cover - 配置校验保证 key 存在
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"未知路径键: {key}") from exc

    def registry_index(self) -> dict[tuple[str, str], RegistryEntry]:
        return {e.key(): e for e in self.registry}

    def policy_rule_index(self) -> dict[str, PolicyRule]:
        return {r.rule_id: r for r in self.policy_rules}

    def license_allowed(self, license_name: str) -> bool:
        name = str(license_name or "").strip().lower()
        if name in self.deny_licenses:
            return False
        return name in self.license_allowlist

    @property
    def axes(self) -> tuple[str, ...]:
        return tuple(self.pairs["axes"])

    @property
    def adapters(self) -> tuple[str, ...]:
        return tuple(self.distill["adapters"])

    @property
    def source_policy(self) -> Mapping[str, Any]:
        return self.pipeline.get("sources", {})

    def spec_text(self) -> str:
        """把关键配置压成一段可进报告的说明（不含任何原文）。"""
        thresholds = self.regression.get("thresholds", {})
        return " | ".join(
            [
                f"pipeline={self.pipeline_version}",
                f"clock={self.clock_start}/+{self.clock_tick_seconds}s",
                f"sources={len(self.registry)} registered / allowlist={len(self.license_allowlist)}",
                f"pairs: axis_delta>={self.pairs['required_axis_delta']} margin>={self.pairs['min_margin']} "
                f"ratio<={self.pairs['max_length_ratio']}",
                f"distill: adapters={','.join(self.adapters)} targets={','.join(self.distill['targets'])}",
                f"regression: min_pass_rate>={thresholds.get('min_pass_rate')} max_regressions={thresholds.get('max_regressions')}",
                f"policy_rules={len(self.policy_rules)}",
            ]
        )


# ---------------------------------------------------------------- 加载与校验


def _load_registry(config_dir: Path, raw: Mapping[str, Any]) -> tuple[RegistryEntry, ...]:
    entries_raw = raw.get("sources")
    _require(isinstance(entries_raw, list) and entries_raw, "source_registry.sources 必须是非空数组")
    out: list[RegistryEntry] = []
    seen: set[tuple[str, str]] = set()
    for i, item in enumerate(entries_raw):
        _require(isinstance(item, Mapping), f"source_registry.sources[{i}] 必须是对象")
        label = f"source_registry.sources[{i}]"
        source_id = _require_str(item, "source_id", label=label)
        _require(bool(_SOURCE_ID_RE.match(source_id)), f"{label}.source_id 不符合 [A-Z][A-Z0-9-]{2,40}", detail=source_id)
        version = _require_str(item, "version", label=label)
        title = _require_str(item, "title", label=label)
        license_name = _require_str(item, "license", label=label)
        digest = _require_str(item, "content_sha256", label=label)
        _require(is_hash_hex(digest), f"{label}.content_sha256 必须是 64 位小写 hex", detail=digest)
        auth_ref = _require_str(item, "authorization_ref", label=label)
        effective_at = _require_str(item, "effective_at", label=label)
        _require(bool(_DATE_RE.match(effective_at)), f"{label}.effective_at 必须是 YYYY-MM-DD", detail=effective_at)
        tags = tuple(str(t) for t in (item.get("tags") or ()))
        retention = item.get("retention_days", 365)
        _require(isinstance(retention, int) and retention > 0, f"{label}.retention_days 必须是正整数", detail=retention)
        notes = str(item.get("notes", ""))
        entry = RegistryEntry(
            source_id=source_id,
            version=version,
            title=title,
            license=license_name,
            content_sha256=digest,
            authorization_ref=auth_ref,
            effective_at=effective_at,
            tags=tags,
            retention_days=int(retention),
            notes=notes,
        )
        _require(entry.key() not in seen, f"source_registry 里 (source_id, version) 重复: {source_id}@{version}")
        seen.add(entry.key())
        out.append(entry)
    return tuple(out)


def _load_redaction(config_dir: Path, raw: Mapping[str, Any]) -> tuple[RedactionRule, ...]:
    rules_raw = raw.get("rules")
    _require(isinstance(rules_raw, list) and rules_raw, "redaction_rules.rules 必须是非空数组")
    out: list[RedactionRule] = []
    kinds: set[str] = set()
    for i, item in enumerate(rules_raw):
        _require(isinstance(item, Mapping), f"redaction_rules.rules[{i}] 必须是对象")
        label = f"redaction_rules.rules[{i}]"
        kind = _require_str(item, "kind", label=label)
        _require(kind not in kinds, f"redaction_rules 里 kind 重复: {kind}")
        kinds.add(kind)
        pattern = _require_str(item, "pattern", label=label, allow_empty=False)
        try:
            re.compile(pattern, re.IGNORECASE if "i" in str(item.get("flags", "")) else 0)
        except re.error as exc:
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"{label}.pattern 不可编译", detail=str(exc)) from exc
        replacement = _require_str(item, "replacement", label=label)
        flags = str(item.get("flags", ""))
        _require(set(flags) <= {"i", "m", "s"}, f"{label}.flags 只支持 i/m/s", detail=flags)
        out.append(
            RedactionRule(
                kind=kind,
                pattern=pattern,
                replacement=replacement,
                flags=flags,
                description=str(item.get("description", "")),
            )
        )
    return tuple(out)


def _load_leak_patterns(raw: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """加载脱敏自检模式（产物里出现即视为泄漏）。"""
    leak = raw.get("leak_scan")
    _require(isinstance(leak, Mapping), "redaction_rules.leak_scan 必须是对象")
    patterns_raw = leak.get("patterns")
    _require(isinstance(patterns_raw, list) and patterns_raw, "redaction_rules.leak_scan.patterns 必须是非空数组")
    out: list[tuple[str, str]] = []
    kinds: set[str] = set()
    for i, item in enumerate(patterns_raw):
        _require(isinstance(item, Mapping), f"redaction_rules.leak_scan.patterns[{i}] 必须是对象")
        kind = _require_str(item, "kind", label=f"leak_scan.patterns[{i}]")
        _require(kind not in kinds, f"leak_scan.patterns 里 kind 重复: {kind}")
        kinds.add(kind)
        pattern = _require_str(item, "pattern", label=f"leak_scan.patterns[{i}]")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise PipelineError(ErrorCode.CONFIG_INVALID, f"leak_scan.patterns[{i}].pattern 不可编译", detail=str(exc)) from exc
        out.append((kind, pattern))
    _require(leak.get("policy") in {"block", "warn"}, "redaction_rules.leak_scan.policy 只支持 block/warn", detail=leak.get("policy"))
    return tuple(out)


def _load_policy_rules(raw: Mapping[str, Any]) -> tuple[PolicyRule, ...]:
    rules_raw = raw.get("rules")
    _require(isinstance(rules_raw, list) and rules_raw, "policy_rules.rules 必须是非空数组")
    out: list[PolicyRule] = []
    seen: set[str] = set()
    for i, item in enumerate(rules_raw):
        _require(isinstance(item, Mapping), f"policy_rules.rules[{i}] 必须是对象")
        label = f"policy_rules.rules[{i}]"
        rule_id = _require_str(item, "rule_id", label=label)
        _require(bool(_RULE_ID_RE.match(rule_id)), f"{label}.rule_id 必须形如 R-XXX-00", detail=rule_id)
        _require(rule_id not in seen, f"policy_rules 里 rule_id 重复: {rule_id}")
        seen.add(rule_id)
        title = _require_str(item, "title", label=label)
        statement = _require_str(item, "statement", label=label)
        applies_to = tuple(str(t) for t in (item.get("applies_to") or ()))
        for token in applies_to:
            _require(token in {"pair", "triple", "regression"}, f"{label}.applies_to 只支持 pair/triple/regression", detail=token)
        enforcement = str(item.get("enforcement", "offline-regression"))
        _require(enforcement in {"offline-regression", "gate", "documentation"}, f"{label}.enforcement 取值非法", detail=enforcement)
        out.append(
            PolicyRule(
                rule_id=rule_id,
                title=title,
                statement=statement,
                enforcement=enforcement,
                applies_to=applies_to,
            )
        )
    return tuple(out)


def _validate_pairs(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    _require(isinstance(raw, Mapping), "pipeline_config.pairs 必须是对象")
    axes = raw.get("axes")
    _require(isinstance(axes, list) and axes, "pairs.axes 必须是非空数组")
    for axis in axes:
        _require(axis in SUPPORTED_AXES, f"pairs.axes 含未支持的轴: {axis}", detail=list(SUPPORTED_AXES))
    _require(len(set(axes)) == len(axes), "pairs.axes 不能重复")
    _require_number(raw, "min_margin", label="pairs", lo=0.0, hi=1.0)
    _require_number(raw, "required_axis_delta", label="pairs", lo=0.0, hi=1.0)
    _require_number(raw, "cross_axis_tolerance", label="pairs", lo=0.0, hi=1.0)
    _require_number(raw, "min_score", label="pairs", lo=0.0, hi=1.0)
    ratio = _require_number(raw, "max_length_ratio", label="pairs", lo=1.0)
    _require(ratio > 1.0, "pairs.max_length_ratio 必须 > 1", detail=ratio)
    _require_int(raw, "min_chars", label="pairs", lo=1)
    _require_int(raw, "max_chars", label="pairs", lo=1)
    _require(int(raw["min_chars"]) < int(raw["max_chars"]), "pairs.min_chars 必须小于 max_chars")
    _require_int(raw, "max_pairs_per_prompt", label="pairs", lo=1)
    dedupe = raw.get("dedupe")
    _require(isinstance(dedupe, Mapping), "pairs.dedupe 必须是对象")
    _require(dedupe.get("mode") == "normalized_text", "pairs.dedupe.mode 目前只支持 normalized_text", detail=dedupe.get("mode"))
    _require_int(dedupe, "min_chars", label="pairs.dedupe", lo=1)
    return raw


def _validate_distill(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    _require(isinstance(raw, Mapping), "pipeline_config.distill 必须是对象")
    adapters = raw.get("adapters")
    _require(isinstance(adapters, list) and adapters, "distill.adapters 必须是非空数组")
    for adapter in adapters:
        _require(adapter in SUPPORTED_ADAPTERS, f"distill.adapters 含未实现的适配器: {adapter}", detail=list(SUPPORTED_ADAPTERS))
    targets = raw.get("targets")
    _require(isinstance(targets, list) and targets, "distill.targets 必须是非空数组")
    for target in targets:
        _require(target in TARGETS, f"distill.targets 含非法值: {target}", detail=list(TARGETS))
    lo = _require_int(raw, "min_rationale_steps", label="distill", lo=1)
    hi = _require_int(raw, "max_rationale_steps", label="distill", lo=1)
    _require(lo <= hi, "distill.min_rationale_steps 必须 <= max_rationale_steps")
    _require_int(raw, "min_answer_chars", label="distill", lo=1)
    return raw


def _validate_regression(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    _require(isinstance(raw, Mapping), "regression_config 顶层必须是对象")
    thresholds = raw.get("thresholds")
    _require(isinstance(thresholds, Mapping), "regression_config.thresholds 必须是对象")
    _require_number(thresholds, "min_pass_rate", label="regression.thresholds", lo=0.0, hi=1.0)
    value = thresholds.get("max_regressions")
    _require(isinstance(value, int) and not isinstance(value, bool) and value >= 0, "regression.thresholds.max_regressions 必须 >= 0", detail=value)
    citation = raw.get("citation")
    _require(isinstance(citation, Mapping), "regression_config.citation 必须是对象")
    marker = _require_str(citation, "marker_pattern", label="regression.citation")
    try:
        compiled = re.compile(marker)
    except re.error as exc:
        raise PipelineError(ErrorCode.CONFIG_INVALID, "regression.citation.marker_pattern 不可编译", detail=str(exc)) from exc
    for group in ("source_id", "version"):
        _require(group in compiled.groupindex, f"regression.citation.marker_pattern 缺少命名组 {group}")
    _require(isinstance(citation.get("require_for_actions"), list) and citation["require_for_actions"], "regression.citation.require_for_actions 必须是非空数组")
    for action in citation["require_for_actions"]:
        _require(action in ACTIONS, f"regression.citation.require_for_actions 含非法动作: {action}", detail=list(ACTIONS))
    refusal = raw.get("refusal")
    _require(isinstance(refusal, Mapping), "regression_config.refusal 必须是对象")
    for key in ("actions_for_unauthorized", "actions_for_missing_source"):
        action = _require_str(refusal, key, label="regression.refusal")
        _require(action in ACTIONS, f"regression.refusal.{key} 必须是合法动作", detail=list(ACTIONS))
    leak = raw.get("leak_checks")
    _require(isinstance(leak, Mapping), "regression_config.leak_checks 必须是对象")
    kinds = leak.get("forbidden_kinds")
    _require(isinstance(kinds, list) and kinds, "regression.leak_checks.forbidden_kinds 必须是非空数组")
    _require(leak.get("policy") in {"block", "warn"}, "regression.leak_checks.policy 只支持 block/warn", detail=leak.get("policy"))
    judge = raw.get("judge")
    _require(isinstance(judge, Mapping), "regression_config.judge 必须是对象")
    _require(isinstance(judge.get("forbidden_patterns_are_regex"), bool), "regression.judge.forbidden_patterns_are_regex 必须是布尔")
    baseline = raw.get("baseline")
    _require(isinstance(baseline, Mapping), "regression_config.baseline 必须是对象")
    _require(isinstance(baseline.get("pass_rate"), (int, float)), "regression.baseline.pass_rate 必须是数字")
    _require(isinstance(baseline.get("cases"), int) and baseline["cases"] > 0, "regression.baseline.cases 必须是正整数")
    return raw


def load_config(root: str | Path) -> Config:
    """加载并校验整套配置。

    ``root`` 是交付物根目录（包含 ``config/`` 与 ``samples/``）。调用方拿到的
    :class:`Config` 里所有路径都是绝对路径，后续模块不再依赖当前工作目录。
    """
    base = Path(root).resolve()
    config_dir = base / "config"
    pipeline = load_json_file(config_dir / "pipeline_config.json", label="pipeline")

    pipeline_version = _require_str(pipeline, "pipeline_version", label="pipeline")
    clock = pipeline.get("clock")
    _require(isinstance(clock, Mapping), "pipeline.clock 必须是对象")
    clock_start = _require_str(clock, "start", label="pipeline.clock")
    parse_ts(clock_start)  # 时刻格式在加载期就校验，不留到运行期
    clock_tick = _require_int(clock, "tick_seconds", label="pipeline.clock", lo=1)

    hash_cfg = pipeline.get("hash")
    _require(isinstance(hash_cfg, Mapping), "pipeline.hash 必须是对象")
    algorithm = _require_str(hash_cfg, "algorithm", label="pipeline.hash")
    _require(algorithm == "sha256", "pipeline.hash.algorithm 目前只支持 sha256", detail=algorithm)
    normalization = _require_str(hash_cfg, "normalization", label="pipeline.hash")

    sources_cfg = pipeline.get("sources")
    _require(isinstance(sources_cfg, Mapping), "pipeline.sources 必须是对象")
    allow = sources_cfg.get("license_allowlist")
    deny = sources_cfg.get("deny_licenses")
    _require(isinstance(allow, list) and allow, "pipeline.sources.license_allowlist 必须是非空数组")
    _require(isinstance(deny, list) and deny, "pipeline.sources.deny_licenses 必须是非空数组")
    allowlist = tuple(str(x).strip().lower() for x in allow)
    denylist = tuple(str(x).strip().lower() for x in deny)
    overlap = set(allowlist) & set(denylist)
    _require(not overlap, "license 允许/禁止清单不允许重叠", detail=sorted(overlap))
    _require(len(set(allowlist)) == len(allowlist), "license_allowlist 不允许重复")
    _require(len(set(denylist)) == len(denylist), "deny_licenses 不允许重复")

    registry = _load_registry(config_dir, load_json_file(config_dir / str(sources_cfg.get("registry", "source_registry.json")), label="registry"))
    for entry in registry:
        _require(entry.license.strip().lower() in set(allowlist), f"登记表来源 {entry.source_id} 的 license 不在允许清单内", detail=entry.license)
        _require(bool(entry.authorization_ref.strip()), f"登记表来源 {entry.source_id} 缺少授权编号")

    redaction_raw = load_json_file(config_dir / "redaction_rules.json", label="redaction")
    redaction = _load_redaction(config_dir, redaction_raw)
    leak_patterns = _load_leak_patterns(redaction_raw)
    anon_cfg = pipeline.get("anonymize")
    _require(isinstance(anon_cfg, Mapping), "pipeline.anonymize 必须是对象")
    salt = _require_str(anon_cfg, "salt", label="pipeline.anonymize")
    _require(len(salt) >= 8, "pipeline.anonymize.salt 至少 8 个字符（太短会让伪名可被字典反推）", detail=len(salt))
    pseudonym_len = _require_int(anon_cfg, "pseudonym_len", label="pipeline.anonymize", lo=4)
    _require(pseudonym_len <= 32, "pipeline.anonymize.pseudonym_len 不应超过 32")
    leak_policy = _require_str(anon_cfg, "leak_policy", label="pipeline.anonymize")
    _require(leak_policy in {"block", "warn"}, "pipeline.anonymize.leak_policy 只支持 block/warn", detail=leak_policy)
    _require(
        redaction_raw.get("leak_scan", {}).get("policy") == leak_policy,
        "pipeline.anonymize.leak_policy 与 redaction_rules.leak_scan.policy 必须一致（两处口径不许分叉）",
        detail={"pipeline": leak_policy, "rules": redaction_raw.get("leak_scan", {}).get("policy")},
    )

    pairs = _validate_pairs(pipeline.get("pairs", {}))
    distill = _validate_distill(pipeline.get("distill", {}))
    policy_rules = _load_policy_rules(load_json_file(config_dir / "policy_rules.json", label="policy_rules"))
    regression = _validate_regression(load_json_file(config_dir / str(pipeline.get("regression", {}).get("config", "regression_config.json")), label="regression"))

    # 跨文件一致：蒸馏里引用的适配器必须在配置的适配器白名单里；回归里引用的策略必须存在于规则库。
    rule_ids = {r.rule_id for r in policy_rules}
    for item in distill.get("required_policy_refs", []) or []:
        _require(str(item) in rule_ids, f"distill.required_policy_refs 引用了不存在的规则: {item}")
    for item in regression.get("required_policy_refs", []) or []:
        _require(str(item) in rule_ids, f"regression.required_policy_refs 引用了不存在的规则: {item}")

    paths = {
        "root": base,
        "config": config_dir,
        "samples": base / "samples",
        "out": base / "out",
        "var": base / "var",
        "tests": base / "tests",
        "verify": base / "verify",
    }
    source_files = {
        "sources": "sources.jsonl",
        "generations": "generations.jsonl",
        "generations_unauthorized": "generations_unauthorized.jsonl",
        "traces_messages": "traces_messages.jsonl",
        "traces_tool": "traces_tool.jsonl",
        "traces_invalid": "traces_invalid.jsonl",
        "golden_cases": "golden_cases.jsonl",
    }
    return Config(
        root=base,
        pipeline=pipeline,
        pipeline_version=pipeline_version,
        clock_start=clock_start,
        clock_tick_seconds=clock_tick,
        hash_algorithm=algorithm,
        hash_normalization=normalization,
        license_allowlist=allowlist,
        deny_licenses=denylist,
        registry=registry,
        redaction_rules=redaction,
        leak_patterns=leak_patterns,
        anon_salt=salt,
        pseudonym_len=pseudonym_len,
        leak_policy=leak_policy,
        pairs=pairs,
        distill=distill,
        regression=regression,
        policy_rules=policy_rules,
        paths=paths,
        source_files=source_files,
    )
