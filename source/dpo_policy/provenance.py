"""授权与版本闸门：哪一份内容可以被拿来训练。

本模块只回答一个问题："这一条来源，此刻是否允许进入流水线；如果允许，它绑定的是
哪个版本、哪种许可、哪份内容指纹、哪个授权编号"。答案只有两种——给出
:class:`~dpo_policy.model.SourceBinding`，或者抛出带稳定错误码的
:class:`~dpo_policy.model.PipelineError`。

明确不做的事：

- 不读样例文件、不写产物、不打分、不脱敏（那是 io / pairs / anonymize 层的事）；
- 不做"先跑起来再补授权"的宽容路径：授权是**白名单制**，登记表里没有的来源、
  版本对不上、指纹对不上、许可不在 ``license_allowlist`` 内、授权编号为空，
  五种情况一律拒绝；
- 不构造"看起来对"的绑定：``SourceBinding`` 只允许在本模块内由登记表条目派生。
  其它模块（pairs / distill / regression / cli）必须调用 :meth:`SourceRegistry.resolve`
  或 :meth:`SourceRegistry.binding_for`；自己 ``SourceBinding(...)`` 一个字段齐全的
  对象属于越权，等于绕过授权闸门，评审可以直接判不合格。

为什么拒绝要区分 SOURCE_UNKNOWN 与 SOURCE_VERSION_MISMATCH：前者说明引用了
根本不存在的资料（可能是伪造或笔误），后者说明引用了未登记的历史/未发布版本
（可能是缓存过期）。下游对这两种情况的处置不同，混成一个码就失去了可追溯性。
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping, Sequence

from .config import Config, RegistryEntry
from .model import ErrorCode, PipelineError, SourceBinding, SourceRecord

__all__ = ["SourceRegistry"]

_DIGIT_RUN_RE = re.compile(r"(\d+)")


def _natural_version_key(version: str) -> tuple[tuple[int, int, str], ...]:
    """把版本串切成"数字段 / 文本段"序列，让 ``v10`` 排在 ``v9`` 之后。

    key 的每一项都以整数打头，因此不会出现"字符串比较把 10 判成小于 9"的经典错误。
    数字段与文本段的相对顺序也被显式编码（0 表示数字段，1 表示文本段），
    这样 ``v1`` 与 ``v1-beta`` 之间的先后是确定且可解释的。
    """
    parts: list[tuple[int, int, str]] = []
    cursor = 0
    for match in _DIGIT_RUN_RE.finditer(version):
        if match.start() > cursor:
            parts.append((1, 0, version[cursor : match.start()]))
        parts.append((0, int(match.group(1)), ""))
        cursor = match.end()
    if cursor < len(version):
        parts.append((1, 0, version[cursor:]))
    return tuple(parts)


class SourceRegistry:
    """授权登记表的只读索引。

    索引有两层：``(source_id, version) -> 条目`` 用于精确解析；
    ``source_id -> 该来源的全部条目`` 用于区分"来源不存在"与"来源存在但版本不对"，
    以及给 ``binding_for`` 挑最大版本。两层都在构造时排序完成，
    因此任何一次查询都不依赖 dict 的插入顺序，复跑结果逐字节一致。
    """

    __slots__ = ("_cfg", "_entries", "_index", "_by_source")

    def __init__(self, cfg: Config, entries: Sequence[RegistryEntry]) -> None:
        self._cfg = cfg
        ordered = tuple(sorted(entries, key=lambda entry: (entry.source_id, entry.version)))
        self._entries = ordered
        self._index = {entry.key(): entry for entry in ordered}
        grouped: dict[str, list[RegistryEntry]] = {}
        for entry in ordered:
            grouped.setdefault(entry.source_id, []).append(entry)
        self._by_source = {source_id: tuple(items) for source_id, items in grouped.items()}

    # ------------------------------------------------------------ 构造

    @classmethod
    def from_config(cls, cfg: Config) -> "SourceRegistry":
        """用已在加载期校验过的登记表建索引。

        不重新校验登记表内容：配置层已经保证 ``(source_id, version)`` 唯一、
        指纹是 64 位小写 hex、许可在 allowlist 内、授权编号非空。这里重复校验
        只会让两套口径有机会分叉。
        """
        return cls(cfg, tuple(cfg.registry))

    # ------------------------------------------------------------ 查询

    def resolve(self, source_ref: Mapping[str, str], *, record_id: str = "") -> SourceBinding:
        """按引用里的 (source_id, version) 精确解析出一条授权绑定。

        判定顺序即"从便宜到昂贵"：先看引用本身是否成合法形状，再看登记表是否
        认这个 (来源, 版本)，再看许可与授权编号，最后才比对调用方自称的内容指纹。
        任何一步不过都立刻抛错，不返回"部分可用"的半成品。
        """
        source_id, version, claimed_hash = self._read_ref(source_ref, record_id=record_id)
        entry = self._index.get((source_id, version))
        if entry is None:
            known = self._by_source.get(source_id)
            if known:
                raise PipelineError(
                    ErrorCode.SOURCE_VERSION_MISMATCH,
                    f"来源 {source_id} 已登记，但没有版本 {version} 的授权条目",
                    record_id=record_id,
                    detail={
                        "source_id": source_id,
                        "version": version,
                        "registered_versions": [item.version for item in known],
                    },
                )
            raise PipelineError(
                ErrorCode.SOURCE_UNKNOWN,
                f"来源 {source_id} 不在授权登记表内",
                record_id=record_id,
                detail={"source_id": source_id, "version": version},
            )
        self._require_authorized(entry, record_id=record_id)
        if claimed_hash and claimed_hash != entry.content_sha256.lower():
            raise PipelineError(
                ErrorCode.SOURCE_HASH_MISMATCH,
                f"来源 {source_id}@{version} 的自称内容指纹与登记表不一致",
                record_id=record_id,
                detail={
                    "source_id": source_id,
                    "version": version,
                    "claimed": claimed_hash,
                    "registered": entry.content_sha256,
                },
            )
        return self._binding(entry)

    def binding_for(self, source_id: str, version: str | None = None) -> SourceBinding:
        """按 source_id（可指定版本）取绑定；不指定版本时取最大版本。

        "最大版本"按版本串里的数字自然排序，而不是字符串排序。版本不存在时统一
        报 ``SOURCE_UNKNOWN``：对本方法来说"这个来源没有这个版本"和"这个来源不存在"
        对调用方是同一件事——你要的绑定拿不到，必须显式指定一个已登记版本。
        """
        name = str(source_id or "").strip()
        known = self._by_source.get(name)
        if not known:
            raise PipelineError(
                ErrorCode.SOURCE_UNKNOWN,
                f"来源 {name} 不在授权登记表内",
                detail={"source_id": name, "version": version},
            )
        wanted = str(version).strip() if version is not None else ""
        if wanted:
            entry = self._index.get((name, wanted))
            if entry is None:
                raise PipelineError(
                    ErrorCode.SOURCE_UNKNOWN,
                    f"来源 {name} 没有版本 {wanted} 的授权条目",
                    detail={"source_id": name, "version": wanted},
                )
        else:
            # 先按自然序挑最大版本，再用版本串本身兜底：即使两个版本的自然序相同
            # （例如 v1 与 v01），取到的条目也永远是同一个，不受登记表顺序影响。
            entry = max(known, key=lambda item: (_natural_version_key(item.version), item.version))
        self._require_authorized(entry)
        return self._binding(entry)

    def entries(self) -> tuple[RegistryEntry, ...]:
        """登记表全集，按 (source_id, version) 排序。

        排序后返回，是为了让"登记了哪些版本"这件事在报告里稳定可比；
        返回 tuple 而不是 list，避免调用方就地改写这份索引。
        """
        return self._entries

    def stats(self) -> dict[str, Any]:
        """登记表概况：条目数、来源数、许可分布、生效区间。

        只做聚合，不做判定：这里的数字进报告，用于证明"授权面"有多大，
        而不是用来解释某条记录为什么被拒（那要看错误码）。
        """
        licenses: dict[str, int] = {}
        for entry in self._entries:
            licenses[entry.license] = licenses.get(entry.license, 0) + 1
        dates = [entry.effective_at for entry in self._entries]
        return {
            "registered": len(self._entries),
            "sources": len(self._by_source),
            "licenses": {name: licenses[name] for name in sorted(licenses)},
            "effective_from": min(dates) if dates else "",
            "effective_to": max(dates) if dates else "",
        }

    # ------------------------------------------------------------ 语料闸门

    def resolve_corpus(
        self,
        records: Iterable[SourceRecord],
    ) -> tuple[tuple[SourceRecord, ...], tuple[dict[str, Any], ...]]:
        """批量过闸：返回 (通过的记录, 被拒记录的说明)。

        每条记录都复算内容指纹再和登记表比对——登记表里存的是"当时那份正文"的
        指纹，因此正文被改过、标题被改过、版本被改过任一项，这里都会漂移。
        被拒项只带身份与原因，不带正文片段：拒绝清单本身不能变成新的泄漏面。
        """
        accepted: list[SourceRecord] = []
        rejected: list[dict[str, Any]] = []
        for raw in records:
            record = self._as_record(raw)
            problem = self._judge_record(record)
            if problem is None:
                accepted.append(record)
            else:
                rejected.append(problem)
        # 两侧都排序：入参顺序（可能是 set 或字典视图）不允许影响复跑结果。
        accepted.sort(key=lambda item: (item.source_id, item.version, item.content_sha256()))
        rejected.sort(key=lambda item: (str(item["record_id"]), str(item["code"])))
        return tuple(accepted), tuple(rejected)

    # ------------------------------------------------------------ 内部

    @staticmethod
    def _as_record(raw: Any) -> SourceRecord:
        if isinstance(raw, SourceRecord):
            return raw
        if isinstance(raw, Mapping):
            # CLI 从 JSONL 读出来的就是 dict；这里统一走模型的 from_dict，
            # 保证"样例文件"和"内存记录"两条路径的指纹口径完全一致。
            return SourceRecord.from_dict(raw)
        raise PipelineError(
            ErrorCode.SOURCE_SCHEMA_INVALID,
            "resolve_corpus 只接受 SourceRecord 或其映射",
            detail={"type": type(raw).__name__},
        )

    def _judge_record(self, record: SourceRecord) -> dict[str, Any] | None:
        record_id = f"{record.source_id}@{record.version}"

        def reject(code: str, message: str) -> dict[str, Any]:
            return {
                "record_id": record_id,
                "code": code,
                "message": message,
                "source_id": record.source_id,
                "version": record.version,
            }

        entry = self._index.get((record.source_id, record.version))
        if entry is None:
            return reject(ErrorCode.SOURCE_UNKNOWN, "登记表里没有该来源版本，整条记录不进入语料")
        if entry.content_sha256.lower() != record.content_sha256():
            return reject(ErrorCode.SOURCE_HASH_MISMATCH, "复算的内容指纹与登记表不一致（正文或标题被改动过）")
        if entry.license.strip().lower() != str(record.license or "").strip().lower():
            return reject(ErrorCode.SOURCE_UNAUTHORIZED, "记录自带许可与登记表许可不一致")
        if not self._cfg.license_allowed(entry.license):
            return reject(ErrorCode.SOURCE_UNAUTHORIZED, "登记表许可不在允许清单内")
        # 授权编号缺失放在最后判定：前面四条是登记表口径，这一条是"凭证完整性"。
        # 顺序固定，保证同一份坏数据永远得到同一个码。
        if not entry.authorization_ref.strip():
            return reject(ErrorCode.SOURCE_UNAUTHORIZED, "登记表条目缺少授权编号")
        return None

    @staticmethod
    def _read_ref(source_ref: Mapping[str, str], *, record_id: str) -> tuple[str, str, str]:
        if not isinstance(source_ref, Mapping):
            raise PipelineError(
                ErrorCode.SOURCE_SCHEMA_INVALID,
                "source_ref 必须是对象，且至少带 source_id 与 version",
                record_id=record_id,
                detail={"type": type(source_ref).__name__},
            )
        source_id = source_ref.get("source_id")
        version = source_ref.get("version")
        if not isinstance(source_id, str) or not source_id.strip():
            raise PipelineError(
                ErrorCode.SOURCE_SCHEMA_INVALID,
                "source_ref.source_id 必须是非空字符串",
                record_id=record_id,
                detail={"value": repr(source_id)[:40]},
            )
        if not isinstance(version, str) or not version.strip():
            raise PipelineError(
                ErrorCode.SOURCE_SCHEMA_INVALID,
                "source_ref.version 必须是非空字符串（版本锁定不允许省略）",
                record_id=record_id,
                detail={"value": repr(version)[:40]},
            )
        claimed = source_ref.get("content_sha256")
        claimed_hash = claimed.strip().lower() if isinstance(claimed, str) else ""
        return source_id.strip(), version.strip(), claimed_hash

    def _require_authorized(self, entry: RegistryEntry, *, record_id: str = "") -> None:
        if not self._cfg.license_allowed(entry.license):
            raise PipelineError(
                ErrorCode.SOURCE_UNAUTHORIZED,
                f"来源 {entry.source_id}@{entry.version} 的许可不在允许清单内",
                record_id=record_id,
                detail={"source_id": entry.source_id, "version": entry.version, "license": entry.license},
            )
        if not entry.authorization_ref.strip():
            raise PipelineError(
                ErrorCode.SOURCE_UNAUTHORIZED,
                f"来源 {entry.source_id}@{entry.version} 缺少授权编号",
                record_id=record_id,
                detail={"source_id": entry.source_id, "version": entry.version},
            )

    @staticmethod
    def _binding(entry: RegistryEntry) -> SourceBinding:
        return SourceBinding(
            source_id=entry.source_id,
            version=entry.version,
            license=entry.license,
            content_sha256=entry.content_sha256,
            authorization_ref=entry.authorization_ref,
            effective_at=entry.effective_at,
        )
