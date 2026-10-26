"""存储层：只追加 JSONL + 原子落盘。

本模块回答一个问题："产物怎么写才不会一半对一半错"。它不判业务、不改记录内容。

三条纪律：

1. **只追加，不改写**：产物文件一旦写入，同一次运行内不再回改；需要"重来"就换目录，
   而不是原地删了重写（否则复跑时无法区分"上次的产物"和"这次的产物"）。
2. **一行一条、规范化编码**：每行都是 :func:`dpo_policy.model.canonical_json`，键排序、
   紧凑分隔符，所以同一批记录在任何机器上逐字节一致，可直接 sha256 比对。
3. **原子落盘**：先写同目录临时文件、``os.replace`` 覆盖，避免中途失败留下半截文件。
   临时文件名带 pid，避免并行进程互相踩。

``var/`` 放工作数据（含脱敏映射摘要等），``out/`` 放交付产物；发布时 ``var/`` 会被跳过。
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .model import ErrorCode, PipelineError, canonical_json

__all__ = [
    "JsonlStore",
    "atomic_write_text",
    "read_json",
    "read_jsonl",
    "write_json",
    "write_jsonl",
]


def atomic_write_text(path: str | Path, text: str) -> Path:
    """原子写文本：临时文件 + ``os.replace``。返回最终路径。"""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        tmp.write_text(text, encoding="utf-8", newline="\n")
        os.replace(tmp, target)
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:  # pragma: no cover - 清理失败不影响主流程
                pass
    return target


def write_json(path: str | Path, obj: Any) -> Path:
    """写一份可读 JSON（缩进 1，键排序，保留中文）。"""
    return atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=1, sort_keys=True) + "\n")


def read_json(path: str | Path, *, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError as exc:
        raise PipelineError(ErrorCode.STORE_INTEGRITY, f"JSON 不可解析: {Path(path).name}", detail=str(exc)) from exc


def read_jsonl(path: str | Path) -> tuple[dict[str, Any], ...]:
    """读 JSONL；空行跳过；坏行立刻报错（不做"跳过坏行"的宽容处理）。"""
    target = Path(path)
    if not target.exists():
        raise PipelineError(ErrorCode.STORE_INTEGRITY, f"文件不存在: {target}")
    out: list[dict[str, Any]] = []
    for lineno, line in enumerate(target.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PipelineError(
                ErrorCode.STORE_INTEGRITY,
                f"JSONL 第 {lineno} 行不是合法 JSON: {target.name}",
                detail=str(exc),
            ) from exc
        if not isinstance(obj, dict):
            raise PipelineError(ErrorCode.STORE_INTEGRITY, f"JSONL 第 {lineno} 行不是对象: {target.name}")
        out.append(obj)
    return tuple(out)


def write_jsonl(path: str | Path, records: Iterable[Mapping[str, Any]]) -> Path:
    lines = [canonical_json(dict(record)) for record in records]
    return atomic_write_text(path, "\n".join(lines) + ("\n" if lines else ""))


class JsonlStore:
    """一个只追加的 JSONL 存储。

    ``path`` 指向目标文件；同一次运行里多次 ``append`` 会累积到内存并在 ``flush`` 时
    一次性原子落盘。``append`` 只接受 Mapping，且会记录写入条数供报告引用。
    """

    __slots__ = ("path", "_records", "_flushed")

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._records: list[dict[str, Any]] = []
        self._flushed = 0

    @property
    def pending(self) -> int:
        return len(self._records)

    @property
    def flushed(self) -> int:
        return self._flushed

    def append(self, records: Iterable[Mapping[str, Any]]) -> int:
        n = 0
        for record in records:
            if not isinstance(record, Mapping):
                raise PipelineError(ErrorCode.STORE_CONFLICT, "JsonlStore 只接受 Mapping 记录")
            self._records.append(dict(record))
            n += 1
        return n

    def flush(self) -> Path:
        """把内存里的记录写成文件（覆盖式，但同一进程内只调用一次）。"""
        if self._flushed:
            raise PipelineError(
                ErrorCode.STORE_CONFLICT,
                "同一进程内不允许二次 flush（只追加纪律：要重来就换文件）",
                detail={"path": str(self.path), "flushed": self._flushed},
            )
        write_jsonl(self.path, self._records)
        self._flushed = len(self._records)
        return self.path

    def digest(self) -> str:
        """当前内存记录的内容摘要（用于产物指纹与一致性断言）。"""
        from .model import content_hash

        return content_hash(self._records)

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(self._records)


def summarize_files(paths: Sequence[str | Path], root: str | Path | None = None) -> list[dict[str, Any]]:
    """给产物做一份清单：相对路径 + 字节数（给报告与验证脚本用）。

    ``root`` 之外的路径（例如隔离复跑时的临时产物目录）退回只用文件名，
    因为"相对谁"在这种情况下没有意义——但绝不能因此抛异常把整条流水线打断。
    """
    out: list[dict[str, Any]] = []
    base = Path(root).resolve() if root is not None else None
    for p in paths:
        target = Path(p)
        if base is not None and target.exists():
            try:
                rel = target.resolve().relative_to(base).as_posix()
            except ValueError:
                rel = target.name
        else:
            rel = target.name
        out.append({"path": rel, "bytes": target.stat().st_size if target.exists() else 0})
    return sorted(out, key=lambda item: item["path"])
