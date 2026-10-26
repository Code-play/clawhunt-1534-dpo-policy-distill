"""脱敏闸门：先把敏感片段换成稳定伪名，再检查有没有残留。

本模块只回答一个问题："这段文本能不能安全地进入训练产物；如果不能，命中了哪类
残留"。它不判授权（那是 provenance 的事）、不建偏好对（那是 pairs 的事）、
不写文件、不读时钟。

明确不做的事：

- **不做"命中片段打码后放行"。** 脱敏是"先整体替换成伪名，再用残留扫描复检"；
  复检一旦命中，调用方必须把整条记录退回去（``assert_clean`` 抛 ``ANON_LEAK``）。
  也就是说，本模块提供的不是"擦掉几个字"的能力，而是"这条记录要么干净、
  要么整条不要"的判定；
- **不保存原文。** 映射表只记 ``(kind, 伪名)`` 两项，原文既不落内存映射也不进
  任何返回值；连原文的独立哈希都不单独存放，避免把映射表变成反查表；
- **不做随机加盐、不读真实时钟。** 同一份 salt + 同一 ``(kind, 原文)`` 永远得到
  同一伪名，所以跨批次仍可去重、偏好对仍可训练，但无法从产物反推原值。

伪名口径：``<kind:digest>``，其中 ``digest = HMAC-SHA256(salt, "kind|原文")`` 的
十六进制前 ``pseudonym_len`` 位。用 HMAC 而不是裸哈希，是为了让"知道算法但不知道
salt"的人无法用字典逐个试出原值。
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .config import Config, RedactionRule
from .model import ErrorCode, PipelineError, canonical_json, sha256_text

__all__ = ["Anonymizer", "RedactionHit"]

_DIGEST_SLOT = "{digest}"


@dataclass(frozen=True)
class RedactionHit:
    """一次命中的位置描述。

    ``digest`` 只在脱敏阶段填充；残留扫描阶段留空串——扫描只回答"哪里还脏"，
    不负责再次派生伪名，否则就变成了"打码后放行"。
    """

    kind: str
    start: int
    end: int
    digest: str = ""


class Anonymizer:
    """按配置里的规则做稳定伪名替换，并用残留模式自检。

    实例内部只保留编译后的正则、salt、长度参数、以及 ``(kind, 伪名)`` 映射集合。
    映射集合用来给"到底替换了多少种敏感值"留一个可审计的数字与摘要，
    它本身不包含原文，因此即使被打印也没有泄漏风险。
    """

    __slots__ = ("_salt", "_pseudonym_len", "_rules", "_leak_patterns", "_leak_policy", "_mapping")

    def __init__(
        self,
        *,
        salt: str,
        pseudonym_len: int,
        rules: Sequence[tuple[RedactionRule, re.Pattern[str]]],
        leak_patterns: Sequence[tuple[str, re.Pattern[str]]],
        leak_policy: str,
    ) -> None:
        if not salt:
            # salt 为空会让伪名退化成"裸哈希"，字典反推成本骤降，属于配置错误。
            raise PipelineError(ErrorCode.CONFIG_INVALID, "脱敏 salt 不能为空")
        if pseudonym_len <= 0:
            raise PipelineError(ErrorCode.CONFIG_INVALID, "pseudonym_len 必须为正整数", detail=pseudonym_len)
        self._salt = salt
        self._pseudonym_len = int(pseudonym_len)
        self._rules = tuple(rules)
        self._leak_patterns = tuple(leak_patterns)
        self._leak_policy = str(leak_policy)
        self._mapping: set[tuple[str, str]] = set()

    # ------------------------------------------------------------ 构造

    @classmethod
    def from_config(cls, cfg: Config) -> "Anonymizer":
        """把配置里的规则编译一次。

        正则只在建实例时编译：``redact_text`` 可能被每条候选调用若干次，
        每次重编译既慢又容易在建实例之外的地方悄悄改变口径。
        """
        compiled = tuple((rule, rule.compile()) for rule in cfg.redaction_rules)
        leaks = tuple((kind, re.compile(pattern)) for kind, pattern in cfg.leak_patterns)
        return cls(
            salt=cfg.anon_salt,
            pseudonym_len=cfg.pseudonym_len,
            rules=compiled,
            leak_patterns=leaks,
            leak_policy=cfg.leak_policy,
        )

    # ------------------------------------------------------------ 伪名

    def pseudonym(self, kind: str, value: str) -> str:
        """给 ``(kind, 原文)`` 派生稳定伪名，并登记进映射表。

        同一对输入永远得到同一输出；不同输入理论上可能在截断后碰撞，
        这是"短伪名换可读性"的代价，映射表里也只记 ``(kind, 伪名)``，
        因此碰撞不会导致原文泄漏，只会让两个值共用一个占位符。
        """
        label = str(kind)
        digest = self._digest(label, str(value))
        placeholder = f"<{label}:{digest}>"
        self._mapping.add((label, placeholder))
        return placeholder

    # ------------------------------------------------------------ 文本脱敏

    def redact_text(self, text: str) -> str:
        """把文本里所有规则命中替换成伪名占位符。

        重叠处理顺序见 :meth:`_collect`：长匹配优先、等长看规则声明顺序，
        然后从右向左替换，保证替换后的偏移不会互相串位。无命中时原样返回
        同一个字符串对象，调用方可以据此判断"这条文本没有动过"。
        """
        if not isinstance(text, str):
            raise PipelineError(ErrorCode.ANON_SCHEMA_INVALID, "redact_text 只接受字符串", detail=type(text).__name__)
        pieces = self._collect(text)
        if not pieces:
            return text
        out: list[str] = []
        cursor = len(text)
        for start, end, rule, digest in reversed(pieces):
            out.append(text[end:cursor])
            out.append(self._render(rule, digest))
            cursor = start
        out.append(text[:cursor])
        return "".join(reversed(out))

    def _render(self, rule: RedactionRule, digest: str) -> str:
        """按规则声明里的模板渲染占位符，并把伪名登记进映射表。

        映射表里登记的是标准形式 ``<kind:digest>``，与模板长什么样无关：
        模板是可配置的展示口径（比如 ``<phone:{digest}>``），映射语义不能跟着
        配置漂移，否则换了模板就等于换了映射表，历史摘要全部对不上。
        """
        self._mapping.add((rule.kind, f"<{rule.kind}:{digest}>"))
        return rule.replacement.replace(_DIGEST_SLOT, digest)

    def _digest(self, kind: str, value: str) -> str:
        message = f"{kind}|{value}".encode("utf-8")
        return hmac.new(self._salt.encode("utf-8"), message, hashlib.sha256).hexdigest()[: self._pseudonym_len]

    def _collect(self, text: str) -> list[tuple[int, int, RedactionRule, str]]:
        """收集所有命中并按"长优先、同级按规则声明顺序"做不重叠筛选。

        为什么不能每个规则各替换一遍：邮箱里可能套着 URL 凭据，18 位卡号里可能
        也能被身份证规则匹配一段。多轮替换会让偏移互相错位，也会让同一条原文
        先被规则 A 打码、再被规则 B 从伪名里再打一次码。
        """
        candidates: list[tuple[int, int, int, int, RedactionRule]] = []
        for order, (rule, pattern) in enumerate(self._rules):
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                if end > start:
                    candidates.append((-(end - start), order, start, end, rule))
        if not candidates:
            return []
        # 排序键：先按长度倒序，再按规则声明顺序，最后按位置，保证同输入同结果。
        candidates.sort(key=lambda item: (item[0], item[1], item[2], item[3]))
        taken: list[tuple[int, int, RedactionRule, str]] = []
        occupied: list[tuple[int, int]] = []
        for _, _, start, end, rule in candidates:
            if any(start < other_end and other_start < end for other_start, other_end in occupied):
                continue
            occupied.append((start, end))
            taken.append((start, end, rule, self._digest(rule.kind, text[start:end])))
        taken.sort(key=lambda item: (item[0], item[1]))
        return taken

    # ------------------------------------------------------------ 结构化脱敏

    def redact_mapping(self, obj: Any) -> Any:
        """递归脱敏 dict / list / tuple，字符串叶子走 :meth:`redact_text`。

        dict 的键也过一遍：样例里出现过 ``{"张三": "..."}`` 这种"人名为键"的写法，
        只洗值不洗键等于漏一半。入参不会被修改，返回同构的新对象。
        """
        if isinstance(obj, str):
            return self.redact_text(obj)
        if isinstance(obj, Mapping):
            return {
                (self.redact_text(key) if isinstance(key, str) else key): self.redact_mapping(value)
                for key, value in obj.items()
            }
        if isinstance(obj, list):
            return [self.redact_mapping(item) for item in obj]
        if isinstance(obj, tuple):
            return tuple(self.redact_mapping(item) for item in obj)
        return obj

    # ------------------------------------------------------------ 残留自检

    def scan(self, text: str) -> tuple[RedactionHit, ...]:
        """按 ``leak_patterns`` 找残留，返回按位置排序的命中。

        这里只找位置、不派生伪名：扫描的结论只能是"干净 / 不干净"，
        不能顺手把命中的片段变成占位符继续用。
        """
        if not isinstance(text, str):
            raise PipelineError(ErrorCode.ANON_SCHEMA_INVALID, "scan 只接受字符串", detail=type(text).__name__)
        hits: list[RedactionHit] = []
        for kind, pattern in self._leak_patterns:
            for match in pattern.finditer(text):
                if match.end() > match.start():
                    hits.append(RedactionHit(kind=kind, start=match.start(), end=match.end(), digest=""))
        hits.sort(key=lambda hit: (hit.start, hit.end, hit.kind))
        return tuple(hits)

    def assert_clean(self, text: str, *, record_id: str = "") -> tuple[RedactionHit, ...]:
        """扫描残留；block 模式下命中即抛 ``ANON_LEAK``，warn 模式只回传命中。

        异常里只放命中类型列表，绝不放命中片段——否则"报错日志"就成了新的泄漏面。
        返回命中的元组，方便调用方在 warn 模式下把命中数记进统计。
        """
        hits = self.scan(text)
        if hits and self._leak_policy == "block":
            kinds = sorted({hit.kind for hit in hits})
            raise PipelineError(
                ErrorCode.ANON_LEAK,
                f"脱敏后仍检测到 {len(hits)} 处残留，整条记录拒绝（类型: {', '.join(kinds)}）",
                record_id=record_id,
                detail={"kinds": kinds},
            )
        return hits

    # ------------------------------------------------------------ 映射表

    def entries(self) -> tuple[tuple[str, str], ...]:
        """``(kind, 伪名)`` 的排序元组；不含原文，也不含原文的独立指纹。"""
        return tuple(sorted(self._mapping))

    def mapping_size(self) -> int:
        return len(self._mapping)

    def mapping_digest(self) -> str:
        """映射表摘要：排序后 canonical JSON 的 sha256。

        用摘要而不是清单进报告，是为了"能证明两次运行用了同一套映射"同时
        "不把映射表交出去"。完全由内容决定，不掺任何时刻信息。
        """
        return sha256_text(canonical_json([list(item) for item in self.entries()]))
