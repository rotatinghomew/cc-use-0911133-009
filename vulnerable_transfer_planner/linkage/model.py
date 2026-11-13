"""名册同户分析的数据模型。

只承载分析所需的只读视图与人工来源记录，不包含任何匹配算法。
所有登记对象都保留原始 ``registration_id``，分析过程中不会改写。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


class LinkageError(ValueError):
    """名册资料不满足分析前提（字段缺失、引用悬空等）。"""


@dataclass(frozen=True, slots=True)
class Registration:
    """一条登记记录的不可变视图。"""

    registration_id: str
    source: str
    cohort: str
    observed_at: str
    valid_from: str
    valid_until: str
    address: str | None
    former_addresses: tuple[str, ...]
    contact_key: str | None
    members: tuple[str, ...]
    size: int
    vehicle_need: str

    @classmethod
    def from_payload(cls, row: Mapping[str, Any]) -> "Registration":
        try:
            registration_id = str(row["registration_id"])
            source = str(row["source"])
            cohort = str(row["cohort"])
            observed_at = str(row["observed_at"])
            valid_from = str(row["valid_from"])
            valid_until = str(row["valid_until"])
        except KeyError as exc:
            raise LinkageError(f"登记记录缺少必填字段: {exc}") from exc
        return cls(
            registration_id=registration_id,
            source=source,
            cohort=cohort,
            observed_at=observed_at,
            valid_from=valid_from,
            valid_until=valid_until,
            address=row.get("address"),
            former_addresses=tuple(str(item) for item in row.get("former_addresses", ())),
            contact_key=row.get("contact_key"),
            members=tuple(str(item) for item in row.get("members", ())),
            size=int(row.get("size", len(row.get("members", ()))) or 0),
            vehicle_need=str(row.get("vehicle_need", "ordinary")),
        )

    @property
    def member_set(self) -> frozenset[str]:
        return frozenset(self.members)


@dataclass(frozen=True, slots=True)
class ManualDecision:
    """人工同户/不同户结论及其独立来源键。"""

    left: str
    right: str
    same: bool
    review_id: str
    at: str

    @classmethod
    def from_payload(cls, row: Mapping[str, Any]) -> "ManualDecision":
        try:
            return cls(
                left=str(row["left"]),
                right=str(row["right"]),
                same=bool(row["same"]),
                review_id=str(row["review_id"]),
                at=str(row["at"]),
            )
        except KeyError as exc:
            raise LinkageError(f"人工结论缺少必填字段: {exc}") from exc

    def pair(self) -> tuple[str, str]:
        return tuple(sorted((self.left, self.right)))  # type: ignore[return-value]


@dataclass(slots=True)
class CandidateEdge:
    """两个登记之间的候选关系。

    ``role`` 区分同一时点跨名册的 ``cross`` 关系与只能放回时间轴解释的
    ``longitudinal`` 关系（如跨期分户）。一对一约束只作用于 cross 边。
    """

    left: str
    right: str
    left_source: str
    right_source: str
    role: str
    score: float
    plausible: bool
    overlap_in_time: bool
    blocked_by: list[str] = field(default_factory=list)
    forced_by: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    origins: list[dict[str, str]] = field(default_factory=list)
    # 人工锚点推导出的禁止/强制关系，来源 review_id 记录在 origins 中。
    manual_forbidden: bool = False
    manual_forced: bool = False

    @property
    def pair(self) -> tuple[str, str]:
        return tuple(sorted((self.left, self.right)))  # type: ignore[return-value]

    def to_dict(self) -> dict[str, Any]:
        return {
            "left": self.left,
            "right": self.right,
            "left_source": self.left_source,
            "right_source": self.right_source,
            "role": self.role,
            "score": round(self.score, 6),
            "plausible": self.plausible,
            "overlap_in_time": self.overlap_in_time,
            "manual_forced": self.manual_forced,
            "manual_forbidden": self.manual_forbidden,
            "blocked_by": list(self.blocked_by),
            "forced_by": list(self.forced_by),
            "evidence": list(self.evidence),
            "origins": list(self.origins),
        }


@dataclass(slots=True)
class LinkageGroup:
    """候选图的一个连通群组（同一批需要一起裁定的登记）。"""

    group_id: str
    cohort: str
    registration_ids: list[str]
    edges: list[CandidateEdge]
    timeline_events: list[dict[str, Any]]
    conflicts: list[dict[str, Any]]
    scenarios: list[dict[str, Any]]
    demand: dict[str, Any]
    review_queue: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "group_id": self.group_id,
            "cohort": self.cohort,
            "registration_ids": list(self.registration_ids),
            "edges": [edge.to_dict() for edge in self.edges],
            "timeline_events": list(self.timeline_events),
            "conflicts": list(self.conflicts),
            "scenarios": list(self.scenarios),
            "demand": dict(self.demand),
            "review_queue": list(self.review_queue),
        }
