"""候选评分：可解释的加权证据模型。

分数只用于排序和"是否合理"的门槛，绝不自动裁定同户。规则刻意保持
简单、可向现场解释：

* 缺失字段不扣分（没有地址/电话不等于不匹配）；
* 共用联络键是弱证据，单独使用时分数达不到合理门槛；
* 成员集合全等、现址一致、搬迁地址链是强证据；
* 有效区间不重叠的关系只能按跨期关系解释，不能参与同一时点匹配；
* 人工锚点通过 ``manual_forced`` / ``manual_forbidden`` 单独表达，
  与机器分数分开保存来源。
"""

from __future__ import annotations

from typing import Any

from vulnerable_transfer_planner.linkage.model import CandidateEdge, Registration
from vulnerable_transfer_planner.linkage.timeline import intervals_overlap

# 达到该门槛的 cross 边才被视为"合理链接"，进入需求情景枚举。
# 0.2 的含义：共用联络键（0.15）再叠加车型一致（0.05）等旁证时，作为
# 弱合理替代进入情景枚举，用于量化"共用联络人的两户老人"带来的不确定性；
# 但仅靠共用联络键（0.15）永远达不到门槛，符合"共用电话不是充分证据"。
PLAUSIBLE_THRESHOLD = 0.2

# 信号权重。共享联络键的权重刻意压低：共用联络人在村级资料里很常见。
WEIGHTS = {
    "identical_member_set": 0.45,
    "member_overlap_partial": 0.2,
    "same_current_address": 0.3,
    "former_address_chain": 0.25,
    "shared_contact_key": 0.15,
    "same_vehicle_need": 0.05,
    "same_size": 0.05,
}


def _member_overlap(left: Registration, right: Registration) -> float:
    union = left.member_set | right.member_set
    if not union:
        return 0.0
    return len(left.member_set & right.member_set) / len(union)


def score_edge(left: Registration, right: Registration) -> CandidateEdge:
    evidence: list[dict[str, Any]] = []
    score = 0.0

    def add(reason: str, weight: float, detail: dict[str, Any]) -> None:
        nonlocal score
        score += weight
        evidence.append({"reason": reason, "weight": weight, "detail": detail})

    overlap = intervals_overlap(left, right)
    if left.member_set and left.member_set == right.member_set:
        add(
            "identical_member_set",
            WEIGHTS["identical_member_set"],
            {"members": sorted(left.member_set)},
        )
    else:
        jaccard = _member_overlap(left, right)
        if jaccard > 0:
            add(
                "member_overlap_partial",
                WEIGHTS["member_overlap_partial"] * jaccard,
                {"jaccard": round(jaccard, 6)},
            )

    if left.address and left.address == right.address:
        add(
            "same_current_address",
            WEIGHTS["same_current_address"],
            {"address": left.address},
        )
    former_chain = (left.address and left.address in right.former_addresses) or (
        right.address and right.address in left.former_addresses
    )
    if former_chain:
        add(
            "former_address_chain",
            WEIGHTS["former_address_chain"],
            {
                "left_former": list(left.former_addresses),
                "right_former": list(right.former_addresses),
            },
        )

    if left.contact_key and left.contact_key == right.contact_key:
        # 弱证据：共用联络键可能对应两户老人，绝不能单独推出同户。
        add(
            "shared_contact_key",
            WEIGHTS["shared_contact_key"],
            {"contact_key": left.contact_key},
        )

    if left.vehicle_need == right.vehicle_need:
        add(
            "same_vehicle_need",
            WEIGHTS["same_vehicle_need"],
            {"vehicle_need": left.vehicle_need},
        )
    if left.size and left.size == right.size:
        add("same_size", WEIGHTS["same_size"], {"size": left.size})

    score = min(1.0, round(score, 6))
    role = "cross" if overlap else "longitudinal"
    return CandidateEdge(
        left=left.registration_id,
        right=right.registration_id,
        left_source=left.source,
        right_source=right.source,
        role=role,
        score=score,
        plausible=overlap and score >= PLAUSIBLE_THRESHOLD,
        overlap_in_time=overlap,
        evidence=evidence,
    )
