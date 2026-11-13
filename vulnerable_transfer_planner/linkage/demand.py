"""需求范围与复核价值（value of information）。

现场组关心的不是哪一对最接近 0.5，而是复核哪一对最能压缩
"待转移人数"和"车型缺口"的不确定性。因此每个群组在不同合理链接情景下
分别计算需求快照，再用情景极差衡量复核价值。
"""

from __future__ import annotations

from typing import Any

from vulnerable_transfer_planner.linkage.model import CandidateEdge, Registration

ACCESSIBLE = "accessible"


def demand_snapshot(
    registrations: dict[str, Registration],
    household_ids: list[str],
) -> dict[str, Any]:
    """按一组"去重后的家庭标识"计算需求快照。

    同户链接成立时，两侧登记描述同一家庭，人数取两侧较大值而不是相加，
    避免重复计数；车型需求只要任一侧要求无障碍车，就按无障碍车保障。
    """

    people = 0
    accessible_households = 0
    ordinary_households = 0
    for household_id in household_ids:
        row = registrations[household_id]
        people += max(row.size, len(row.members))
        if row.vehicle_need == ACCESSIBLE:
            accessible_households += 1
        else:
            ordinary_households += 1
    return {
        "households": len(household_ids),
        "people": people,
        "accessible_households": accessible_households,
        "ordinary_households": ordinary_households,
    }


def scenario_households(
    group_ids: list[str],
    matching: dict[str, str | None],
) -> list[str]:
    """把一个链接情景展开成去重家庭标识列表。"""

    matched_right = {right for right in matching.values() if right}
    households = list(group_ids)
    # 被匹配上的 temporary 与其 resident 是同一户，从独立计数中去掉。
    households = [node for node in households if node not in matched_right]
    return households


def demand_range(
    registrations: dict[str, Registration],
    group_ids: list[str],
    scenarios: list[dict[str, Any]],
    vehicle_capacities: dict[str, int],
) -> dict[str, Any]:
    """汇总所有情景下的需求最小值、最大值与基线。"""

    snapshots: list[dict[str, Any]] = []
    for scenario in scenarios:
        households = scenario_households(group_ids, scenario["matching"])
        snapshot = demand_snapshot(registrations, households)
        accessible_capacity = max(1, int(vehicle_capacities.get(ACCESSIBLE, 1)))
        ordinary_capacity = max(1, int(vehicle_capacities.get("ordinary", 1)))
        snapshot["accessible_vehicle_gap"] = max(
            0,
            -(-snapshot["accessible_households"] // accessible_capacity),
        )
        snapshot["ordinary_vehicle_gap"] = max(
            0,
            -(-snapshot["ordinary_households"] // ordinary_capacity),
        )
        snapshots.append(snapshot)

    def span(key: str) -> dict[str, int]:
        values = [snapshot[key] for snapshot in snapshots]
        return {"min": min(values), "max": max(values), "range": max(values) - min(values)}

    return {
        "scenario_count": len(snapshots),
        "people": span("people"),
        "households": span("households"),
        "accessible_households": span("accessible_households"),
        "ordinary_households": span("ordinary_households"),
        "accessible_vehicle_gap": span("accessible_vehicle_gap"),
        "ordinary_vehicle_gap": span("ordinary_vehicle_gap"),
        "snapshots": snapshots,
    }


def edge_information_value(
    edge: CandidateEdge,
    registrations: dict[str, Registration],
    group_ids: list[str],
    scenarios: list[dict[str, Any]],
    vehicle_capacities: dict[str, int],
) -> dict[str, Any]:
    """估算复核某条候选边能压缩多少不确定性。

    做法：把情景按"该边成立 / 该边不成立"分成两组，分别取需求极差，
    与不复核时的整体极差比较。削减的人数极差与车型缺口极差加权后，
    得到该边的复核价值。
    """

    pair = set(edge.pair)
    supporting: list[dict[str, Any]] = []
    contradicting: list[dict[str, Any]] = []
    for scenario in scenarios:
        matched = {
            tuple(sorted((left, right)))
            for left, right in scenario["matching"].items()
            if right
        }
        target = tuple(sorted(pair))
        (supporting if target in matched else contradicting).append(scenario)

    accessible_capacity = max(1, int(vehicle_capacities.get(ACCESSIBLE, 1)))
    ordinary_capacity = max(1, int(vehicle_capacities.get("ordinary", 1)))

    def total_span(rows: list[dict[str, Any]]) -> dict[str, int]:
        if not rows:
            return {
                "people": 0,
                "accessible_households": 0,
                "ordinary_households": 0,
                "accessible_vehicle_gap": 0,
                "ordinary_vehicle_gap": 0,
            }
        snapshots = [
            demand_snapshot(
                registrations,
                scenario_households(group_ids, row["matching"]),
            )
            for row in rows
        ]
        people_values = [item["people"] for item in snapshots]
        accessible_values = [
            -(-item["accessible_households"] // accessible_capacity)
            for item in snapshots
        ]
        ordinary_values = [
            -(-item["ordinary_households"] // ordinary_capacity)
            for item in snapshots
        ]
        return {
            "people": max(people_values) - min(people_values),
            "accessible_households": max(
                item["accessible_households"] for item in snapshots
            )
            - min(item["accessible_households"] for item in snapshots),
            "ordinary_households": max(
                item["ordinary_households"] for item in snapshots
            )
            - min(item["ordinary_households"] for item in snapshots),
            "accessible_vehicle_gap": max(accessible_values) - min(accessible_values),
            "ordinary_vehicle_gap": max(ordinary_values) - min(ordinary_values),
        }

    before = total_span(scenarios)
    after_support = total_span(supporting)
    after_contradict = total_span(contradicting)
    # 复核后无论结论是同户还是不同户，都只会落到其中一组，取两组极差的
    # 最大值作为保守的残余不确定性。
    residual = {
        key: max(after_support[key], after_contradict[key]) for key in before
    }
    reduction = {key: before[key] - residual[key] for key in before}
    # 车型缺口与其原始户数不确定性都计入价值：无障碍车保障难度高，权重更大。
    value = (
        reduction["people"]
        + 2 * reduction["accessible_households"]
        + reduction["ordinary_households"]
        + 2
        * (
            reduction["accessible_vehicle_gap"]
            + reduction["ordinary_vehicle_gap"]
        )
    )
    return {
        "edge": [edge.left, edge.right],
        "information_value": round(float(value), 6),
        "uncertainty_reduction": reduction,
        "supporting_scenarios": len(supporting),
        "contradicting_scenarios": len(contradicting),
    }
