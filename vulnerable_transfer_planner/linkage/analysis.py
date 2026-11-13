"""名册同户分析主流程。

输出全部是建议性工件：保留原始 registration_id、不生成合并后的家庭标识、
不导入也不触发任何转移任务状态变化。人工结论通过 :class:`LinkagePlanner`
局部应用，只重算受影响群组，其余群组工件保持不变，并完整保留来源。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from vulnerable_transfer_planner.households.runtime import fingerprint, stable_json
from vulnerable_transfer_planner.linkage.blocking import (
    blocking_reasons,
    cross_roster_pairs,
)
from vulnerable_transfer_planner.linkage.demand import (
    demand_range,
    edge_information_value,
)
from vulnerable_transfer_planner.linkage.matching import (
    enumerate_scenarios,
    hungarian_assignment,
    transitive_conflicts,
)
from vulnerable_transfer_planner.linkage.model import (
    CandidateEdge,
    LinkageError,
    LinkageGroup,
    ManualDecision,
    Registration,
)
from vulnerable_transfer_planner.linkage.scoring import score_edge
from vulnerable_transfer_planner.linkage.timeline import split_relation

REVIEW_PRIORITY_CONFLICT = 100
REVIEW_PRIORITY_BASE = 1


class LinkagePlanner:
    """保存不可变登记视图，人工决策可叠加、可溯源、可局部更新。"""

    def __init__(self, payload: Mapping[str, Any]) -> None:
        self.payload = payload
        self.as_of = str(payload.get("as_of", ""))
        self.vehicle_capacities = dict(payload.get("vehicle_capacities", {}))
        self.review_budget = int(payload.get("review_budget", 0) or 0)
        self.registrations = self._load_registrations(payload)
        self.by_id = {row.registration_id: row for row in self.registrations}
        self._validate_references(payload)
        # 决策日志：同一对的后续结论会覆盖裁定，但被覆盖条目保留 superseded。
        self.decision_log: list[dict[str, Any]] = []
        for row in payload.get("anchors", []):
            self.apply_decision(ManualDecision.from_payload(row), origin="anchor")
        for row in payload.get("conflict_updates", []):
            self.apply_decision(
                ManualDecision.from_payload(row), origin="conflict_update"
            )
        self.split_events = list(payload.get("split_events", []))

    # ------------------------------------------------------------------
    # 载入与校验
    # ------------------------------------------------------------------
    def _load_registrations(
        self, payload: Mapping[str, Any]
    ) -> list[Registration]:
        rows = payload.get("registrations")
        if not isinstance(rows, list) or not rows:
            raise LinkageError("registrations 必须是非空列表")
        registrations = [Registration.from_payload(row) for row in rows]
        identifiers = [row.registration_id for row in registrations]
        if len(set(identifiers)) != len(identifiers):
            raise LinkageError("registration_id 必须唯一")
        return registrations

    def _validate_references(self, payload: Mapping[str, Any]) -> None:
        known = set(self.by_id)
        for key in ("anchors", "conflict_updates"):
            for row in payload.get(key, []):
                if row["left"] not in known or row["right"] not in known:
                    raise LinkageError(f"{key} 引用了未知登记: {row}")
        for event in payload.get("split_events", []):
            if event["parent"] not in known:
                raise LinkageError(f"split_events 引用了未知登记: {event}")
            for child in event["children"]:
                if child not in known:
                    raise LinkageError(f"split_events 引用了未知登记: {event}")

    # ------------------------------------------------------------------
    # 人工决策（局部更新，保留来源）
    # ------------------------------------------------------------------
    def apply_decision(self, decision: ManualDecision, origin: str) -> dict[str, Any]:
        pair = decision.pair()
        for entry in self.decision_log:
            if tuple(entry["pair"]) == pair:
                entry["superseded"] = True
        record = {
            "pair": pair,
            "same": decision.same,
            "review_id": decision.review_id,
            "at": decision.at,
            "origin": origin,
            "superseded": False,
        }
        self.decision_log.append(record)
        return record

    def current_decisions(self) -> dict[tuple[str, str], dict[str, Any]]:
        current: dict[tuple[str, str], dict[str, Any]] = {}
        for entry in self.decision_log:
            if not entry["superseded"]:
                current[tuple(entry["pair"])] = entry
        return current

    # ------------------------------------------------------------------
    # 候选边与群组构建
    # ------------------------------------------------------------------
    def build_edges(self) -> list[CandidateEdge]:
        pairs = cross_roster_pairs(self.registrations)
        edges: list[CandidateEdge] = []
        for resident_id, temporary_id in sorted(pairs):
            edge = score_edge(self.by_id[resident_id], self.by_id[temporary_id])
            reasons = blocking_reasons(
                self.by_id[resident_id], self.by_id[temporary_id]
            )
            edge.evidence.insert(
                0, {"reason": "blocking_keys", "weight": 0.0, "detail": reasons}
            )
            edges.append(edge)

        # 人工锚点即使没命中任何阻断键，也必须作为候选关系出现。
        existing = {edge.pair for edge in edges}
        decisions = self.current_decisions()
        for pair, entry in sorted(decisions.items()):
            left = self.by_id[pair[0]]
            right = self.by_id[pair[1]]
            if left.source == right.source:
                # 同源人工关系只记录为纵向/同册关系，不进入二分指派。
                edges.append(self._manual_same_source_edge(left, right, entry))
            elif pair not in existing:
                edge = score_edge(left, right)
                edge.evidence.insert(
                    0,
                    {
                        "reason": "blocking_keys",
                        "weight": 0.0,
                        "detail": blocking_reasons(left, right),
                    },
                )
                edges.append(edge)

        # 统一把当前生效的人工结论标注到对应候选边上，保留来源 review_id。
        edge_lookup: dict[tuple[str, str], CandidateEdge] = {}
        for edge in edges:
            edge_lookup.setdefault(edge.pair, edge)
        for pair, entry in sorted(decisions.items()):
            edge = edge_lookup.get(pair)
            if edge is not None:
                self._mark_manual(edge, entry)
        return self._split_edges(edges)

    def _manual_same_source_edge(
        self, left: Registration, right: Registration, entry: Mapping[str, Any]
    ) -> CandidateEdge:
        edge = CandidateEdge(
            left=left.registration_id,
            right=right.registration_id,
            left_source=left.source,
            right_source=right.source,
            role="longitudinal",
            score=0.0,
            plausible=False,
            overlap_in_time=False,
            evidence=[
                {
                    "reason": "manual_anchor_same_source",
                    "weight": 0.0,
                    "detail": {"same": bool(entry["same"])},
                }
            ],
        )
        self._mark_manual(edge, entry)
        return edge

    def _mark_manual(
        self, edge: CandidateEdge, entry: Mapping[str, Any]
    ) -> None:
        origin = {
            "review_id": str(entry["review_id"]),
            "at": str(entry["at"]),
            "origin": str(entry["origin"]),
        }
        edge.origins.append(origin)
        if entry["same"]:
            edge.manual_forced = True
            edge.forced_by.append(str(entry["review_id"]))
            if edge.overlap_in_time:
                edge.plausible = True
        else:
            edge.manual_forbidden = True
            edge.blocked_by.append(str(entry["review_id"]))
            edge.plausible = False

    def _split_edges(self, edges: list[CandidateEdge]) -> list[CandidateEdge]:
        """把 split_events 转成可解释的跨期边，并校验时间轴判据。"""

        for event in self.split_events:
            parent = self.by_id[event["parent"]]
            for child_id in event["children"]:
                child = self.by_id[child_id]
                supported = split_relation(parent, child, event["effective_at"])
                edge = CandidateEdge(
                    left=parent.registration_id,
                    right=child_id,
                    left_source=parent.source,
                    right_source=child.source,
                    role="longitudinal",
                    score=0.0,
                    plausible=False,
                    overlap_in_time=False,
                    evidence=[
                        {
                            "reason": "split_event",
                            "weight": 0.0,
                            "detail": {
                                "effective_at": event["effective_at"],
                                "timeline_supported": supported,
                            },
                        }
                    ],
                    origins=[
                        {
                            "review_id": "split_event",
                            "at": event["effective_at"],
                            "origin": "split_events",
                        }
                    ],
                )
                edges.append(edge)
        edges.sort(key=lambda item: (item.left, item.right, item.role))
        return edges

    # ------------------------------------------------------------------
    # 连通群组
    # ------------------------------------------------------------------
    def build_groups(self, edges: list[CandidateEdge]) -> list[LinkageGroup]:
        adjacency: dict[str, set[str]] = {
            row.registration_id: set() for row in self.registrations
        }
        for edge in edges:
            adjacency[edge.left].add(edge.right)
            adjacency[edge.right].add(edge.left)

        visited: set[str] = set()
        groups: list[LinkageGroup] = []
        for start in sorted(adjacency):
            if start in visited:
                continue
            stack = [start]
            members: list[str] = []
            while stack:
                node = stack.pop()
                if node in visited:
                    continue
                visited.add(node)
                members.append(node)
                stack.extend(sorted(adjacency[node] - visited))
            members.sort()
            group_edges = [
                edge
                for edge in edges
                if edge.left in members and edge.right in members
            ]
            cohort = self.by_id[members[0]].cohort
            group = self._analyze_group(
                f"group-{len(groups):03d}", cohort, members, group_edges
            )
            groups.append(group)
        return groups

    def _analyze_group(
        self,
        group_id: str,
        cohort: str,
        members: list[str],
        edges: list[CandidateEdge],
    ) -> LinkageGroup:
        cross_edges = [
            edge
            for edge in edges
            if edge.role == "cross" and edge.overlap_in_time
        ]
        left_nodes = sorted(
            edge.left for edge in cross_edges if self.by_id[edge.left].source == "resident"
        )
        right_nodes = sorted(
            edge.right
            for edge in cross_edges
            if self.by_id[edge.right].source == "temporary"
        )
        left_nodes = sorted(set(left_nodes))
        right_nodes = sorted(set(right_nodes))

        conflicts = transitive_conflicts(members, edges)
        # 同一对人工结论前后矛盾（anchors 与 conflict_updates 相互覆盖）。
        member_set = set(members)
        conflicts.extend(
            conflict
            for conflict in self._decision_reversal_conflicts(edges)
            if conflict["left"] in member_set and conflict["right"] in member_set
        )

        scenarios = enumerate_scenarios(left_nodes, right_nodes, cross_edges)
        demand = demand_range(
            self.by_id, members, scenarios, self.vehicle_capacities
        )
        assignment = hungarian_assignment(left_nodes, right_nodes, cross_edges)
        review_queue = self._review_queue(
            cross_edges, members, scenarios, conflicts, assignment
        )
        timeline_events = self._timeline_events(members, edges)
        return LinkageGroup(
            group_id=group_id,
            cohort=cohort,
            registration_ids=members,
            edges=edges,
            timeline_events=timeline_events,
            conflicts=conflicts,
            scenarios=[
                {
                    "label": scenario.get("label", "maximal_matching"),
                    "matching": scenario["matching"],
                    "unmatched_right": scenario["unmatched_right"],
                }
                for scenario in scenarios
            ],
            demand=demand,
            review_queue=review_queue,
        )

    def _decision_reversal_conflicts(
        self, edges: list[CandidateEdge]
    ) -> list[dict[str, Any]]:
        conflicts: list[dict[str, Any]] = []
        edge_pairs = {edge.pair: edge for edge in edges}
        history: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for entry in self.decision_log:
            history.setdefault(tuple(entry["pair"]), []).append(entry)
        # 只有同一对登记出现过相反结论才是矛盾；单次结论无论同户/不同户
        # 都属于正常锚点，不能因为字段名叫 same 就误报。
        for pair, entries in history.items():
            if len(entries) < 2:
                continue
            if len({entry["same"] for entry in entries}) <= 1:
                continue
            edge = edge_pairs.get(pair)
            conflicts.append(
                {
                    "type": "manual_decision_reversed",
                    "left": pair[0],
                    "right": pair[1],
                    "message": "人工结论前后相反，以最新结论为准但保留全部来源",
                    "sources": [
                        {
                            "review_id": entry["review_id"],
                            "at": entry["at"],
                            "same": entry["same"],
                            "superseded": entry["superseded"],
                        }
                        for entry in entries
                    ],
                    "current_forced": bool(edge and edge.manual_forced),
                    "current_forbidden": bool(edge and edge.manual_forbidden),
                }
            )
        return conflicts

    def _timeline_events(
        self, members: list[str], edges: list[CandidateEdge]
    ) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        member_set = set(members)
        for event in self.split_events:
            if event["parent"] in member_set or any(
                child in member_set for child in event["children"]
            ):
                events.append(
                    {
                        "type": "split_event",
                        "parent": event["parent"],
                        "children": list(event["children"]),
                        "effective_at": event["effective_at"],
                    }
                )
        for edge in edges:
            if edge.role == "longitudinal":
                events.append(
                    {
                        "type": "longitudinal_edge",
                        "left": edge.left,
                        "right": edge.right,
                        "evidence": edge.evidence,
                        "origins": edge.origins,
                    }
                )
        events.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
        return events

    # ------------------------------------------------------------------
    # 复核优先级
    # ------------------------------------------------------------------
    def _review_queue(
        self,
        cross_edges: list[CandidateEdge],
        members: list[str],
        scenarios: list[dict[str, Any]],
        conflicts: list[dict[str, Any]],
        assignment: dict[str, str],
    ) -> list[dict[str, Any]]:
        conflict_pairs = {
            tuple(sorted((item["left"], item["right"]))) for item in conflicts
        }
        queued: list[dict[str, Any]] = []
        for edge in cross_edges:
            if edge.manual_forced and not edge.manual_forbidden:
                # 已有人工同户结论的边不需要再占用复核名额，除非它卷入冲突。
                if edge.pair not in conflict_pairs:
                    continue
            value = edge_information_value(
                edge,
                self.by_id,
                members,
                scenarios,
                self.vehicle_capacities,
            )
            priority = REVIEW_PRIORITY_BASE + value["information_value"]
            reasons = list(value["uncertainty_reduction"].keys())
            if edge.pair in conflict_pairs:
                priority += REVIEW_PRIORITY_CONFLICT
                reasons.insert(0, "manual_anchor_conflict")
            if edge.manual_forbidden:
                reasons.append("manual_different_household_anchor")
            if not edge.overlap_in_time:
                reasons.append("non_overlapping_validity")
            queued.append(
                {
                    "left": edge.left,
                    "right": edge.right,
                    "score": round(edge.score, 6),
                    "plausible": edge.plausible,
                    "priority": round(priority, 6),
                    "information_value": value["information_value"],
                    "uncertainty_reduction": value["uncertainty_reduction"],
                    "supporting_scenarios": value["supporting_scenarios"],
                    "contradicting_scenarios": value["contradicting_scenarios"],
                    "machine_assignment": assignment.get(edge.left) == edge.right,
                    "reasons": reasons,
                    "sources": list(edge.origins),
                }
            )
        queued.sort(
            key=lambda item: (
                -item["priority"],
                -item["information_value"],
                item["left"],
                item["right"],
            )
        )
        return self._spread_budget(queued)

    def _spread_budget(self, queue: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """复核名额在群组间轮转分配，避免一个大群组占光全部名额。"""

        if self.review_budget <= 0:
            return queue
        selected: list[dict[str, Any]] = []
        remaining = list(queue)
        while remaining and len(selected) < self.review_budget:
            pick = remaining.pop(0)
            pick["within_budget"] = True
            selected.append(pick)
            # 把同群组后续候选推后，让其他群组有机会进入预算。
            tail = remaining
            remaining = tail[1:] + tail[:1]
        for item in remaining:
            item["within_budget"] = False
        return selected + remaining

    # ------------------------------------------------------------------
    # 汇总与局部更新
    # ------------------------------------------------------------------
    def analyze(self) -> dict[str, Any]:
        edges = self.build_edges()
        groups = self.build_groups(edges)
        return self._report(edges, groups)

    def analyze_with_local_update(
        self, decision: ManualDecision
    ) -> tuple[dict[str, Any], list[str]]:
        """应用一条新的人工结论，只重算受影响群组并返回受影响群组 ID。"""

        before_groups = {
            group.group_id: set(group.registration_ids)
            for group in self.build_groups(self.build_edges())
        }
        self.apply_decision(decision, origin="field_review")
        edges = self.build_edges()
        after_groups = self.build_groups(edges)
        affected: list[str] = []
        pair = set(decision.pair())
        for group in after_groups:
            member_set = set(group.registration_ids)
            before = before_groups.get(group.group_id, set())
            if pair & member_set or before != member_set:
                affected.append(group.group_id)
        return self._report(edges, after_groups), sorted(set(affected))

    def _report(
        self, edges: list[CandidateEdge], groups: list[LinkageGroup]
    ) -> dict[str, Any]:
        cohort_summary = self._cohort_summary(groups)
        global_demand = self._global_demand(groups)
        review_queue = self._global_review_queue(groups)
        return {
            "schema": "household_linkage_analysis/v1",
            "as_of": self.as_of,
            "input_fingerprint": fingerprint(
                {
                    "registrations": self.payload.get("registrations"),
                    "anchors": self.payload.get("anchors", []),
                    "split_events": self.payload.get("split_events", []),
                }
            ),
            "principles": [
                "registration_id 原样保留，不生成合并家庭标识",
                "候选关系只做建议，不自动合并转移任务",
                "缺失字段不视为不匹配，共用联络键不是充分证据",
                "同一时点跨名册保持一对一与群组一致性",
                "开发/验证 cohort 隔离，人工锚点不跨 cohort 泄漏",
            ],
            "registration_count": len(self.registrations),
            "candidate_edge_count": len(edges),
            "group_count": len(groups),
            "decision_log": list(self.decision_log),
            "cohort_summary": cohort_summary,
            "global_demand": global_demand,
            "review_budget": self.review_budget,
            "review_queue": review_queue,
            "groups": [group.to_dict() for group in groups],
            "candidate_edges": [edge.to_dict() for edge in edges],
        }

    def _cohort_summary(self, groups: list[LinkageGroup]) -> dict[str, Any]:
        summary: dict[str, Any] = {}
        for cohort in sorted({row.cohort for row in self.registrations}):
            cohort_groups = [group for group in groups if group.cohort == cohort]
            summary[cohort] = {
                "registrations": sum(
                    1 for row in self.registrations if row.cohort == cohort
                ),
                "groups": len(cohort_groups),
                "manual_anchors": sum(
                    1
                    for entry in self.decision_log
                    if not entry["superseded"]
                    and all(
                        self.by_id[identifier].cohort == cohort
                        for identifier in entry["pair"]
                    )
                ),
                "conflicts": sum(
                    len(group.conflicts)
                    for group in cohort_groups
                ),
            }
        return summary

    def _global_demand(self, groups: list[LinkageGroup]) -> dict[str, Any]:
        keys = (
            "people",
            "households",
            "accessible_households",
            "ordinary_households",
            "accessible_vehicle_gap",
            "ordinary_vehicle_gap",
        )
        totals = {
            key: {"min": 0, "max": 0}
            for key in keys
        }
        for group in groups:
            for key in keys:
                totals[key]["min"] += group.demand[key]["min"]
                totals[key]["max"] += group.demand[key]["max"]
        for key in keys:
            totals[key]["range"] = totals[key]["max"] - totals[key]["min"]
        return totals

    def _global_review_queue(
        self, groups: list[LinkageGroup]
    ) -> list[dict[str, Any]]:
        queue: list[dict[str, Any]] = []
        for group in groups:
            for item in group.review_queue:
                enriched = dict(item)
                enriched["group_id"] = group.group_id
                enriched["cohort"] = group.cohort
                queue.append(enriched)
        queue.sort(
            key=lambda item: (
                -item["priority"],
                -item["information_value"],
                item["group_id"],
                item["left"],
                item["right"],
            )
        )
        # 全局名额按群组轮转分配：每轮取各群组当前最优的一条，避免少数
        # 大群组占光有限的复核机会；群组内部顺序沿用组内已排好的优先级。
        if self.review_budget > 0:
            by_group: dict[str, list[dict[str, Any]]] = {}
            for item in queue:
                by_group.setdefault(item["group_id"], []).append(item)
            for rows in by_group.values():
                rows.sort(
                    key=lambda item: (
                        -item["priority"],
                        -item["information_value"],
                        item["left"],
                        item["right"],
                    )
                )
            chosen: list[dict[str, Any]] = []
            group_order = sorted(by_group, key=lambda gid: -by_group[gid][0]["priority"])
            cursors = {gid: 0 for gid in group_order}
            while len(chosen) < self.review_budget:
                progressed = False
                for gid in group_order:
                    if len(chosen) >= self.review_budget:
                        break
                    index = cursors[gid]
                    if index < len(by_group[gid]):
                        chosen.append(by_group[gid][index])
                        cursors[gid] = index + 1
                        progressed = True
                if not progressed:
                    break
            chosen_keys = {
                (item["group_id"], item["left"], item["right"]) for item in chosen
            }
            for item in queue:
                key = (item["group_id"], item["left"], item["right"])
                item["within_budget"] = key in chosen_keys
        for index, item in enumerate(queue):
            item["rank"] = index + 1
            if self.review_budget <= 0:
                item["within_budget"] = False
        return queue


def write_report(report: Mapping[str, Any], output_dir: str | Path) -> dict[str, str]:
    """把分析工件写到独立目录，不触碰任何任务数据库。"""

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    files = {
        "summary": output / "summary.json",
        "candidate_edges": output / "candidate_edges.json",
        "groups": output / "groups.json",
        "review_queue": output / "review_queue.json",
        "decision_log": output / "decision_log.json",
    }
    files["summary"].write_text(
        json.dumps(
            {
                key: value
                for key, value in report.items()
                if key not in {"groups", "candidate_edges"}
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    files["candidate_edges"].write_text(
        json.dumps(report["candidate_edges"], ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    files["groups"].write_text(
        json.dumps(report["groups"], ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    files["review_queue"].write_text(
        json.dumps(report["review_queue"], ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    files["decision_log"].write_text(
        json.dumps(report["decision_log"], ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    manifest = {key: str(path) for key, path in files.items()}
    (output / "manifest.json").write_text(
        json.dumps(
            {
                "files": manifest,
                "report_fingerprint": fingerprint(report),
                "stable_json": stable_json(report)[:64],
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return manifest
