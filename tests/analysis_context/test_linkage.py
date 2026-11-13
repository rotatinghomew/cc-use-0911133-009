from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from vulnerable_transfer_planner.linkage.analysis import LinkagePlanner
from vulnerable_transfer_planner.linkage.blocking import (
    blocking_reasons,
    cross_roster_pairs,
)
from vulnerable_transfer_planner.linkage.matching import (
    enumerate_scenarios,
    hungarian_assignment,
    transitive_conflicts,
)
from vulnerable_transfer_planner.linkage.model import (
    CandidateEdge,
    LinkageError,
    ManualDecision,
    Registration,
)
from vulnerable_transfer_planner.linkage.scoring import (
    PLAUSIBLE_THRESHOLD,
    score_edge,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / "fixtures" / "household_linkage.json"


def load_payload() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def reg(
    registration_id: str,
    source: str = "resident",
    cohort: str = "development",
    address: str | None = "lane-x",
    contact_key: str | None = None,
    members: tuple[str, ...] = ("adult-x",),
    valid_from: str = "2026-07-01",
    valid_until: str = "2026-09-01",
    vehicle_need: str = "ordinary",
) -> Registration:
    return Registration(
        registration_id=registration_id,
        source=source,
        cohort=cohort,
        observed_at="2026-08-01",
        valid_from=valid_from,
        valid_until=valid_until,
        address=address,
        former_addresses=(),
        contact_key=contact_key,
        members=members,
        size=len(members),
        vehicle_need=vehicle_need,
    )


class BlockingAndScoringTests(unittest.TestCase):
    def test_shared_contact_alone_is_not_sufficient(self):
        # 两户老人共用联络人，但成员、地址、规模、车型全部不同——除电话外
        # 没有任何旁证，这种关系不能达到合理链接门槛。
        left = reg(
            "r-a",
            address="lane-a",
            contact_key="contact-shared",
            members=("elder-1",),
            vehicle_need="ordinary",
        )
        right = reg(
            "t-a",
            source="temporary",
            address="lane-b",
            contact_key="contact-shared",
            members=("elder-2", "elder-3"),
            vehicle_need="accessible",
        )
        edge = score_edge(left, right)
        self.assertLess(edge.score, PLAUSIBLE_THRESHOLD)
        self.assertFalse(edge.plausible)
        self.assertIn(
            "shared_contact_key",
            [item["reason"] for item in edge.evidence],
        )
        # 共用联络键的权重明显低于成员全等或地址一致这类强证据。
        contact_weight = next(
            item["weight"]
            for item in edge.evidence
            if item["reason"] == "shared_contact_key"
        )
        self.assertLess(contact_weight, 0.2)

    def test_missing_fields_are_not_negative_evidence(self):
        # 没有地址、没有电话但成员完全一致，仍可成为高置信候选。
        left = reg("r-b", address=None, contact_key=None)
        right = reg(
            "t-b",
            source="temporary",
            address=None,
            contact_key=None,
        )
        edge = score_edge(left, right)
        self.assertTrue(edge.plausible)
        self.assertNotIn(
            "missing_field_penalty",
            [item["reason"] for item in edge.evidence],
        )

    def test_relocation_uses_former_address_chain(self):
        payload = load_payload()
        planner = LinkagePlanner(payload)
        report = planner.analyze()
        group = next(
            item
            for item in report["groups"]
            if "resident-007" in item["registration_ids"]
        )
        edge = next(
            item
            for item in group["edges"]
            if item["left"] == "resident-007" and item["right"] == "temporary-007"
        )
        reasons = [
            evidence["reason"]
            for evidence in edge["evidence"]
            if evidence["reason"] == "former_address_chain"
        ]
        self.assertTrue(reasons)
        self.assertTrue(edge["plausible"])

    def test_repeating_member_labels_do_not_merge_unrelated_households(self):
        payload = load_payload()
        # adult-0 单人户在不同家庭重复出现；阻断不能只靠成员全等把它们连成一片。
        pairs = cross_roster_pairs(
            [Registration.from_payload(row) for row in payload["registrations"]]
        )
        self.assertNotIn(("resident-000", "temporary-015"), pairs)
        # resident-000/temporary-000 无地址无电话，靠人工同户锚点进入候选，
        # 而不是靠重复的成员标签被阻断键自动拉入。
        planner = LinkagePlanner(payload)
        report = planner.analyze()
        edge = next(
            item
            for item in report["candidate_edges"]
            if item["left"] == "resident-000" and item["right"] == "temporary-000"
        )
        self.assertTrue(edge["manual_forced"] or edge["manual_forbidden"])

    def test_blocking_reasons_are_explainable(self):
        left = reg("r-c", address="lane-1", contact_key="contact-1")
        right = reg(
            "t-c",
            source="temporary",
            address="lane-1",
            contact_key="contact-1",
        )
        reasons = blocking_reasons(left, right)
        self.assertIn("same_current_address", reasons)
        self.assertIn("shared_contact_key", reasons)


class OneToOneAndGroupConsistencyTests(unittest.TestCase):
    def _edge(self, left: str, right: str, score: float) -> CandidateEdge:
        return CandidateEdge(
            left=left,
            right=right,
            left_source="resident",
            right_source="temporary",
            role="cross",
            score=score,
            plausible=score >= PLAUSIBLE_THRESHOLD,
            overlap_in_time=True,
        )

    def test_assignment_is_one_to_one(self):
        edges = [
            self._edge("r1", "t1", 0.95),
            self._edge("r1", "t2", 0.2),
            self._edge("r2", "t1", 0.8),
            self._edge("r2", "t2", 0.3),
        ]
        assignment = hungarian_assignment(["r1", "r2"], ["t1", "t2"], edges)
        self.assertEqual(len(set(assignment.values())), len(assignment))
        self.assertEqual(assignment["r1"], "t1")
        self.assertEqual(assignment["r2"], "t2")

    def test_chain_similarity_does_not_force_three_way_merge(self):
        # 甲像乙、乙像丙不代表甲丙同户；没有强制锚点时只允许一对一。
        edges = [
            self._edge("r1", "t1", 0.9),
            self._edge("r2", "t1", 0.85),
            self._edge("r2", "t2", 0.8),
        ]
        scenarios = enumerate_scenarios(["r1", "r2"], ["t1", "t2"], edges)
        for scenario in scenarios:
            rights = [value for value in scenario["matching"].values() if value]
            self.assertEqual(len(rights), len(set(rights)))

    def test_transitive_anchor_conflict_is_flagged_not_auto_resolved(self):
        edges = [
            CandidateEdge(
                "a", "b", "resident", "temporary", "cross", 0.9, True, True,
                manual_forced=True,
            ),
            CandidateEdge(
                "b", "c", "resident", "temporary", "cross", 0.9, True, True,
                manual_forced=True,
            ),
            CandidateEdge(
                "a", "c", "resident", "temporary", "cross", 0.2, False, True,
                manual_forbidden=True,
            ),
        ]
        conflicts = transitive_conflicts(["a", "b", "c"], edges)
        self.assertTrue(
            any(item["type"] == "transitive_anchor_conflict" for item in conflicts)
        )

    def test_fixture_scenarios_never_violate_one_to_one(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        for group in report["groups"]:
            for scenario in group["scenarios"]:
                rights = [
                    value for value in scenario["matching"].values() if value
                ]
                self.assertEqual(len(rights), len(set(rights)))


class AnchorConflictTests(unittest.TestCase):
    def test_reversed_manual_decision_is_reported_with_full_provenance(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        conflicts = [
            conflict
            for group in report["groups"]
            for conflict in group["conflicts"]
        ]
        reversal = next(
            item
            for item in conflicts
            if item["type"] == "manual_decision_reversed"
        )
        self.assertEqual(reversal["left"], "resident-000")
        self.assertEqual(reversal["right"], "temporary-000")
        self.assertTrue(reversal["current_forbidden"])
        review_ids = {source["review_id"] for source in reversal["sources"]}
        self.assertIn("review-0", review_ids)
        self.assertIn("conflict-1", review_ids)

    def test_latest_decision_wins_but_history_is_kept(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        entries = [
            item
            for item in report["decision_log"]
            if tuple(item["pair"]) == ("resident-000", "temporary-000")
        ]
        self.assertEqual(len(entries), 2)
        self.assertTrue(any(item["superseded"] for item in entries))
        active = [item for item in entries if not item["superseded"]]
        self.assertEqual(len(active), 1)
        self.assertFalse(active[0]["same"])

    def test_different_household_anchor_blocks_edge(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        edge = next(
            item
            for item in report["candidate_edges"]
            if item["left"] == "resident-002" and item["right"] == "temporary-003"
        )
        self.assertTrue(edge["manual_forbidden"])
        self.assertFalse(edge["plausible"])


class SplitAndTimelineTests(unittest.TestCase):
    def test_split_event_is_longitudinal_not_cross_merge(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        edge = next(
            item
            for item in report["candidate_edges"]
            if item["left"] == "historic-household"
            and item["right"] == "split-household-a"
        )
        self.assertEqual(edge["role"], "longitudinal")
        self.assertFalse(edge["plausible"])

    def test_historic_registration_is_not_assigned_to_current_temporary(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        group = next(
            item
            for item in report["groups"]
            if "historic-household" in item["registration_ids"]
        )
        for scenario in group["scenarios"]:
            self.assertNotIn("historic-household", scenario["matching"])

    def test_non_overlapping_validity_cannot_be_cross_match(self):
        old = reg(
            "old",
            valid_from="2025-01-01",
            valid_until="2026-01-01",
            contact_key="contact-t",
        )
        current = reg(
            "t-new",
            source="temporary",
            contact_key="contact-t",
        )
        edge = score_edge(old, current)
        self.assertFalse(edge.overlap_in_time)
        self.assertEqual(edge.role, "longitudinal")
        self.assertFalse(edge.plausible)


class DemandRangeTests(unittest.TestCase):
    def test_demand_range_spans_linked_and_independent_worlds(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        uncertain = next(
            group
            for group in report["groups"]
            if group["demand"]["people"]["range"] > 0
        )
        self.assertGreater(uncertain["demand"]["people"]["max"], 0)
        labels = {scenario["label"] for scenario in uncertain["scenarios"]}
        self.assertIn("all_independent_households", labels)
        self.assertIn("maximal_matching", labels)

    def test_global_demand_reports_min_max_and_range(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        people = report["global_demand"]["people"]
        self.assertGreaterEqual(people["max"], people["min"])
        self.assertEqual(people["range"], people["max"] - people["min"])
        self.assertGreater(people["range"], 0)

    def test_matching_does_not_double_count_people(self):
        registrations = {
            "r1": reg("r1", members=("a", "b")),
            "t1": reg("t1", source="temporary", members=("a", "b")),
        }
        from vulnerable_transfer_planner.linkage.demand import (
            demand_snapshot,
            scenario_households,
        )

        households = scenario_households(
            ["r1", "t1"], {"r1": "t1"}
        )
        snapshot = demand_snapshot(registrations, households)
        self.assertEqual(snapshot["people"], 2)
        self.assertEqual(snapshot["households"], 1)


class ReviewQueueTests(unittest.TestCase):
    def test_conflict_group_outranks_score_only_pairs(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        top = report["review_queue"][0]
        self.assertEqual(top["left"], "resident-000")
        self.assertEqual(top["right"], "temporary-000")
        self.assertIn("manual_anchor_conflict", top["reasons"])

    def test_review_budget_is_respected_and_spread_across_groups(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        within = [item for item in report["review_queue"] if item["within_budget"]]
        self.assertEqual(len(within), report["review_budget"])
        # 名额不应被单一群组占满。
        self.assertGreater(len({item["group_id"] for item in within}), 1)

    def test_priority_reflects_information_value_not_score_proximity(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        queue = report["review_queue"]
        for earlier, later in zip(queue, queue[1:]):
            self.assertGreaterEqual(earlier["priority"], later["priority"])


class LocalUpdateTests(unittest.TestCase):
    def test_local_update_only_recomputes_affected_group(self):
        planner = LinkagePlanner(load_payload())
        before = planner.analyze()
        decision = ManualDecision(
            "resident-050", "temporary-051", False, "field-1", "2026-08-03"
        )
        after, affected = planner.analyze_with_local_update(decision)
        self.assertEqual(affected, ["group-027"])
        untouched_before = next(
            item for item in before["groups"] if item["group_id"] == "group-030"
        )
        untouched_after = next(
            item for item in after["groups"] if item["group_id"] == "group-030"
        )
        self.assertEqual(untouched_before, untouched_after)

    def test_local_update_preserves_source_and_original_identifier(self):
        planner = LinkagePlanner(load_payload())
        decision = ManualDecision(
            "resident-050", "temporary-051", False, "field-2", "2026-08-03"
        )
        report, _ = planner.analyze_with_local_update(decision)
        edge = next(
            item
            for item in report["candidate_edges"]
            if item["left"] == "resident-050" and item["right"] == "temporary-051"
        )
        self.assertTrue(edge["manual_forbidden"])
        self.assertEqual(edge["origins"][0]["review_id"], "field-2")
        self.assertEqual(edge["left"], "resident-050")
        self.assertEqual(edge["right"], "temporary-051")

    def test_supersede_keeps_full_history(self):
        planner = LinkagePlanner(load_payload())
        first = ManualDecision("r-x", "t-x", True, "rv-1", "2026-08-02")
        second = ManualDecision("r-x", "t-x", False, "rv-2", "2026-08-03")
        planner.apply_decision(first, origin="field_review")
        planner.apply_decision(second, origin="field_review")
        entries = [
            item
            for item in planner.decision_log
            if tuple(item["pair"]) == ("r-x", "t-x")
        ]
        self.assertEqual(len(entries), 2)
        self.assertTrue(entries[0]["superseded"])
        self.assertFalse(entries[1]["superseded"])


class CohortIsolationTests(unittest.TestCase):
    def test_no_cross_cohort_edges(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        cohorts = {
            row["registration_id"]: row["cohort"]
            for row in load_payload()["registrations"]
        }
        for edge in report["candidate_edges"]:
            self.assertEqual(cohorts[edge["left"]], cohorts[edge["right"]])

    def test_validation_cohort_has_no_anchor_leakage(self):
        planner = LinkagePlanner(load_payload())
        report = planner.analyze()
        cohorts = {
            row["registration_id"]: row["cohort"]
            for row in load_payload()["registrations"]
        }
        for edge in report["candidate_edges"]:
            if cohorts[edge["left"]] == "validation":
                self.assertEqual(edge["origins"], [])

    def test_development_anchors_reference_only_development(self):
        payload = load_payload()
        cohorts = {
            row["registration_id"]: row["cohort"]
            for row in payload["registrations"]
        }
        for anchor in payload["anchors"]:
            self.assertEqual(cohorts[anchor["left"]], "development")
            self.assertEqual(cohorts[anchor["right"]], "development")


class SideEffectAndCliTests(unittest.TestCase):
    def test_analysis_does_not_import_mission_pipeline(self):
        # 同户分析模块保持独立，不能依赖 SQLite 账本或任务状态机。
        import vulnerable_transfer_planner.linkage.analysis as analysis

        source = Path(analysis.__file__).read_text(encoding="utf-8")
        self.assertNotIn("mission", source.lower().replace("transmission", ""))
        self.assertNotIn("sqlite", source.lower())

    def test_invalid_reference_raises_domain_error(self):
        payload = load_payload()
        payload["anchors"].append(
            {
                "left": "resident-000",
                "right": "missing-id",
                "same": True,
                "review_id": "bad",
                "at": "2026-08-02",
            }
        )
        with self.assertRaises(LinkageError):
            LinkagePlanner(payload)

    def test_cli_writes_outputs_without_task_state_change(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "linkage"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vulnerable_transfer_planner.linkage",
                    str(FIXTURE),
                    "--output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            console = json.loads(result.stdout)
            self.assertEqual(console["schema"], "household_linkage_analysis/v1")
            for name in (
                "summary.json",
                "candidate_edges.json",
                "groups.json",
                "review_queue.json",
                "decision_log.json",
                "manifest.json",
            ):
                self.assertTrue((output / name).exists())
            # 输出目录里没有任何数据库文件。
            self.assertFalse(list(Path(directory).glob("*.sqlite3")))


if __name__ == "__main__":
    unittest.main()
