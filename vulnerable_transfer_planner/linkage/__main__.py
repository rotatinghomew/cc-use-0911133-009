"""命令行入口：

    python3 -m vulnerable_transfer_planner.linkage fixtures/household_linkage.json \
        --output /tmp/household-linkage

该入口只读取名册 JSON、写出分析工件，不连接 SQLite、不导入任务状态机，
因此分析建议不会触发任何现有任务状态变化。
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from vulnerable_transfer_planner.linkage.analysis import LinkagePlanner, write_report
from vulnerable_transfer_planner.linkage.model import LinkageError, ManualDecision


def _load_decisions(path: str | None) -> list[ManualDecision]:
    if not path:
        return []
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload.get("decisions", payload if isinstance(payload, list) else [])
    return [ManualDecision.from_payload(row) for row in rows]


def run(fixture_path: str, output_dir: str, decision_path: str | None = None) -> dict[str, Any]:
    payload = json.loads(Path(fixture_path).read_text(encoding="utf-8"))
    planner = LinkagePlanner(payload)
    affected: list[str] = []
    decisions = _load_decisions(decision_path)
    if decisions:
        for decision in decisions[:-1]:
            planner.apply_decision(decision, origin="cli_decision_file")
        report, affected = planner.analyze_with_local_update(decisions[-1])
    else:
        report = planner.analyze()
    manifest = write_report(report, output_dir)
    report["output_manifest"] = manifest
    report["local_update"] = {
        "applied": bool(decisions),
        "affected_groups": affected,
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="村级名册同户分析（只读建议，不合并转移任务）"
    )
    parser.add_argument("fixture", help="批量名册 JSON 路径")
    parser.add_argument("--output", required=True, help="分析工件输出目录")
    parser.add_argument(
        "--decisions",
        help="可选：人工结论 JSON（含 left/right/same/review_id/at 的列表或对象）",
    )
    args = parser.parse_args(argv)
    try:
        report: Mapping[str, Any] = run(args.fixture, args.output, args.decisions)
    except (LinkageError, FileNotFoundError, KeyError) as exc:
        parser.exit(2, f"名册分析失败: {exc}\n")
    console = {
        key: report[key]
        for key in (
            "schema",
            "as_of",
            "registration_count",
            "candidate_edge_count",
            "group_count",
            "cohort_summary",
            "global_demand",
            "review_budget",
            "local_update",
            "output_manifest",
        )
    }
    console["top_review_queue"] = report["review_queue"][: report["review_budget"] or 5]
    print(json.dumps(console, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
