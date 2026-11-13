"""同一时点的一对一匹配与群组一致性。

匹配在每个候选连通群组内部、仅对 ``role == "cross"`` 且有效区间重叠的
resident↔temporary 候选做加权二分图指派，保证：

1. 同一时点一名 resident 至多匹配一名 temporary，反之亦然；
2. 人工"同户"锚点作为强制边，人工"不同户"锚点作为禁止边；
3. 不会把 甲↔乙、乙↔丙 这种传递性近似当成三户必然同户——强制边会做
   并查集闭包校验，冲突整体留给人工，不做自动裁定。

指派结果只是"机器建议基线"，不是合并决定；情景枚举会保留其他合理链接。
"""

from __future__ import annotations

from typing import Any

from vulnerable_transfer_planner.linkage.model import CandidateEdge

FORCED_WEIGHT = 1_000_000.0


class _UnionFind:
    def __init__(self, nodes: list[str]) -> None:
        self.parent = {node: node for node in nodes}

    def find(self, node: str) -> str:
        while self.parent[node] != node:
            self.parent[node] = self.parent[self.parent[node]]
            node = self.parent[node]
        return node

    def union(self, left: str, right: str) -> None:
        root_left = self.find(left)
        root_right = self.find(right)
        if root_left != root_right:
            self.parent[root_right] = root_left


def _eligible(edge: CandidateEdge) -> bool:
    return (
        edge.role == "cross"
        and edge.overlap_in_time
        and not edge.manual_forbidden
    )


def hungarian_assignment(
    left_nodes: list[str],
    right_nodes: list[str],
    edges: list[CandidateEdge],
) -> dict[str, str]:
    """最大化总权重的一对一指派，返回 left_id -> right_id。

    使用经典 e-maxx 匈牙利算法（O(n³)，1 基索引）：把权重取负转为最小化
    费用，方阵用大费用哑边补齐。求解后只回收真实且有权重的边，哑节点与
    禁止边不会出现在结果里。人工强制边赋予超大权重，闭包校验通过后必然
    被选中。
    """

    if not left_nodes or not right_nodes:
        return {}
    right_index = {node: index for index, node in enumerate(right_nodes)}
    size = max(len(left_nodes), len(right_nodes))
    # 补成方阵：不存在的候选给 0 权（等价于该登记不匹配），哑行列也为 0，
    # 因此矩形（两侧户数不等）也能求解，最后过滤零权/哑边。
    weight_matrix = [[0.0] * size for _ in range(size)]
    eligible_lookup: dict[tuple[str, str], CandidateEdge] = {}
    for edge in edges:
        if not _eligible(edge) or edge.right not in right_index:
            continue
        weight = FORCED_WEIGHT if edge.manual_forced else float(edge.score)
        if weight <= 0:
            continue
        row = left_nodes.index(edge.left)
        weight_matrix[row][right_index[edge.right]] = weight
        eligible_lookup[(edge.left, edge.right)] = edge
    cost = [[-value for value in row] for row in weight_matrix]

    # 经典 e-maxx 匈牙利最小费用指派（方阵，1 基索引）。u/v 为势函数，
    # p[j] 是与第 j 列配对的行，way[j] 是交替路上的列前驱。
    u = [0.0] * (size + 1)
    v = [0.0] * (size + 1)
    p = [0] * (size + 1)
    way = [0] * (size + 1)
    for row_index in range(1, size + 1):
        p[0] = row_index
        minv = [float("inf")] * (size + 1)
        used = [False] * (size + 1)
        column = 0
        while True:
            used[column] = True
            marked_row = p[column]
            delta = float("inf")
            next_column = 0
            for candidate in range(1, size + 1):
                if used[candidate]:
                    continue
                current = (
                    cost[marked_row - 1][candidate - 1]
                    - u[marked_row]
                    - v[candidate]
                )
                if current < minv[candidate]:
                    minv[candidate] = current
                    way[candidate] = column
                if minv[candidate] < delta:
                    delta = minv[candidate]
                    next_column = candidate
            for candidate in range(size + 1):
                if used[candidate]:
                    u[p[candidate]] += delta
                    v[candidate] -= delta
                else:
                    minv[candidate] -= delta
            column = next_column
            if p[column] == 0:  # 到达一个尚未配对的自由列
                break
        while True:
            previous = way[column]
            p[column] = p[previous]
            column = previous
            if column == 0:
                break

    assignment: dict[str, str] = {}
    for column in range(1, len(right_nodes) + 1):
        row_index = p[column]
        if row_index == 0 or row_index > len(left_nodes):
            continue
        left = left_nodes[row_index - 1]
        right = right_nodes[column - 1]
        if (
            weight_matrix[row_index - 1][column - 1] > 0
            and (left, right) in eligible_lookup
        ):
            assignment[left] = right
    return assignment


def transitive_conflicts(
    node_ids: list[str], edges: list[CandidateEdge]
) -> list[dict[str, Any]]:
    """检查人工同户闭包与人工不同户锚点之间的群组一致性冲突。"""

    forced = [edge for edge in edges if edge.manual_forced]
    forbidden = [edge for edge in edges if edge.manual_forbidden]
    union_find = _UnionFind(node_ids)
    for edge in forced:
        union_find.union(edge.left, edge.right)

    conflicts: list[dict[str, Any]] = []
    for edge in forbidden:
        if union_find.find(edge.left) == union_find.find(edge.right):
            conflicts.append(
                {
                    "type": "transitive_anchor_conflict",
                    "left": edge.left,
                    "right": edge.right,
                    "message": "人工同户闭包与人工不同户结论冲突，不能自动裁定",
                    "sources": list(edge.origins),
                }
            )
    return conflicts


def enumerate_scenarios(
    left_nodes: list[str],
    right_nodes: list[str],
    edges: list[CandidateEdge],
    limit: int = 64,
) -> list[dict[str, Any]]:
    """枚举群组内具有业务含义的链接情景（带数量上限）。

    只使用合理（plausible）且未被人工禁止的 cross 边；longitudinal 边
    不进入同一时点指派。返回两类情景：

    * 极大匹配情景：只要某条合理边还能加入就不允许留空，覆盖"链接成立"
      的各种一对一排列；
    * 独立家庭基线：群组内所有跨名册候选都不成立（如共用联络人的两户
      老人其实是两户），用于表达"全部按独立家庭转移"的需求上界。

    两类情景共同给出需求的最小值与最大值，未匹配登记显式记为 null。
    """

    options: dict[str, list[CandidateEdge]] = {node: [] for node in left_nodes}
    has_plausible = False
    for edge in edges:
        if edge.role != "cross" or not edge.overlap_in_time:
            continue
        if edge.manual_forbidden or not edge.plausible:
            continue
        options[edge.left].append(edge)
        has_plausible = True
    for node in options:
        options[node].sort(key=lambda item: (-item.score, item.right))

    scenarios: list[dict[str, Any]] = []

    def record(chosen: dict[str, str], used_right: set[str], label: str) -> None:
        if len(scenarios) >= limit:
            return
        scenarios.append(
            {
                "label": label,
                "matching": {node: chosen.get(node) for node in left_nodes},
                "unmatched_right": sorted(
                    node for node in right_nodes if node not in used_right
                ),
            }
        )

    # 独立家庭基线：所有合理候选都不合并，是需求人数/户数的保守上界。
    if has_plausible:
        record({}, set(), "all_independent_households")

    def walk(index: int, chosen: dict[str, str], used_right: set[str]) -> None:
        if len(scenarios) >= limit:
            return
        if index == len(left_nodes):
            record(chosen, used_right, "maximal_matching")
            return
        node = left_nodes[index]
        available = [
            edge for edge in options[node] if edge.right not in used_right
        ]
        if not available:
            # 没有仍可使用的合理候选，该登记在本群组内保持独立家庭。
            walk(index + 1, chosen, used_right)
            return
        for edge in available:
            chosen[node] = edge.right
            used_right.add(edge.right)
            walk(index + 1, chosen, used_right)
            used_right.remove(edge.right)
            chosen.pop(node, None)

    walk(0, {}, set())
    return scenarios
