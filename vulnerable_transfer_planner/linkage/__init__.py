"""名册同户分析（linkage）。

该子包只做只读分析：生成候选关系、解释证据、标注不能自动裁定的冲突、
给出不同合理链接下的需求范围与复核优先级。它不导入任务状态机、SQLite 账本
等既有转移流程模块，因此任何分析输出都不会改变现有任务状态，也不会改写
原始登记标识（registration_id 始终原样保留）。
"""

from vulnerable_transfer_planner.linkage.analysis import LinkagePlanner
from vulnerable_transfer_planner.linkage.model import (
    CandidateEdge,
    LinkageError,
    LinkageGroup,
    ManualDecision,
    Registration,
)

__all__ = [
    "LinkagePlanner",
    "CandidateEdge",
    "LinkageError",
    "LinkageGroup",
    "ManualDecision",
    "Registration",
]
