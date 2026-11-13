"""时间轴工具：有效区间重叠判断与跨期分户解释。

成员变化和分户必须放回时间中解释，因此匹配算法不能只看当前字段。
这里只用标准库 ``datetime.date`` 做区间运算，不引入任何第三方依赖。
"""

from __future__ import annotations

from datetime import date

from vulnerable_transfer_planner.linkage.model import Registration


def parse_day(value: str) -> date:
    return date.fromisoformat(value)


def intervals_overlap(left: Registration, right: Registration) -> bool:
    """两条登记的有效区间是否在时间轴上重叠（端点相接不算重叠）。"""

    left_start = parse_day(left.valid_from)
    left_end = parse_day(left.valid_until)
    right_start = parse_day(right.valid_from)
    right_end = parse_day(right.valid_until)
    return left_start < right_end and right_start < left_end


def overlap_days(left: Registration, right: Registration) -> int:
    if not intervals_overlap(left, right):
        return 0
    start = max(parse_day(left.valid_from), parse_day(right.valid_from))
    end = min(parse_day(left.valid_until), parse_day(right.valid_until))
    return max(0, (end - start).days)


def split_relation(parent: Registration, child: Registration, effective_at: str) -> bool:
    """判断 child 是否是 parent 在 effective_at 之后的分户延续。

    业务判据：父登记在分户生效前已经失效，子登记在生效后才有效，
    且二者共享联络键或地址线索。该关系属于时间轴解释，不参与同一时点
    的一对一匹配。
    """

    if parent.valid_until > effective_at:
        return False
    if child.valid_from < effective_at:
        return False
    shared_contact = bool(
        parent.contact_key and child.contact_key and parent.contact_key == child.contact_key
    )
    shared_address = bool(
        parent.address
        and (parent.address == child.address or parent.address in child.former_addresses)
    )
    return shared_contact or shared_address
