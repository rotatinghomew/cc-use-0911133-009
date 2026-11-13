"""候选生成（blocking）。

设计原则：
* 只在同一 cohort 内生成候选，避免开发/验证人群中同一真实家庭的不同
  登记互相串入。
* 缺失字段（地址或联络键为 null）只是没有该证据，不产生任何负向信号，
  也不会单独阻断候选。
* 共用联络键是弱线索：它把登记拉进同一个候选池，但绝不单独构成同户。
* 同一时点跨名册只保留 resident↔temporary 的候选，保证一对一匹配的
  两侧互斥；同源登记之间只允许通过 split_events 建立跨期关系。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from vulnerable_transfer_planner.linkage.model import Registration


def _same_cohort(left: Registration, right: Registration) -> bool:
    return left.cohort == right.cohort


def cross_roster_pairs(registrations: list[Registration]) -> set[tuple[str, str]]:
    """返回候选 (resident_id, temporary_id) 集合，按阻断键取并集。"""

    residents = [row for row in registrations if row.source == "resident"]
    temporaries = [row for row in registrations if row.source == "temporary"]

    contact_buckets: dict[str, list[Registration]] = defaultdict(list)
    address_buckets: dict[str, list[Registration]] = defaultdict(list)
    former_address_buckets: dict[str, list[Registration]] = defaultdict(list)
    member_buckets: dict[frozenset[str], list[Registration]] = defaultdict(list)

    for row in registrations:
        if row.contact_key:
            contact_buckets[row.contact_key].append(row)
        if row.address:
            address_buckets[row.address].append(row)
        for former in row.former_addresses:
            former_address_buckets[former].append(row)
        if row.members:
            member_buckets[row.member_set].append(row)

    pairs: set[tuple[str, str]] = set()

    def collect(buckets: dict[Any, list[Registration]]) -> None:
        for bucket in buckets.values():
            left_rows = [row for row in bucket if row.source == "resident"]
            right_rows = [row for row in bucket if row.source == "temporary"]
            for left in left_rows:
                for right in right_rows:
                    if _same_cohort(left, right):
                        pairs.add((left.registration_id, right.registration_id))

    collect(contact_buckets)
    collect(address_buckets)

    # 搬迁线索：一方现址出现在另一方曾用地址中，按地址漏判会丢掉这类家庭。
    for former, rows in former_address_buckets.items():
        holders = address_buckets.get(former, [])
        for left in holders:
            for right in rows:
                if left.source == right.source or not _same_cohort(left, right):
                    continue
                resident, temporary = (
                    (left, right) if left.source == "resident" else (right, left)
                )
                pairs.add((resident.registration_id, temporary.registration_id))

    # 成员标签（如 adult-0）是户内角色而非全局自然人标识，在不同家庭间会
    # 重复，因此成员集合全等不能单独阻断；只有同时具备地址/联络/搬迁旁证时
    # 才纳入候选，避免把共用角色标签的陌生家庭连成一个巨大群组，同时保证
    # 无联络键、无地址的家庭仍能通过成员全等 + 其他线索被找回。
    for bucket in member_buckets.values():
        left_rows = [row for row in bucket if row.source == "resident"]
        right_rows = [row for row in bucket if row.source == "temporary"]
        for left in left_rows:
            for right in right_rows:
                if not _same_cohort(left, right):
                    continue
                corroborated = (
                    (left.contact_key and left.contact_key == right.contact_key)
                    or (left.address and left.address == right.address)
                    or (
                        left.address
                        and left.address in right.former_addresses
                    )
                    or (
                        right.address
                        and right.address in left.former_addresses
                    )
                )
                if corroborated:
                    pairs.add((left.registration_id, right.registration_id))
    return pairs


def blocking_reasons(left: Registration, right: Registration) -> list[str]:
    """解释候选是被哪些阻断键拉进候选池的，供证据链使用。"""

    reasons: list[str] = []
    if left.contact_key and left.contact_key == right.contact_key:
        reasons.append("shared_contact_key")
    if left.address and left.address == right.address:
        reasons.append("same_current_address")
    # 搬迁线索：一方现址出现在另一方曾用地址中，按地址漏判会丢掉这类家庭。
    moved = (left.address and left.address in right.former_addresses) or (
        right.address and right.address in left.former_addresses
    )
    if moved:
        reasons.append("address_matches_other_former_address")
    # 成员集合全等是评分证据，不是阻断键（成员标签在不同家庭间会重复）。
    # 同一候选可能被多个键命中，证据去重但保留首次命中顺序。
    deduped: list[str] = []
    for reason in reasons:
        if reason not in deduped:
            deduped.append(reason)
    return deduped
