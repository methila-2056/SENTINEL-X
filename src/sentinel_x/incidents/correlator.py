"""Event correlation: cluster related events into candidate incidents.

Uses union-find over proximity links: events are joined when they share an
entity (host / user / source ip) within a configurable time window.
"""

from collections import defaultdict
from dataclasses import dataclass, field

import pandas as pd

from sentinel_x.common.netutil import is_internal_ip


@dataclass
class CandidateIncident:
    member_event_ids: list[str] = field(default_factory=list)
    users: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    src_ips: set[str] = field(default_factory=set)
    dst_ips_external: set[str] = field(default_factory=set)
    first_seen: pd.Timestamp | None = None
    last_seen: pd.Timestamp | None = None


class UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def correlate_events(
    events: pd.DataFrame,
    entity_link_window: str = "15min",
    same_host_link: bool = True,
    same_user_link: bool = True,
    same_src_ip_link: bool = True,
) -> list[CandidateIncident]:
    """Group events into connected components based on shared entities in time proximity.

    Args:
        events: canonical event DataFrame (must contain timestamp, event_id).
    Returns:
        List of candidate incidents sorted by size descending.
    """
    df = events.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("timestamp").reset_index(drop=True)

    window = pd.Timedelta(entity_link_window)
    uf = UnionFind(len(df))
    keys: dict[str, list[tuple[pd.Timestamp, int]]] = defaultdict(list)

    link_fields = []
    if same_host_link:
        link_fields.append("host")
    if same_user_link:
        link_fields.append("user")
    if same_src_ip_link:
        link_fields.append("src_ip")

    # Index events per entity value
    for field_name in link_fields:
        if field_name not in df.columns:
            continue
        for idx, val in zip(df.index, df[field_name].fillna("").astype(str), strict=True):
            if val and val != "":
                keys[f"{field_name}={val}"].append((df.at[idx, "timestamp"], idx))

    # Union events sharing an entity within the time window
    for occurrences in keys.values():
        occurrences.sort()
        for i, (ts_i, idx_i) in enumerate(occurrences):
            for ts_j, idx_j in occurrences[i + 1 :]:
                if ts_j - ts_i > window:
                    break
                uf.union(idx_i, idx_j)

    groups: dict[int, list[int]] = defaultdict(list)
    for idx in range(len(df)):
        groups[uf.find(idx)].append(idx)

    incidents: list[CandidateIncident] = []
    for members in groups.values():
        cand = CandidateIncident()
        sub = df.loc[members]
        cand.member_event_ids = sub["event_id"].tolist()
        for col, target in (("user", "users"), ("host", "hosts"), ("src_ip", "src_ips")):
            vals = set(sub[col].dropna().astype(str)) - {""}
            getattr(cand, target).update(vals)
        dst = sub["dst_ip"].dropna().astype(str)
        ext = {d for d in dst if d and not is_internal_ip(d)}
        cand.dst_ips_external.update(ext)
        cand.first_seen = sub["timestamp"].min()
        cand.last_seen = sub["timestamp"].max()
        incidents.append(cand)

    incidents.sort(key=lambda c: len(c.member_event_ids), reverse=True)
    return incidents
