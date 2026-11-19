"""
Ephemeral Socket Attribution Cache for Uncloak.
Retains 5-tuple to process-identity mappings across short-lived connections so rapid
beacons that close before polling intervals remain attributable via the Hybrid Triplet.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, replace
from typing import Any, Callable, Optional

SocketKey = tuple[str, str, int, str, int]


@dataclass(frozen=True)
class CachedSocketAttribution:
    """Immutable process identity bound to a network 5-tuple."""

    pid: int
    process_name: str
    executable_path: str
    process_guid: str
    sha256: str
    is_signed: bool
    path_class: int
    first_seen: float
    last_seen: float


class SocketAttributionCache:
    """Bounded, thread-safe TTL cache mapping 5-tuple sockets to process triplets."""

    def __init__(self, ttl_seconds: float = 30.0, max_entries: int = 4096) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries <= 0:
            raise ValueError("max_entries must be positive")
        self.ttl_seconds = float(ttl_seconds)
        self.max_entries = int(max_entries)
        self._lock = threading.Lock()
        self._entries: OrderedDict[SocketKey, CachedSocketAttribution] = OrderedDict()

    def record(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        attribution: CachedSocketAttribution,
        proto: str = "TCP",
    ) -> None:
        """Inserts or refreshes a 5-tuple attribution entry, evicting oldest on capacity."""
        key: SocketKey = (proto.upper(), local_ip, int(local_port), remote_ip, int(remote_port))
        with self._lock:
            existing = self._entries.get(key)
            if existing and existing.pid == attribution.pid and existing.process_guid == attribution.process_guid:
                updated = replace(
                    attribution,
                    first_seen=min(existing.first_seen, attribution.first_seen),
                    last_seen=max(existing.last_seen, attribution.last_seen),
                )
                self._entries[key] = updated
                self._entries.move_to_end(key)
                return

            self._entries[key] = attribution
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)

    def lookup(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        proto: str = "TCP",
        now: Optional[float] = None,
    ) -> Optional[CachedSocketAttribution]:
        """Retrieves an active or recently closed socket attribution within the TTL window."""
        ts = time.time() if now is None else float(now)
        key: SocketKey = (proto.upper(), local_ip, int(local_port), remote_ip, int(remote_port))
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if ts - entry.last_seen > self.ttl_seconds:
                self._entries.pop(key, None)
                return None
            return entry

    def ingest_table_rows(
        self,
        rows: list[dict[str, Any]],
        resolver: Optional[Callable[[int], dict[str, Any]]] = None,
        now: Optional[float] = None,
    ) -> int:
        """Refreshes the cache from kernel TCP table rows, returning count of ingested tuples."""
        ts = time.time() if now is None else float(now)
        ingested = 0
        for row in rows:
            pid = int(row.get("pid", 0))
            local_ip = str(row.get("local_ip", ""))
            local_port = int(row.get("local_port", 0))
            remote_ip = str(row.get("remote_ip", ""))
            remote_port = int(row.get("remote_port", 0))
            if not local_ip or not remote_ip or remote_port <= 0:
                continue

            meta = resolver(pid) if resolver else {}
            entry = CachedSocketAttribution(
                pid=pid,
                process_name=str(meta.get("process_name") or row.get("process_name") or f"pid-{pid}"),
                executable_path=str(meta.get("executable_path") or ""),
                process_guid=str(meta.get("process_guid") or ""),
                sha256=str(meta.get("sha256") or ""),
                is_signed=bool(meta.get("is_signed", False)),
                path_class=int(meta.get("path_class", 0)),
                first_seen=ts,
                last_seen=ts,
            )
            self.record(local_ip, local_port, remote_ip, remote_port, entry)
            ingested += 1
        return ingested

    def prune_expired(self, now: Optional[float] = None) -> int:
        """Purges all entries whose last_seen timestamp exceeds the TTL window."""
        ts = time.time() if now is None else float(now)
        removed = 0
        with self._lock:
            expired_keys = [
                k for k, v in self._entries.items() if (ts - v.last_seen) > self.ttl_seconds
            ]
            for k in expired_keys:
                self._entries.pop(k, None)
                removed += 1
        return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
