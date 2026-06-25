"""
Presence state and event derivation for LANAgent.
"""

import time
import threading
from typing import Dict, Iterable, List, Optional


class PresenceMonitor:
    """Turns point-in-time scan observations into durable presence state."""

    def __init__(
        self,
        grace: float = 1800,
        sleep_grace: float = 12 * 3600,
        miss_count: int = 3,
        min_probe_completeness: float = 0.35,
        resume_gap: float = 300,
        cadence: float = 60,
        max_events: int = 1000,
    ):
        self.grace = grace
        self.sleep_grace = sleep_grace
        self.miss_count = miss_count
        self.min_probe_completeness = min_probe_completeness
        self.resume_gap = resume_gap
        self.cadence = cadence
        self.max_events = max_events
        self.records: Dict[str, Dict[str, object]] = {}
        self.events: List[Dict[str, object]] = []
        self.lock = threading.RLock()
        self.next_sequence = 1
        self.probe_degraded = False
        self.last_update_started: Optional[float] = None
        self.last_update: Optional[Dict[str, object]] = None

    def update(self, devices: Iterable[Dict[str, object]], now: Optional[float] = None) -> None:
        with self.lock:
            now = now or time.time()
            cycle_gap = self._cycle_gap(now)
            if cycle_gap is not None and self._is_resume_gap(cycle_gap):
                local_pause = max(0.0, cycle_gap - self.cadence)
                self._shift_last_seen(local_pause)
                self._append_event(
                    "monitor_resumed",
                    now,
                    {
                        "pause": int(cycle_gap),
                        "ignored": int(local_pause),
                    },
                )
            self.last_update_started = now

            observed = self._observed_by_key(devices)
            self._promote_ip_records(observed)
            seen_keys = set(observed)
            present_before = {key for key, record in self.records.items() if record.get("present")}
            expected = len(present_before)
            seen_known_present = len(seen_keys & present_before)
            complete_enough = self._probe_complete_enough(seen_known_present, expected)

            for key, device in observed.items():
                record = self.records.get(key)
                if record is None:
                    self.records[key] = self._new_record(key, device, now)
                    self._append_event("joined", now, {"device": self.records[key].copy()})
                    continue

                was_present = bool(record.get("present"))
                away_for = int(now - float(record.get("lastSeen", now)))
                record.update({
                    "ip": device.get("ip", record.get("ip", "")),
                    "mac": device.get("mac", record.get("mac", "")),
                    "hostname": device.get("hostname", record.get("hostname", "")),
                    "lastSeen": now,
                    "misses": 0,
                    "present": True,
                    "source": device.get("source", record.get("source", "scan")),
                })
                if self._is_sleep_tolerant(device):
                    record["sleepTolerant"] = True
                if not was_present:
                    event_device = record.copy()
                    event_device["awayFor"] = away_for
                    self._append_event("back_online", now, {"device": event_device})

            if not complete_enough:
                if not self.probe_degraded:
                    self._append_event(
                        "probe_degraded",
                        now,
                        {
                            "seen": seen_known_present,
                            "expected": expected,
                            "minProbeCompleteness": self.min_probe_completeness,
                        },
                    )
                self.probe_degraded = True
                self._set_last_update(now, seen_known_present, expected, complete_enough)
                return

            if self.probe_degraded:
                self._append_event(
                    "probe_recovered",
                    now,
                    {"seen": seen_known_present, "expected": expected},
                )
                self.probe_degraded = False

            for key, record in list(self.records.items()):
                if not record.get("present") or key in seen_keys:
                    continue
                misses = int(record.get("misses", 0)) + 1
                record["misses"] = misses
                gone = now - float(record.get("lastSeen", now))
                threshold = self.sleep_grace if record.get("sleepTolerant") else self.grace
                if misses >= self.miss_count and gone >= threshold:
                    record["present"] = False
                    event_device = record.copy()
                    event_device["goneFor"] = int(gone)
                    self._append_event("left", now, {"device": event_device})

            self._set_last_update(now, seen_known_present, expected, complete_enough)

    def snapshot(self, include_absent: bool = False) -> List[Dict[str, object]]:
        with self.lock:
            records = [
                record.copy()
                for record in self.records.values()
                if include_absent or record.get("present")
            ]
            return sorted(records, key=lambda record: str(record.get("ip", "")))

    def events_since(self, since: int = 0, limit: int = 200) -> List[Dict[str, object]]:
        with self.lock:
            selected = [event.copy() for event in self.events if int(event["sequence"]) > since]
            return selected[:max(0, limit)]

    def diagnostics(self) -> Dict[str, object]:
        with self.lock:
            present = sum(1 for record in self.records.values() if record.get("present"))
            return {
                "records": len(self.records),
                "present": present,
                "events": len(self.events),
                "lastEventSequence": self.next_sequence - 1,
                "probeDegraded": self.probe_degraded,
                "lastUpdate": self.last_update,
                "grace": self.grace,
                "sleepGrace": self.sleep_grace,
                "missCount": self.miss_count,
                "minProbeCompleteness": self.min_probe_completeness,
                "resumeGap": self.resume_gap,
            }

    def _new_record(self, key: str, device: Dict[str, object], now: float) -> Dict[str, object]:
        return {
            "key": key,
            "ip": device.get("ip", ""),
            "mac": device.get("mac", ""),
            "hostname": device.get("hostname", ""),
            "firstSeen": now,
            "lastSeen": now,
            "present": True,
            "misses": 0,
            "source": device.get("source", "scan"),
            "sleepTolerant": self._is_sleep_tolerant(device),
        }

    def _observed_by_key(self, devices: Iterable[Dict[str, object]]) -> Dict[str, Dict[str, object]]:
        observed: Dict[str, Dict[str, object]] = {}
        ip_to_key: Dict[str, str] = {}
        for device in devices:
            ip = str(device.get("ip", ""))
            mac = str(device.get("mac", ""))
            if mac and ip:
                ip_to_key[ip] = mac

        for device in devices:
            ip = str(device.get("ip", ""))
            mac = str(device.get("mac", ""))
            key = mac if mac else ip_to_key.get(ip) or self._known_key_for_ip(ip) or ip
            if not key:
                continue
            source = str(device.get("source", "scan"))
            hostname = str(device.get("hostname", ""))
            existing = observed.get(key)
            if existing:
                if ip:
                    existing["ip"] = ip
                if mac:
                    existing["mac"] = mac
                elif not existing.get("mac"):
                    existing["mac"] = str(self.records.get(key, {}).get("mac", ""))
                if hostname:
                    existing["hostname"] = hostname
                existing["source"] = self._merge_sources(str(existing.get("source", "")), source)
                continue
            observed[key] = {
                "ip": ip,
                "mac": mac or str(self.records.get(key, {}).get("mac", "")),
                "source": source,
                "hostname": hostname,
            }
        return observed

    def _known_key_for_ip(self, ip: str) -> Optional[str]:
        if not ip:
            return None
        for key, record in self.records.items():
            if record.get("ip") == ip:
                return key
        return None

    def _promote_ip_records(self, observed: Dict[str, Dict[str, object]]) -> None:
        """Move an existing IP-keyed Bonjour record to its later MAC-keyed identity."""
        promotions = [
            (key, str(device.get("ip", "")), str(device.get("mac", "")))
            for key, device in observed.items()
            if device.get("ip") and device.get("mac") and key == device.get("mac")
        ]
        for target_key, ip, mac in promotions:
            old_key = self._known_ip_only_key_for_ip(ip, excluding=target_key)
            if not old_key:
                continue
            old_record = self.records.pop(old_key)
            target_record = self.records.get(target_key)
            if target_record is None:
                old_record["key"] = target_key
                old_record["mac"] = mac
                old_record["source"] = self._merge_sources(str(old_record.get("source", "")), str(observed[target_key].get("source", "")))
                if observed[target_key].get("hostname"):
                    old_record["hostname"] = observed[target_key].get("hostname", "")
                old_record["sleepTolerant"] = bool(old_record.get("sleepTolerant")) or self._is_sleep_tolerant(observed[target_key])
                self.records[target_key] = old_record
                continue

            target_record["firstSeen"] = min(
                float(target_record.get("firstSeen", 0)),
                float(old_record.get("firstSeen", target_record.get("firstSeen", 0))),
            )
            target_record["lastSeen"] = max(
                float(target_record.get("lastSeen", 0)),
                float(old_record.get("lastSeen", target_record.get("lastSeen", 0))),
            )
            target_record["present"] = bool(target_record.get("present")) or bool(old_record.get("present"))
            target_record["misses"] = min(int(target_record.get("misses", 0)), int(old_record.get("misses", 0)))
            target_record["sleepTolerant"] = bool(target_record.get("sleepTolerant")) or bool(old_record.get("sleepTolerant"))
            if not target_record.get("hostname") and old_record.get("hostname"):
                target_record["hostname"] = old_record.get("hostname", "")
            target_record["source"] = self._merge_sources(str(target_record.get("source", "")), str(old_record.get("source", "")))

    def _known_ip_only_key_for_ip(self, ip: str, excluding: str) -> Optional[str]:
        for key, record in self.records.items():
            if key == excluding:
                continue
            if key != ip:
                continue
            if record.get("ip") == ip and not record.get("mac"):
                return key
        return None

    def _merge_sources(self, left: str, right: str) -> str:
        sources = []
        for source in (left, right):
            for part in source.split("+"):
                if part and part not in sources:
                    sources.append(part)
        return "+".join(sources) or "scan"

    def _is_sleep_tolerant(self, device: Dict[str, object]) -> bool:
        source = str(device.get("source", "")).lower()
        hostname = str(device.get("hostname", "")).lower()
        mac = str(device.get("mac", ""))
        if "bonjour" in source:
            return True
        if any(token in hostname for token in ("apple", "iphone", "ipad", "watch", "macbook", "imac", "appletv")):
            return True
        return self._is_locally_administered(mac)

    @staticmethod
    def _is_locally_administered(mac: str) -> bool:
        try:
            first_octet = int(mac.split(":")[0], 16)
        except (IndexError, ValueError):
            return False
        return bool(first_octet & 0x02)

    def _cycle_gap(self, now: float) -> Optional[float]:
        if self.last_update_started is None:
            return None
        return now - self.last_update_started

    def _is_resume_gap(self, interval: float) -> bool:
        if self.resume_gap <= 0:
            return False
        return interval >= max(self.resume_gap, self.cadence * 2.5)

    def _shift_last_seen(self, interval: float) -> None:
        if interval <= 0:
            return
        for record in self.records.values():
            if record.get("present"):
                record["lastSeen"] = float(record.get("lastSeen", 0)) + interval

    def _probe_complete_enough(self, seen: int, expected: int) -> bool:
        if expected < 10 or self.min_probe_completeness <= 0:
            return True
        return (seen / expected) >= self.min_probe_completeness

    def _set_last_update(self, now: float, seen: int, expected: int, complete_enough: bool) -> None:
        self.last_update = {
            "timestamp": now,
            "seen": seen,
            "expected": expected,
            "completeEnough": complete_enough,
        }

    def _append_event(self, event_type: str, timestamp: float, payload: Dict[str, object]) -> None:
        event = {
            "sequence": self.next_sequence,
            "timestamp": timestamp,
            "type": event_type,
        }
        event.update(payload)
        self.next_sequence += 1
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
