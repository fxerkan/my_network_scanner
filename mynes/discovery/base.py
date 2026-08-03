"""Shared shape for every discovery backend.

A backend answers one question: "what did protocol X see on this network?"
It returns plain dicts keyed by an identity the merger can reconcile (ip and/or
mac), so backends stay independent of the scanner and of each other.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class DiscoveredDevice:
    """One device as seen by a single protocol."""

    source: str  # 'mdns' | 'ssdp' | 'ble' | 'mqtt' | 'arp' | 'ha'
    ip: str | None = None
    mac: str | None = None
    name: str | None = None
    model: str | None = None
    vendor: str | None = None
    device_type: str | None = None
    # Protocol-specific payload: TXT records, UPnP fields, MQTT topic, ...
    attributes: dict[str, Any] = field(default_factory=dict)
    services: list[str] = field(default_factory=list)

    def key(self) -> str:
        """Identity used for merging. MAC wins; IP is the fallback."""
        if self.mac:
            return f"mac:{self.mac.lower()}"
        if self.ip:
            return f"ip:{self.ip}"
        return f"{self.source}:{self.name or id(self)}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "ip": self.ip,
            "mac": self.mac,
            "name": self.name,
            "model": self.model,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "services": self.services,
            "attributes": self.attributes,
        }


class DiscoveryBackend:
    """Base class. Subclasses implement `discover()` and set `name`/`requires`."""

    name = "base"
    requires: tuple[str, ...] = ()  # importable module names this backend needs

    def available(self) -> tuple[bool, str]:
        """(usable?, reason). Keeps optional deps optional instead of fatal."""
        import importlib.util

        for mod in self.requires:
            if importlib.util.find_spec(mod) is None:
                return False, f"missing optional dependency '{mod}'"
        return True, "ok"

    def discover(self, timeout: float = 5.0) -> list[DiscoveredDevice]:
        raise NotImplementedError

    def safe_discover(self, timeout: float = 5.0) -> list[DiscoveredDevice]:
        """discover() that never raises - one dead protocol must not kill a scan."""
        ok, reason = self.available()
        if not ok:
            log.info("discovery backend %s skipped: %s", self.name, reason)
            return []
        try:
            return self.discover(timeout=timeout)
        except Exception as e:  # noqa: BLE001 - backends touch flaky networks
            log.warning("discovery backend %s failed: %s", self.name, e)
            return []
