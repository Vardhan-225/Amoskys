"""Linux Process Agent — Process Observatory for Linux.

Scaffold agent — uses the same probe set as macOS but with a
Linux-specific collector that leverages /proc and auditd.

To implement:
    1. Build LinuxProcessCollector in collector.py
    2. The probes from macOS work as-is (they read shared_data dicts)
    3. Test on a Linux device with ground-truth verification
"""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Any, Sequence

from amoskys.agents.common.base import HardenedAgentBase, ValidationResult
from amoskys.agents.common.probes import MicroProbeAgentMixin
from amoskys.agents.common.queue_adapter import LocalQueueAdapter
from amoskys.agents.os.macos.process.probes import create_process_probes
from amoskys.config import get_config

logger = logging.getLogger(__name__)

config = get_config()
QUEUE_PATH = "data/queue/linux_process.db"


class LinuxProcessAgent(MicroProbeAgentMixin, HardenedAgentBase):
    """Linux Process Observatory agent (scaffold).

    Uses the same 10 probes as macOS — detection logic is platform-agnostic.
    Only the collector needs Linux-specific implementation.
    """

    def __init__(self, collection_interval: float = 10.0) -> None:
        device_id = socket.gethostname()
        Path(QUEUE_PATH).parent.mkdir(parents=True, exist_ok=True)
        queue_adapter = LocalQueueAdapter(
            queue_path=QUEUE_PATH,
            agent_name="linux_process",
            device_id=device_id,
            max_bytes=50 * 1024 * 1024,
            max_retries=10,
            signing_key_path=f"{config.agent.cert_dir}/agent.ed25519",
        )
        super().__init__(
            agent_name="linux_process",
            device_id=device_id,
            collection_interval=collection_interval,
            queue_adapter=queue_adapter,
        )
        # Probes are platform-agnostic — same as macOS
        self.register_probes(create_process_probes())
        logger.info(
            "LinuxProcessAgent initialized (scaffold): %d probes", len(self._probes)
        )

    def setup(self) -> bool:
        import platform

        if platform.system() != "Linux":
            logger.error("LinuxProcessAgent requires Linux")
            return False
        return self.setup_probes(
            collector_shared_data_keys=[
                "processes",
                "own_user_count",
                "total_count",
                "collection_time_ms",
            ]
        )

    def collect_data(self) -> Sequence[Any]:
        raise NotImplementedError(
            "LinuxProcessAgent collector not yet implemented. "
            "Port MacOSProcessCollector to use /proc + auditd."
        )

    def validate_event(self, event: Any) -> ValidationResult:
        errors = []
        if not hasattr(event, "device_id") or not event.device_id:
            errors.append("Missing device_id")
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def shutdown(self) -> None:
        logger.info("LinuxProcessAgent shutting down")
