from __future__ import annotations

from collections.abc import Iterable

from .models import MCPConfig, ScanReport
from .rules import RULES


def scan_configs(configs: Iterable[MCPConfig]) -> ScanReport:
    config_list = list(configs)
    findings = []
    for config in config_list:
        for server in config.servers:
            for rule in RULES:
                findings.extend(rule(server))
    return ScanReport(configs=config_list, findings=findings)
