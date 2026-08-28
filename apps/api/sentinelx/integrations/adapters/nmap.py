"""Nmap adapter.

Runs the real `nmap` binary when installed and parses XML output into
normalized services/assets. When nmap is unavailable the adapter reports
NOT_INSTALLED and the platform degrades gracefully.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from ..base import (
    NormalizedAsset,
    NormalizedFinding,
    NormalizedService,
    ToolAdapter,
    ToolNotInstalled,
    run_cli,
)

SERVICE_TO_CWE = {
    "http": "CWE-1188",
    "https": "CWE-1188",
    "ftp": "CWE-319",
    "telnet": "CWE-319",
    "ssh": "CWE-1188",
    "smb": "CWE-1188",
    "rdp": "CWE-1188",
}


class NmapAdapter(ToolAdapter):
    name = "nmap"
    category = "recon"
    description = "Network discovery and service enumeration (Nmap XML parser)"

    def build_request(self, target: str, params: dict[str, Any]) -> dict[str, Any]:
        # Constructed from validated structured params only — never user strings.
        scan_type = params.get("scan_type", "SYN")
        ports = params.get("ports")
        cmd = [self._binary_path(), "-oX", "-", "--unprivileged" if scan_type == "TCP_CONNECT" else "-sS"]
        if ports:
            cmd += ["-p", str(ports)]
        cmd += ["-T", str(params.get("timing", 3))]
        cmd.append(target)
        return {"cmd": cmd, "target": target, "params": params}

    def execute(self, request: dict[str, Any]) -> str:
        if not self._binary_available():
            raise ToolNotInstalled("nmap is not installed")
        proc = run_cli(request["cmd"], timeout=int(request["params"].get("timeout", 300)))
        if proc.returncode not in (0, 1):  # nmap returns 1 for "no open ports"
            raise ToolNotInstalled(f"nmap failed: {proc.stderr[:400]}")
        return proc.stdout

    def parse_output(self, raw: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        try:
            root = ET.fromstring(raw)
        except ET.ParseError:
            return results
        for host in root.findall("host"):
            addresses = host.findall("address")
            ip = next((a.get("addr") for a in addresses if a.get("addrtype") == "ipv4"), None)
            hostname = next(
                (h.get("name") for h in host.findall("hostnames/hostname") if h.get("type") == "PTR"),
                None,
            )
            ports: list[dict[str, Any]] = []
            for port in host.findall("ports/port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                service_el = port.find("service")
                ports.append(
                    {
                        "port": int(port.get("portid")),
                        "protocol": port.get("protocol"),
                        "name": service_el.get("name") if service_el is not None else "unknown",
                        "version": service_el.get("version") if service_el is not None else None,
                        "product": service_el.get("product") if service_el is not None else None,
                    }
                )
            if ip:
                results.append({"ip": ip, "hostname": hostname, "ports": ports})
        return results

    def normalize_result(self, parsed: list[dict[str, Any]]) -> dict[str, Any]:
        assets: list[NormalizedAsset] = []
        services: list[NormalizedService] = []
        findings: list[NormalizedFinding] = []
        for host in parsed:
            assets.append(
                NormalizedAsset(
                    name=host["hostname"] or host["ip"],
                    asset_type="SERVER",
                    ip_address=host["ip"],
                    dns_name=host["hostname"],
                    exposure="INTERNAL",
                    source="nmap",
                )
            )
            for p in host["ports"]:
                services.append(
                    NormalizedService(
                        asset_ip=host["ip"],
                        name=p["name"],
                        port=p["port"],
                        protocol=p["protocol"],
                        version=p["version"] or (p["product"] or None),
                        technology=p.get("product"),
                    )
                )
                # Exposed service on an internet-facing host is a candidate finding
                if p["name"] in SERVICE_TO_CWE:
                    findings.append(
                        NormalizedFinding(
                            title=f"Exposed service {p['name'].upper()} on {host['ip']}:{p['port']}",
                            severity="LOW",
                            cwe=SERVICE_TO_CWE[p["name"]],
                            category="Exposed Service",
                            endpoint=f"{p['protocol']}://{host['ip']}:{p['port']}",
                            asset_ip=host["ip"],
                            description=(
                                f"Service {p['name']} is reachable on port {p['port']}. "
                                "Verify it is required and properly hardened."
                            ),
                            remediation="Restrict exposure to authorized networks or disable unused services.",
                            confidence=0.7,
                        )
                    )
        return {"assets": assets, "services": services, "findings": findings, "events": []}
