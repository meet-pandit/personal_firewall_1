import ipaddress
import json
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import DEFAULT_RULES_PATH, ensure_directories


@dataclass
class Rule:
    id: str
    action: str  # "allow" or "deny"
    direction: str  # "in", "out", or "any"
    protocol: str  # "tcp", "udp", "icmp", or "any"
    src_ip: Optional[str] = None  # single IP or CIDR
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    description: str = ""
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Rule":
        return Rule(**data)


def load_rules(path: Path = DEFAULT_RULES_PATH) -> List[Rule]:
    ensure_directories()
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [Rule.from_dict(item) for item in raw]


def save_rules(rules: List[Rule], path: Path = DEFAULT_RULES_PATH) -> None:
    ensure_directories()
    with path.open("w", encoding="utf-8") as f:
        json.dump([r.to_dict() for r in rules], f, indent=2)


def create_rule(
    action: str,
    direction: str = "any",
    protocol: str = "any",
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    description: str = "",
    enabled: bool = True,
) -> Rule:
    if action not in {"allow", "deny"}:
        raise ValueError("action must be 'allow' or 'deny'")
    if direction not in {"in", "out", "any"}:
        raise ValueError("direction must be 'in', 'out', or 'any'")
    if protocol not in {"tcp", "udp", "icmp", "any"}:
        raise ValueError("protocol must be 'tcp', 'udp', 'icmp', or 'any'")
    for ip_text in [src_ip, dst_ip]:
        if ip_text:
            ipaddress.ip_network(ip_text, strict=False)
    return Rule(
        id=str(uuid.uuid4()),
        action=action,
        direction=direction,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        description=description,
        enabled=enabled,
    )


def ip_matches(candidate: Optional[str], rule_cidr: Optional[str]) -> bool:
    if not rule_cidr:
        return True
    if not candidate:
        return False
    try:
        network = ipaddress.ip_network(rule_cidr, strict=False)
        ip_obj = ipaddress.ip_address(candidate)
        return ip_obj in network
    except Exception:
        return False


def port_matches(candidate: Optional[int], rule_port: Optional[int]) -> bool:
    if rule_port is None:
        return True
    return candidate == rule_port


def protocol_matches(candidate: Optional[str], rule_protocol: str) -> bool:
    if rule_protocol == "any" or not rule_protocol:
        return True
    if not candidate:
        return False
    return candidate.lower() == rule_protocol.lower()


def evaluate_rules(
    rules: List[Rule],
    *,
    direction: str,
    protocol: Optional[str],
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
) -> Optional[Rule]:
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.direction not in {"any", direction}:
            continue
        if not protocol_matches(protocol, rule.protocol):
            continue
        if not ip_matches(src_ip, rule.src_ip):
            continue
        if not ip_matches(dst_ip, rule.dst_ip):
            continue
        if not port_matches(src_port, rule.src_port):
            continue
        if not port_matches(dst_port, rule.dst_port):
            continue
        return rule
    return None

