import socket
from dataclasses import dataclass
from typing import Optional, List

import psutil
from scapy.all import AsyncSniffer, Packet, IP, TCP, UDP, ICMP

from .logger_util import setup_logging
from .rules import Rule, evaluate_rules


logger = setup_logging("sniffer")


@dataclass
class SniffResult:
    packet_summary: str
    action: str
    matched_rule_id: Optional[str]


def resolve_direction(pkt: Packet) -> str:
    # Basic heuristic: if dst is one of local addresses => incoming, else outgoing
    try:
        if IP in pkt:
            local_ips = {addr.address for iface, addrs in psutil.net_if_addrs().items() for addr in addrs if addr.family == socket.AF_INET}
            dst_ip = pkt[IP].dst
            return "in" if dst_ip in local_ips else "out"
    except Exception:
        pass
    return "any"


def extract_metadata(pkt: Packet):
    proto = None
    src_ip = dst_ip = None
    src_port = dst_port = None

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

    if TCP in pkt:
        proto = "tcp"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
    elif UDP in pkt:
        proto = "udp"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
    elif ICMP in pkt:
        proto = "icmp"

    return proto, src_ip, dst_ip, src_port, dst_port


class FirewallSniffer:
    def __init__(self, rules: List[Rule], iface: Optional[str] = None, log_matches_only: bool = False):
        self.rules = rules
        self.iface = iface
        self.log_matches_only = log_matches_only
        self._sniffer: Optional[AsyncSniffer] = None

    def _handle_packet(self, pkt: Packet):
        protocol, src_ip, dst_ip, src_port, dst_port = extract_metadata(pkt)
        direction = resolve_direction(pkt)
        rule = evaluate_rules(
            self.rules,
            direction=direction,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
        )
        action = rule.action if rule else "allow"
        summary = pkt.summary()
        if rule or not self.log_matches_only:
            logger.info(f"{action.upper()} {summary} rule={rule.id if rule else 'none'}")

    def start(self) -> None:
        iface = self.iface
        if iface == "auto" or iface is None:
            iface = None  # scapy will choose
        logger.info(f"Starting sniffer on iface={iface or 'auto'}")
        self._sniffer = AsyncSniffer(prn=self._handle_packet, store=False, iface=iface)
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer:
            logger.info("Stopping sniffer")
            self._sniffer.stop()
            self._sniffer = None