import platform
import subprocess
from typing import List

from .logger_util import setup_logging
from .rules import Rule


logger = setup_logging("enforcer")


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def apply_windows_rules(rules: List[Rule]) -> None:
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.action == "deny":
            name = f"PFW-{rule.id[:8]}"
            proto = rule.protocol if rule.protocol != "any" else "any"
            direction = {
                "in": "in",
                "out": "out",
                "any": "in,out",
            }[rule.direction]
            cmd = [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={name}",
                "dir={}".format(direction.split(",")[0]),
                "action=block",
            ]
            if rule.src_ip:
                cmd.append(f"remoteip={rule.src_ip}")
            if rule.dst_port and proto in {"tcp", "udp"}:
                cmd.append(f"protocol={proto}")
                cmd.append(f"localport={rule.dst_port}")
            elif proto != "any":
                cmd.append(f"protocol={proto}")

            try:
                logger.info("Applying Windows rule: " + " ".join(cmd))
                subprocess.run(cmd, check=False, capture_output=True, text=True)
            except Exception as e:
                logger.error(f"Failed to apply Windows rule {name}: {e}")


def clear_windows_rules() -> None:
    try:
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", "name=all", "program=any"], check=False)
        logger.info("Requested deletion of existing firewall rules named 'all' (broad cleanup).")
    except Exception as e:
        logger.error(f"Failed to clear rules: {e}")


def apply_linux_rules(rules: List[Rule]) -> None:
    # This uses iptables for deny rules. Requires sudo.
    for rule in rules:
        if not rule.enabled or rule.action != "deny":
            continue
        base = ["sudo", "iptables", "-A"]
        if rule.direction == "in":
            base += ["INPUT"]
        elif rule.direction == "out":
            base += ["OUTPUT"]
        else:
            base += ["INPUT"]
        if rule.protocol != "any":
            base += ["-p", rule.protocol]
        if rule.src_ip:
            base += ["-s", rule.src_ip]
        if rule.dst_ip:
            base += ["-d", rule.dst_ip]
        if rule.dst_port and rule.protocol in {"tcp", "udp"}:
            base += ["--dport", str(rule.dst_port)]
        base += ["-j", "DROP"]
        try:
            logger.info("Applying Linux rule: " + " ".join(base))
            subprocess.run(base, check=False)
        except Exception as e:
            logger.error(f"Failed to apply Linux rule: {e}")


def clear_linux_rules() -> None:
    try:
        subprocess.run(["sudo", "iptables", "-F"], check=False)
        logger.info("Flushed iptables filter table.")
    except Exception as e:
        logger.error(f"Failed to flush iptables: {e}")


def enforce_rules(rules: List[Rule], platform_hint: str = "auto") -> None:
    target = platform_hint
    if platform_hint == "auto":
        target = "windows" if is_windows() else "linux"
    logger.info(f"Enforcing deny rules using {target}")
    if target == "windows":
        apply_windows_rules(rules)
    else:
        apply_linux_rules(rules)


def clear_enforcement(platform_hint: str = "auto") -> None:
    target = platform_hint
    if platform_hint == "auto":
        target = "windows" if is_windows() else "linux"
    logger.info(f"Clearing rules on {target}")
    if target == "windows":
        clear_windows_rules()
    else:
        clear_linux_rules()

