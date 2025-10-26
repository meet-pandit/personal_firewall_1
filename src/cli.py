import argparse
import json
import time
from typing import Optional

from .config import ensure_directories, DEFAULT_RULES_PATH
from .enforcer import enforce_rules, clear_enforcement
from .logger_util import setup_logging
from .rules import load_rules, save_rules, create_rule
from .sniffer import FirewallSniffer


logger = setup_logging("cli")


def cmd_init_rules(_: argparse.Namespace) -> None:
    ensure_directories()
    if DEFAULT_RULES_PATH.exists():
        logger.info(f"Rules file already exists at {DEFAULT_RULES_PATH}")
        return
    save_rules([], DEFAULT_RULES_PATH)
    logger.info(f"Initialized rules file at {DEFAULT_RULES_PATH}")


def cmd_list_rules(_: argparse.Namespace) -> None:
    rules = load_rules()
    print(json.dumps([r.to_dict() for r in rules], indent=2))


def cmd_add_rule(ns: argparse.Namespace) -> None:
    rule = create_rule(
        action=ns.action,
        direction=ns.direction,
        protocol=ns.protocol,
        src_ip=ns.src_ip,
        dst_ip=ns.dst_ip,
        src_port=ns.src_port,
        dst_port=ns.dst_port,
        description=ns.description or "",
    )
    rules = load_rules()
    rules.append(rule)
    save_rules(rules)
    logger.info(f"Added rule {rule.id}")


def cmd_remove_rule(ns: argparse.Namespace) -> None:
    rules = load_rules()
    new_rules = [r for r in rules if r.id != ns.id]
    save_rules(new_rules)
    logger.info(f"Removed rule {ns.id} (if it existed)")


def cmd_start(ns: argparse.Namespace) -> None:
    rules = load_rules()
    sniffer = FirewallSniffer(rules, iface=ns.iface, log_matches_only=ns.log_matches_only)
    sniffer.start()
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        sniffer.stop()


def cmd_enforce(ns: argparse.Namespace) -> None:
    rules = load_rules()
    enforce_rules(rules, platform_hint=ns.platform)


def cmd_clear_enforce(ns: argparse.Namespace) -> None:
    clear_enforcement(platform_hint=ns.platform)


def cmd_gui(_: argparse.Namespace) -> None:
    from .gui import run_gui

    run_gui()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="personal-firewall", description="Python Personal Firewall")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-rules", help="Create an empty rules.json if missing")
    s.set_defaults(func=cmd_init_rules)

    s = sub.add_parser("list-rules", help="Print all rules")
    s.set_defaults(func=cmd_list_rules)

    s = sub.add_parser("add-rule", help="Add a rule")
    s.add_argument("--action", choices=["allow", "deny"], required=True)
    s.add_argument("--direction", choices=["in", "out", "any"], default="any")
    s.add_argument("--protocol", choices=["tcp", "udp", "icmp", "any"], default="any")
    s.add_argument("--src-ip")
    s.add_argument("--dst-ip")
    s.add_argument("--src-port", type=int)
    s.add_argument("--dst-port", type=int)
    s.add_argument("--description")
    s.set_defaults(func=cmd_add_rule)

    s = sub.add_parser("remove-rule", help="Remove a rule by id")
    s.add_argument("--id", required=True)
    s.set_defaults(func=cmd_remove_rule)

    s = sub.add_parser("start", help="Start the sniffer")
    s.add_argument("--iface", default="auto")
    s.add_argument("--log-level", default="INFO")
    s.add_argument("--log-matches-only", action="store_true")
    s.set_defaults(func=cmd_start)

    s = sub.add_parser("enforce", help="Apply deny rules using OS firewall")
    s.add_argument("--platform", choices=["windows", "linux", "auto"], default="auto")
    s.set_defaults(func=cmd_enforce)

    s = sub.add_parser("clear-enforce", help="Clear rules using OS firewall")
    s.add_argument("--platform", choices=["windows", "linux", "auto"], default="auto")
    s.set_defaults(func=cmd_clear_enforce)

    s = sub.add_parser("gui", help="Open the monitoring GUI")
    s.set_defaults(func=cmd_gui)

    return p


def main(argv: Optional[list] = None) -> None:
    parser = build_parser()
    ns = parser.parse_args(argv)
    logger.setLevel(ns.__dict__.get("log_level", "INFO"))
    ns.func(ns)


if __name__ == "__main__":
    main()


