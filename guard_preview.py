"""Offline rule rendering and recovery decisions for a temporary macOS PF session."""

import argparse
import ipaddress
import json
import re
from pathlib import Path


DOCUMENTATION_NETWORKS = tuple(
    ipaddress.IPv4Network(value)
    for value in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
SNAPSHOT_FIELDS = ("main", "session_anchor", "nat", "system_anchors")


def render_rules(tunnel, physical, endpoints):
    """Return the session anchor text, with no access to live system state."""
    if not isinstance(tunnel, str) or not re.fullmatch(r"utun[0-9]+", tunnel):
        raise ValueError("Expected a tunnel interface such as utun4")
    if not isinstance(physical, str) or not re.fullmatch(r"en[0-9]+", physical):
        raise ValueError("Expected a physical interface such as en0")
    if not isinstance(endpoints, list) or not 1 <= len(endpoints) <= 3:
        raise ValueError("Expected one to three VPN peer IPv4 addresses")
    peers = []
    for value in endpoints:
        if not isinstance(value, str):
            raise ValueError("VPN peers must be IPv4 strings")
        peer = ipaddress.IPv4Address(value)
        if peer not in peers and any(peer in network for network in DOCUMENTATION_NETWORKS):
            peers.append(peer)
        else:
            raise ValueError("Use distinct RFC 5737 documentation addresses in this preview")
    rules = [f"pass quick on {interface} all no state" for interface in ("lo0", tunnel)]
    for peer in sorted(peers):
        rules.append(f"pass out quick on {physical} inet proto tcp from any to {peer} port 443 flags any no state")
        rules.append(f"pass in quick on {physical} inet proto tcp from {peer} port 443 to any flags any no state")
    return "\n".join([*rules, "block drop quick all"]) + "\n"


def snapshot(value):
    if not isinstance(value, dict) or set(value) != set(SNAPSHOT_FIELDS):
        raise ValueError("Each snapshot needs main, session_anchor, nat and system_anchors")
    if not all(isinstance(field, str) for field in value.values()):
        raise ValueError("Snapshot fields must be strings")
    return {
        key: tuple(line.strip() for line in value[key].splitlines() if line.strip())
        for key in SNAPSHOT_FIELDS
    }


def recovery_decision(tasks_exited, baseline, armed, current):
    """Describe the next recovery checks using synthetic rule snapshots."""
    before, protected, observed = map(snapshot, (baseline, armed, current))
    if tasks_exited is not True:
        return {"decision": "hold", "reason": "task_exit_unconfirmed"}
    if (before["session_anchor"] or not protected["session_anchor"]
            or not before["main"] or not protected["main"]
            or before["main"] == protected["main"]
            or any(before[key] != protected[key] for key in ("nat", "system_anchors"))):
        raise ValueError("The fixture must describe a distinct, session-owned rule change")
    if (observed["main"] not in (before["main"], protected["main"])
            or observed["session_anchor"] not in ((), protected["session_anchor"])
            or any(observed[key] != before[key] for key in ("nat", "system_anchors"))):
        return {"decision": "hold", "reason": "rules_changed_outside_session"}
    return {
        "decision": "check_ownership_before_recovery",
        "restore_main": observed["main"] == protected["main"],
        "clear_session_anchor": bool(observed["session_anchor"]),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("rules", "recovery-check"))
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        if args.operation == "rules":
            print(render_rules(**fixture), end="")
        else:
            print(json.dumps(recovery_decision(**fixture), indent=2))
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
