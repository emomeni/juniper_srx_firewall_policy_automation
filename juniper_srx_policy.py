#!/usr/bin/env python3
"""
Juniper SRX Firewall Security Policy Automation
---------------------------------------------------------------
✅ Uses Juniper PyEZ (junos-eznc)
✅ Supports multiple devices and multiple policies (YAML-driven)
✅ Safe commits, diff preview, verification included

Author: Ehsan Momeni Bashusqeh (Network Automation Engineer)
"""

import sys
from pathlib import Path
from typing import Iterable, List, Optional, Sequence, Set

import yaml
from jnpr.junos import Device
from jnpr.junos.exception import CommitError, ConfigLoadError, ConnectError
from jnpr.junos.utils.config import Config
from lxml import etree


def _cli_quote(value: str) -> str:
    """Return a double-quoted CLI-safe string."""

    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _load_yaml_list(
    path: str,
    *,
    required: bool,
    default: Optional[Sequence[dict]] = None,
    root_keys: Iterable[str] = (),
    item_label_plural: str,
    entry_label: str,
) -> List[dict]:
    """Load and normalize a YAML file that should contain a list of dictionaries."""

    try:
        with open(path) as handle:
            data = yaml.safe_load(handle)
    except FileNotFoundError:
        if required:
            print(f"✗ Required file '{path}' was not found.")
            sys.exit(1)
        return list(default or [])
    except yaml.YAMLError as err:
        print(f"✗ Failed to parse '{path}': {err}")
        sys.exit(1)

    if data is None:
        if required:
            print(f"✗ File '{path}' is empty; expected a list of {item_label_plural}.")
        sys.exit(1)
        return list(default or [])

    if isinstance(data, dict):
        for key in root_keys:
            if key in data:
                data = data[key]
                break

    if not isinstance(data, list):
        print(f"✗ File '{path}' must contain a list of {item_label_plural}.")
        sys.exit(1)

    normalized: List[dict] = []
    for idx, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            print(
                f"✗ Invalid entry #{idx} in '{path}': expected a mapping that describes {entry_label}.")
            sys.exit(1)
        normalized.append(item)

    return normalized


def _build_policy_filter(from_zone: str, to_zone: str, policy_name: str) -> etree._Element:
    """Build an XML filter targeting a single security policy."""

    configuration = etree.Element("configuration")
    security = etree.SubElement(configuration, "security")
    policies = etree.SubElement(security, "policies")
    from_zone_el = etree.SubElement(policies, "from-zone")
    etree.SubElement(from_zone_el, "name").text = str(from_zone)
    to_zone_el = etree.SubElement(from_zone_el, "to-zone")
    etree.SubElement(to_zone_el, "name").text = str(to_zone)
    policy_el = etree.SubElement(to_zone_el, "policy")
    etree.SubElement(policy_el, "name").text = str(policy_name)
    return configuration


def _collect_text(node: Optional[etree._Element], tag: str) -> Set[str]:
    if node is None:
        return {"any"}
    values = {child.text for child in node.findall(tag) if child.text}
    return values or {"any"}


def _extract_policy_details(policy_el: Optional[etree._Element]) -> Optional[dict]:
    """Convert the existing policy XML element into a comparable dictionary."""

    if policy_el is None:
        return None

    policy_info: dict = {}

    match_el = policy_el.find("match")
    policy_info["source_addresses"] = _collect_text(match_el, "source-address")
    policy_info["destination_addresses"] = _collect_text(match_el, "destination-address")
    policy_info["applications"] = _collect_text(match_el, "application")

    then_el = policy_el.find("then")
    action = None
    log_session_init = False
    log_session_close = False

    if then_el is not None:
        action_el = next(
            (child for child in then_el if isinstance(child.tag, str)),
            None,
        )
        if action_el is not None:
            action = action_el.tag.replace("_", "-")
            log_el = action_el.find("log")
            if log_el is not None:
                log_session_init = log_el.find("session-init") is not None
                log_session_close = log_el.find("session-close") is not None

    policy_info["action"] = action
    policy_info["log_session_init"] = log_session_init
    policy_info["log_session_close"] = log_session_close
    policy_info["description"] = policy_el.findtext("description")

    return policy_info


def _normalize_list(values: Optional[Sequence[str]]) -> List[str]:
    if not values:
        return ["any"]
    return [str(value) for value in values]


def _policy_matches(existing: Optional[dict], desired: dict) -> bool:
    if existing is None:
        return False

    desired_sources = set(_normalize_list(desired.get("source_addresses")))
    desired_destinations = set(_normalize_list(desired.get("destination_addresses")))
    desired_apps = set(_normalize_list(desired.get("applications")))
    desired_action = desired.get("action", "permit")
    desired_log_init = bool(desired.get("log_session_init"))
    desired_log_close = bool(desired.get("log_session_close"))
    desired_description = desired.get("description")

    return (
        existing.get("source_addresses") == desired_sources
        and existing.get("destination_addresses") == desired_destinations
        and existing.get("applications") == desired_apps
        and existing.get("action") == desired_action
        and existing.get("log_session_init") == desired_log_init
        and existing.get("log_session_close") == desired_log_close
        and ((desired_description or "") == (existing.get("description") or ""))
    )


def add_security_policy(host, username, password, policy):
    """Add a security policy to Juniper SRX via PyEZ"""

    required_fields = ("from_zone", "to_zone", "policy_name")
    for field in required_fields:
        if not policy.get(field):
            print(f"✗ Policy is missing required field '{field}'. Skipping.")
            return

    from_zone_raw = policy["from_zone"]
    to_zone_raw = policy["to_zone"]
    policy_name_raw = policy["policy_name"]

    from_zone = _cli_quote(from_zone_raw)
    to_zone = _cli_quote(to_zone_raw)
    policy_name = _cli_quote(policy_name_raw)

    # Build 'set' commands
    set_cmds = []

    for src in _normalize_list(policy.get("source_addresses")):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match source-address {_cli_quote(src)}"
        )

    for dst in _normalize_list(policy.get("destination_addresses")):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match destination-address {_cli_quote(dst)}"
        )

    for app in _normalize_list(policy.get("applications")):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} match application {_cli_quote(app)}"
        )

    action = str(policy.get("action", "permit")).lower()
    valid_actions = {"permit", "deny", "reject"}
    if action not in valid_actions:
        print(
            f"✗ Policy '{policy_name_raw}' specifies unsupported action '{action}'. Skipping."
        )
        return

    set_cmds.append(
        f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then {action}"
    )

    if policy.get("log_session_init"):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then log session-init"
        )
    if policy.get("log_session_close"):
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} then log session-close"
        )

    if "description" in policy and policy["description"] is not None:
        set_cmds.append(
            f"set security policies from-zone {from_zone} to-zone {to_zone} policy {policy_name} description {_cli_quote(policy['description'])}"
        )

    print(f"\n🔹 Device: {host}")
    print(f"🔹 Policy: {policy_name_raw}")
    print("-" * 70)

    try:
        with Device(host=host, user=username, passwd=password, port=22) as dev:
            with Config(dev, mode="exclusive") as cu:
                filter_xml = _build_policy_filter(from_zone_raw, to_zone_raw, policy_name_raw)
                existing_config = dev.rpc.get_config(filter_xml=filter_xml)
                existing_policy = (
                    existing_config.find(".//policy") if existing_config is not None else None
                )
                if _policy_matches(_extract_policy_details(existing_policy), policy):
                    print(f"⚠️ Policy '{policy_name_raw}' already matches the requested configuration. Skipping...")
                    return

                cu.load("\n".join(set_cmds), format="set")
                diff = cu.diff()

                if diff:
                    print("Configuration diff:")
                    print("=" * 70)
                    print(diff)
                    print("=" * 70)
                    cu.commit(comment=f"Added policy: {policy_name_raw}")
                    print(f"✅ Policy '{policy_name_raw}' committed successfully!\n")
                else:
                    print("No changes detected.")
    except ConnectError as err:
        print(f"✗ Connection Error: {err}")
    except ConfigLoadError as err:
        print(f"✗ Config Load Error: {err}")
    except CommitError as err:
        print(f"✗ Commit Error: {err}")
    except Exception as err:
        print(f"✗ Unexpected Error: {err}")


def verify_policy(host, username, password, from_zone, to_zone, policy_name):
    """Verify the policy on device"""
    try:
        with Device(host=host, user=username, passwd=password) as dev:
            result = dev.cli(
                f"show configuration security policies from-zone {_cli_quote(from_zone)} "
                f"to-zone {_cli_quote(to_zone)} policy {_cli_quote(policy_name)}"
            )
            print("\n" + "=" * 70)
            print(f"Verification: {policy_name} @ {host}")
            print("=" * 70)
            print(result)
            print("=" * 70)
    except Exception as err:
        print(f"✗ Verification failed: {err}")


# ================================================================
# MAIN EXECUTION
# ================================================================
if __name__ == "__main__":
    print("=" * 70)
    print(" JUNIPER SRX SECURITY POLICY AUTOMATION (PyEZ)")
    print("=" * 70)

    # ------------------------------------------------------------
    # Load device inventory
    # ------------------------------------------------------------
    devices_path = Path("devices.yaml")
    if devices_path.exists():
        devices = _load_yaml_list(
            str(devices_path),
            required=True,
            root_keys=("devices",),
            item_label_plural="devices",
            entry_label="a device",
        )
        if not devices:
            print("✗ No devices defined in 'devices.yaml'.")
            sys.exit(1)
    else:
        print("⚠️ No 'devices.yaml' found. Using default local device.")
        devices = [
            {"host": "192.168.1.1", "user": "admin", "password": "password"},
        ]

    # ------------------------------------------------------------
    # Load security policies
    # ------------------------------------------------------------
    policies_path = Path("policies.yaml")
    if not policies_path.exists():
        print("⚠️ No 'policies.yaml' found. Aborting.")
        sys.exit(1)

    policies = _load_yaml_list(
        str(policies_path),
        required=True,
        root_keys=("policies",),
        item_label_plural="policies",
        entry_label="a policy",
    )

    if not policies:
        print("✗ No policies defined in 'policies.yaml'.")
        sys.exit(1)

    # ------------------------------------------------------------
    # Execute for all devices and policies
    # ------------------------------------------------------------
    required_device_fields = ("host", "user", "password")
    required_policy_fields = ("from_zone", "to_zone", "policy_name")

    for dev in devices:
        missing_fields = [field for field in required_device_fields if not dev.get(field)]
        if missing_fields:
            print(
                f"✗ Device entry {dev} is missing required fields: {', '.join(missing_fields)}. Skipping."
            )
            continue

        print(f"\n=== Processing Device: {dev['host']} ===")
        for p in policies:
            missing_policy_fields = [field for field in required_policy_fields if not p.get(field)]
            if missing_policy_fields:
                print(
                    f"✗ Policy entry {p} is missing required fields: {', '.join(missing_policy_fields)}. Skipping."
                )
                continue

            add_security_policy(dev["host"], dev["user"], dev["password"], p)
            verify_policy(
                dev["host"],
                dev["user"],
                dev["password"],
                p["from_zone"],
                p["to_zone"],
                p["policy_name"],
            )

    print("\n✅ All tasks completed successfully!\n")
