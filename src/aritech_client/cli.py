#!/usr/bin/env python3
"""
Aritech ATS CLI - Command-line interface for ATS alarm panels.

Usage:
    python -m aritech_client.cli --host 192.168.1.100 --pin 1234 zones
    aritech-cli --host 192.168.1.100 --pin 1234 areas
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from .client import AritechClient, AritechConfig
from .errors import AritechError
from .monitor import AritechMonitor, ChangeEvent, InitializedEvent
from .state import AreaState, OutputState, TriggerState, ZoneState


def setup_logging(debug: bool = False) -> None:
    """Configure logging based on debug flag or LOG_LEVEL env var."""
    level = logging.DEBUG if debug or os.environ.get("LOG_LEVEL") == "debug" else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def get_changed_flags(
    old_state: ZoneState | AreaState | OutputState | TriggerState | None,
    new_state: ZoneState | AreaState | OutputState | TriggerState | None,
) -> list[str]:
    """
    Compare two state objects and return a list of changed boolean flags.

    Returns strings like "is_active: False -> True"
    """
    if not old_state or not new_state:
        return []

    changed: list[str] = []
    for field in dataclasses.fields(new_state):
        if field.name.startswith("raw"):
            continue
        old_val = getattr(old_state, field.name, None)
        new_val = getattr(new_state, field.name, None)
        if isinstance(new_val, bool) and old_val != new_val:
            changed.append(f"{field.name}: {old_val} -> {new_val}")

    return changed


def load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load configuration from config.json if it exists."""
    paths_to_try = []
    if config_path:
        paths_to_try.append(config_path)
    paths_to_try.extend([
        Path.cwd() / "config.json",
        Path.home() / ".aritech" / "config.json",
    ])

    for path in paths_to_try:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def create_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="aritech-cli",
        description="CLI for Aritech ATS alarm panels",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  aritech-cli --host 192.168.1.100 --pin 1234 zones
  aritech-cli areas
  aritech-cli arm 1 full
  aritech-cli arm 1 part1 --force
  aritech-cli disarm 1
  aritech-cli inhibit 12
  aritech-cli outputs
  aritech-cli activate 1
  aritech-cli event-log 50
""",
    )

    # Connection options
    parser.add_argument("--host", help="Panel IP address")
    parser.add_argument("--port", type=int, help="Panel port number")
    parser.add_argument("--pin", help="User PIN code")
    parser.add_argument("--password", help="Encryption password (24 chars)")
    parser.add_argument("--config", type=Path, help="Path to config.json")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # info
    subparsers.add_parser("info", help="Show panel information")

    # monitor
    subparsers.add_parser("monitor", help="Start monitoring mode (COS events)")

    # zones
    subparsers.add_parser("zones", help="Show zone states")

    # areas
    subparsers.add_parser("areas", help="Show area states")

    # outputs
    subparsers.add_parser("outputs", help="Show output names and states")

    # triggers
    subparsers.add_parser("triggers", help="Show trigger names and states")

    # arm
    arm_parser = subparsers.add_parser("arm", help="Arm an area")
    arm_parser.add_argument("area", type=int, nargs="?", default=1, help="Area number (default: 1)")
    arm_parser.add_argument(
        "set_type",
        nargs="?",
        default="full",
        choices=["full", "part1", "part2"],
        help="Set type (default: full)",
    )
    arm_parser.add_argument("--force", action="store_true", help="Force arm despite faults")

    # disarm
    disarm_parser = subparsers.add_parser("disarm", help="Disarm an area")
    disarm_parser.add_argument("area", type=int, nargs="?", default=1, help="Area number (default: 1)")

    # inhibit
    inhibit_parser = subparsers.add_parser("inhibit", help="Inhibit a zone")
    inhibit_parser.add_argument("zone", type=int, help="Zone number")

    # uninhibit
    uninhibit_parser = subparsers.add_parser("uninhibit", help="Uninhibit a zone")
    uninhibit_parser.add_argument("zone", type=int, help="Zone number")

    # activate (output)
    activate_parser = subparsers.add_parser("activate", help="Activate an output")
    activate_parser.add_argument("output", type=int, help="Output number")

    # deactivate (output)
    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate an output")
    deactivate_parser.add_argument("output", type=int, help="Output number")

    # trigger-activate
    trig_act_parser = subparsers.add_parser("trigger-activate", help="Activate a trigger")
    trig_act_parser.add_argument("trigger", type=int, help="Trigger number")

    # trigger-deactivate
    trig_deact_parser = subparsers.add_parser("trigger-deactivate", help="Deactivate a trigger")
    trig_deact_parser.add_argument("trigger", type=int, help="Trigger number")

    # event-log
    eventlog_parser = subparsers.add_parser("event-log", help="Read event log")
    eventlog_parser.add_argument("count", type=int, nargs="?", default=50, help="Number of events (default: 50)")

    return parser


async def cmd_info(client: AritechClient) -> None:
    """Show panel information."""
    info = await client.get_description()
    print("\nPanel Information:")
    print(f"  Name:     {info.get('panelName', 'unknown')}")
    print(f"  Model:    {info.get('panelModel', 'unknown')}")
    print(f"  Serial:   {info.get('serial', 'unknown')}")
    print(f"  Firmware: {info.get('firmwareVersion', 'unknown')}")
    print(f"  Protocol: {info.get('protocolVersion', 'unknown')}")


async def cmd_zones(client: AritechClient, debug: bool = False) -> None:
    """Show zone states."""
    print("\nQuerying zone names...")
    zone_names = await client.get_zone_names()
    print(f"Found {len(zone_names)} zones\n")

    if not zone_names:
        print("No zones found on this panel.")
        return

    print("Querying zone states...")
    zone_states = await client.get_zone_states([z.number for z in zone_names])

    # Create lookup dict
    states_by_id = {s.number: s.state for s in zone_states}

    print("\nZones:")
    for zone in zone_names:
        state = states_by_id.get(zone.number)
        if not state:
            print(f"  \u26ab Zone {zone.number}: {zone.name}")
            print("     State: unknown")
            continue

        # Determine icon and description (like JS CLI)
        icon = "\u26ab"  # black circle
        state_desc = "Normal"

        if state.is_alarming:
            icon = "\U0001F534"  # red circle
            state_desc = "Alarm"
        elif state.is_isolated:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Isolated"
        elif state.is_inhibited:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Inhibited"
        elif state.is_tampered:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Tamper"
        elif state.has_fault:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Fault"
        elif state.is_active:
            icon = "\U0001F7E2"  # green circle
            state_desc = "Active"
        elif state.is_set:
            icon = "\u26ab"  # black circle
            state_desc = "Armed"

        print(f"  {icon} Zone {zone.number}: {zone.name}")
        print(f"     State: {state_desc}")

        # Show all true flags dynamically
        active_flags = [
            f.name for f in dataclasses.fields(state)
            if getattr(state, f.name) is True and not f.name.startswith("raw")
        ]
        print(f"     Flags: {', '.join(active_flags) or 'none'}")

        if debug:
            print(f"     Raw: {state.raw_flags}")


async def cmd_areas(client: AritechClient, debug: bool = False) -> None:
    """Show area states."""
    print("\nQuerying area names...")
    area_names = await client.get_area_names()
    print(f"Found {len(area_names)} areas\n")

    if not area_names:
        print("No areas found on this panel.")
        return

    print("Querying area states...")
    area_states = await client.get_area_states([a.number for a in area_names])

    # Create lookup dict
    states_by_id = {s.number: s.state for s in area_states}

    print("\nAreas:")
    for area in area_names:
        state = states_by_id.get(area.number)
        if not state:
            print(f"  \u26ab Area {area.number}: {area.name}")
            print("     State: unknown")
            continue

        # Determine icon and description (like JS CLI)
        icon = "\u26ab"  # black circle
        state_desc = "Unknown"

        if state.has_fire:
            icon = "\U0001F525"  # fire emoji
            state_desc = "Fire Alarm"
        elif state.has_panic:
            icon = "\U0001F6A8"  # police car light
            state_desc = "Panic Alarm"
        elif state.has_medical:
            icon = "\U0001F3E5"  # hospital
            state_desc = "Medical Alarm"
        elif state.is_alarming:
            icon = "\U0001F534"  # red circle
            state_desc = "Alarm"
        elif state.is_full_set:
            icon = "\U0001F7E2"  # green circle
            state_desc = "Armed (Full)"
        elif state.is_partially_set:
            icon = "\U0001F7E2"  # green circle
            state_desc = "Armed (Part 1)"
        elif state.is_partially_set_2:
            icon = "\U0001F7E2"  # green circle
            state_desc = "Armed (Part 2)"
        elif state.is_exiting:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Exiting"
        elif state.is_entering:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Entering"
        elif state.is_tampered:
            icon = "\U0001F7E1"  # yellow circle
            state_desc = "Tamper"
        elif state.has_technical:
            icon = "\U0001F527"  # wrench
            state_desc = "Technical Fault"
        elif state.is_unset and state.is_ready_to_arm:
            icon = "\u26ab"  # black circle
            state_desc = "Disarmed (Ready)"
        elif state.is_unset:
            icon = "\u26ab"  # black circle
            state_desc = "Disarmed"

        print(f"  {icon} Area {area.number}: {area.name}")
        print(f"     State: {state_desc}")

        # Show all true flags dynamically
        active_flags = [
            f.name for f in dataclasses.fields(state)
            if getattr(state, f.name) is True and not f.name.startswith("raw")
        ]
        print(f"     Flags: {', '.join(active_flags) or 'none'}")

        if debug:
            print(f"     Raw: {state.raw_flags}")


async def cmd_outputs(client: AritechClient, debug: bool = False) -> None:
    """Show output names and states."""
    print("\nQuerying output names...")
    outputs = await client.get_output_names()
    print(f"Found {len(outputs)} outputs\n")

    if not outputs:
        print("No outputs found on this panel.")
        return

    print("Querying output states...")
    states = await client.get_output_states([o.number for o in outputs])
    states_by_id = {s.number: s.state for s in states}

    print("\nOutputs:")
    for output in outputs:
        state = states_by_id.get(output.number)
        icon = "\U0001F7E2" if state and state.is_on else "\u26ab"  # green or black circle
        state_str = str(state) if state else "unknown"
        print(f"  {icon} Output {output.number}: {output.name}")
        print(f"     State: {state_str}")


async def cmd_triggers(client: AritechClient, debug: bool = False) -> None:
    """Show trigger names and states."""
    print("\nQuerying trigger names...")
    triggers = await client.get_trigger_names()
    print(f"Found {len(triggers)} triggers\n")

    if not triggers:
        print("No triggers found on this panel.")
        return

    print("Querying trigger states...")
    states = await client.get_trigger_states([t.number for t in triggers])
    states_by_id = {s.number: s.state for s in states}

    print("\nTriggers:")
    for trigger in triggers:
        state = states_by_id.get(trigger.number)
        icon = "\U0001F7E2" if state and state.is_active else "\u26ab"  # green or black circle
        state_str = str(state) if state else "unknown"
        print(f"  {icon} Trigger {trigger.number}: {trigger.name}")
        print(f"     State: {state_str}")


async def cmd_arm(client: AritechClient, area: int, set_type: str, force: bool) -> None:
    """Arm an area."""
    print(f"\nArming area {area} ({set_type}{', force' if force else ''})...")
    try:
        await client.arm_area(area, set_type, force=force)
        print(f"\u2713 Area {area} armed successfully")
    except AritechError as e:
        print(f"\u2717 Arm failed: {e}")
        if e.status is not None:
            print(f"  Status: 0x{e.status:04x}")
        if e.details.get("faults"):
            print(f"  Faults: {len(e.details['faults'])} zone(s)")
        if e.details.get("activeZones"):
            print(f"  Active zones: {len(e.details['activeZones'])} zone(s)")
        if not force:
            print("  Use --force to arm anyway")


async def cmd_disarm(client: AritechClient, area: int) -> None:
    """Disarm an area."""
    print(f"\nDisarming area {area}...")
    try:
        await client.disarm_area(area)
        print(f"\u2713 Area {area} disarmed successfully")
    except AritechError as e:
        print(f"\u2717 Disarm failed: {e}")
        if e.status is not None:
            print(f"  Status: 0x{e.status:04x}")


async def cmd_inhibit(client: AritechClient, zone: int) -> None:
    """Inhibit a zone."""
    print(f"\nInhibiting zone {zone}...")
    try:
        await client.inhibit_zone(zone)
        print(f"\u2713 Zone {zone} inhibited successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to inhibit zone {zone}: {e}")


async def cmd_uninhibit(client: AritechClient, zone: int) -> None:
    """Uninhibit a zone."""
    print(f"\nUninhibiting zone {zone}...")
    try:
        await client.uninhibit_zone(zone)
        print(f"\u2713 Zone {zone} uninhibited successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to uninhibit zone {zone}: {e}")


async def cmd_activate(client: AritechClient, output: int) -> None:
    """Activate an output."""
    print(f"\nActivating output {output}...")
    try:
        await client.activate_output(output)
        print(f"\u2713 Output {output} activated successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to activate output {output}: {e}")


async def cmd_deactivate(client: AritechClient, output: int) -> None:
    """Deactivate an output."""
    print(f"\nDeactivating output {output}...")
    try:
        await client.deactivate_output(output)
        print(f"\u2713 Output {output} deactivated successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to deactivate output {output}: {e}")


async def cmd_trigger_activate(client: AritechClient, trigger: int) -> None:
    """Activate a trigger."""
    print(f"\nActivating trigger {trigger}...")
    try:
        await client.activate_trigger(trigger)
        print(f"\u2713 Trigger {trigger} activated successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to activate trigger {trigger}: {e}")


async def cmd_trigger_deactivate(client: AritechClient, trigger: int) -> None:
    """Deactivate a trigger."""
    print(f"\nDeactivating trigger {trigger}...")
    try:
        await client.deactivate_trigger(trigger)
        print(f"\u2713 Trigger {trigger} deactivated successfully!")
    except AritechError as e:
        print(f"\u2717 Failed to deactivate trigger {trigger}: {e}")


async def cmd_monitor(client: AritechClient, debug: bool = False) -> None:
    """Start monitoring mode."""
    monitor = AritechMonitor(client)

    def on_initialized(event: InitializedEvent) -> None:
        print(f"\n\u2713 Monitor initialized")
        print(f"  Zones: {len(event.zones)} tracked")
        print(f"  Areas: {len(event.areas)} tracked")
        print(f"  Outputs: {len(event.outputs)} tracked")
        print(f"  Triggers: {len(event.triggers)} tracked\n")

    def on_zone_changed(event: ChangeEvent) -> None:
        if debug:
            print(f"\U0001F4CD Zone {event.id} ({event.name}) changed:")
            print(f"   State: {event.old_data} \u2192 {event.new_data}")
        else:
            old_state = event.old_data.get("state") if event.old_data else None
            new_state = event.new_data.get("state")
            old_desc = getattr(old_state, "__str__", lambda: "unknown")() if old_state else "unknown"
            new_desc = str(new_state) if new_state else "unknown"
            print(f"\U0001F4CD Zone {event.id} ({event.name}): {old_desc} \u2192 {new_desc}")

            # Show changed flags
            changed_flags = get_changed_flags(old_state, new_state)
            if changed_flags:
                print(f"   Changed flags: {', '.join(changed_flags)}")

    def on_area_changed(event: ChangeEvent) -> None:
        if debug:
            print(f"\U0001F3E0 Area {event.id} ({event.name}) changed:")
            print(f"   State: {event.old_data} \u2192 {event.new_data}")
        else:
            old_state = event.old_data.get("state") if event.old_data else None
            new_state = event.new_data.get("state")
            old_desc = str(old_state) if old_state else "unknown"
            new_desc = str(new_state) if new_state else "unknown"
            print(f"\U0001F3E0 Area {event.id} ({event.name}): {old_desc} \u2192 {new_desc}")

            # Show changed flags
            changed_flags = get_changed_flags(old_state, new_state)
            if changed_flags:
                print(f"   Changed flags: {', '.join(changed_flags)}")

    def on_output_changed(event: ChangeEvent) -> None:
        if debug:
            print(f"\U0001F4A1 Output {event.id} ({event.name}) changed:")
            print(f"   State: {event.old_data} \u2192 {event.new_data}")
        else:
            old_state = event.old_data.get("state") if event.old_data else None
            new_state = event.new_data.get("state")
            old_desc = str(old_state) if old_state else "unknown"
            new_desc = str(new_state) if new_state else "unknown"
            print(f"\U0001F4A1 Output {event.id} ({event.name}): {old_desc} \u2192 {new_desc}")

            # Show changed flags
            changed_flags = get_changed_flags(old_state, new_state)
            if changed_flags:
                print(f"   Changed flags: {', '.join(changed_flags)}")

    def on_trigger_changed(event: ChangeEvent) -> None:
        if debug:
            print(f"\u26A1 Trigger {event.id} ({event.name}) changed:")
            print(f"   State: {event.old_data} \u2192 {event.new_data}")
        else:
            old_state = event.old_data.get("state") if event.old_data else None
            new_state = event.new_data.get("state")
            old_desc = str(old_state) if old_state else "unknown"
            new_desc = str(new_state) if new_state else "unknown"
            print(f"\u26A1 Trigger {event.id} ({event.name}): {old_desc} \u2192 {new_desc}")

            # Show changed flags
            changed_flags = get_changed_flags(old_state, new_state)
            if changed_flags:
                print(f"   Changed flags: {', '.join(changed_flags)}")

    def on_error(err: Exception) -> None:
        print(f"\n\u274C Monitor error: {err}")

    # Register event handlers
    monitor.on_initialized(on_initialized)
    monitor.on_zone_changed(on_zone_changed)
    monitor.on_area_changed(on_area_changed)
    monitor.on_output_changed(on_output_changed)
    monitor.on_trigger_changed(on_trigger_changed)
    monitor.on_error(on_error)

    # Start monitoring
    await monitor.start()

    print("Monitoring for zone/area changes... (Ctrl+C to stop)\n")

    # Keep running until interrupted
    try:
        while monitor.running:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass
    finally:
        monitor.stop()
        print("\n\u2713 Monitor stopped")


async def cmd_event_log(client: AritechClient, count: int) -> None:
    """Read event log."""
    print(f"\nReading up to {count} events from panel log...\n")

    events_read = 0
    async for event in client.read_event_log(count):
        events_read += 1
        try:
            time_str = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            name = event.event_type.name
            entity = f"{event.entity.type.value} {event.entity.id}"
            if event.entity.description:
                entity += f": {event.entity.description}"
            area_str = f" (Area {event.area_id})" if event.area_id else ""

            print(f"[{time_str}] {name}")
            print(f"   {entity}{area_str}")
            print()
        except Exception as e:
            print(f"Error displaying event: {e}")
            print()

    print(f"\nDisplayed {events_read} events")


async def run_command(args: argparse.Namespace) -> int:
    """Run the specified command."""
    # Load config from file and merge with CLI args
    config_data = load_config(args.config)

    # CLI args override config file
    host = args.host or config_data.get("host")
    port = args.port or config_data.get("port", 32000)
    pin = args.pin or config_data.get("pin")
    password = args.password or config_data.get("encryptionPassword") or config_data.get("password")

    # Validate required fields
    missing = []
    if not host:
        missing.append("host")
    if not pin:
        missing.append("pin")
    if not password:
        missing.append("password")

    if missing:
        print(f"Error: Missing required configuration: {', '.join(missing)}")
        print("\nProvide via CLI args or config.json:")
        print("  --host <ip> --pin <pin> --password <24-char-password>")
        return 1

    # Create client config
    config = AritechConfig(
        host=host,
        port=port,
        pin=pin,
        encryption_password=password,
    )

    client = AritechClient(config)
    debug = args.debug

    try:
        await client.connect()

        # Commands that don't need full login
        if args.command == "info":
            await cmd_info(client)
            return 0

        # Initialize session for other commands
        await client.initialize()

        # Run command
        if args.command == "zones":
            await cmd_zones(client, debug)
        elif args.command == "areas":
            await cmd_areas(client, debug)
        elif args.command == "outputs":
            await cmd_outputs(client, debug)
        elif args.command == "triggers":
            await cmd_triggers(client, debug)
        elif args.command == "monitor":
            await cmd_monitor(client, debug)
        elif args.command == "arm":
            await cmd_arm(client, args.area, args.set_type, args.force)
        elif args.command == "disarm":
            await cmd_disarm(client, args.area)
        elif args.command == "inhibit":
            await cmd_inhibit(client, args.zone)
        elif args.command == "uninhibit":
            await cmd_uninhibit(client, args.zone)
        elif args.command == "activate":
            await cmd_activate(client, args.output)
        elif args.command == "deactivate":
            await cmd_deactivate(client, args.output)
        elif args.command == "trigger-activate":
            await cmd_trigger_activate(client, args.trigger)
        elif args.command == "trigger-deactivate":
            await cmd_trigger_deactivate(client, args.trigger)
        elif args.command == "event-log":
            await cmd_event_log(client, args.count)
        else:
            print(f"Unknown command: {args.command}")
            return 1

        return 0

    except AritechError as e:
        print(f"\nError: {e}")
        return 1
    except ConnectionRefusedError:
        print(f"\nError: Connection refused to {host}:{port}")
        return 1
    except asyncio.TimeoutError:
        print("\nError: Connection timed out")
        return 1
    except Exception as e:
        print(f"\nError: {e}")
        if debug:
            import traceback
            traceback.print_exc()
        return 1
    finally:
        # Gracefully disconnect (unless monitoring, which handles its own cleanup)
        if not client.monitoring_active:
            await client.disconnect()


def main() -> None:
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    # Setup logging before running commands
    setup_logging(getattr(args, "debug", False))

    exit_code = asyncio.run(run_command(args))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
