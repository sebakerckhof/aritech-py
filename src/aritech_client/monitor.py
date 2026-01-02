"""
Aritech ATS Panel Monitor

Monitors the panel for changes and emits events when zones, areas, outputs,
or triggers change. Uses COS (Change of Status) events from the panel to
detect changes efficiently.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Coroutine

from .message_helpers import HEADER_RESPONSE, construct_message

if TYPE_CHECKING:
    from .client import AritechClient, NamedItem, StateResult

logger = logging.getLogger(__name__)

# COS change type constants (from COS payload byte 2)
COS_CHANGE_TYPES = {
    "ZONE": 0x01,
    "AREA": 0x02,
    "OUTPUT": 0x07,
    "DOOR": 0x0B,
    "TRIGGER": 0x14,
    "ALL": 0xFF,
}


@dataclass
class ChangeEvent:
    """Event data for a state change."""

    id: int
    name: str
    old_data: dict[str, Any] | None
    new_data: dict[str, Any]


@dataclass
class InitializedEvent:
    """Event data for monitor initialization."""

    zones: list[NamedItem]
    areas: list[NamedItem]
    outputs: list[NamedItem]
    triggers: list[NamedItem]
    doors: list[NamedItem]
    zone_states: dict[int, dict[str, Any]]
    area_states: dict[int, dict[str, Any]]
    output_states: dict[int, dict[str, Any]]
    trigger_states: dict[int, dict[str, Any]]
    door_states: dict[int, dict[str, Any]]


class AritechMonitor:
    """
    Monitor class that wraps an AritechClient and emits change events.

    Events are delivered via callbacks registered with:
    - on_zone_changed(callback)
    - on_area_changed(callback)
    - on_output_changed(callback)
    - on_trigger_changed(callback)
    - on_initialized(callback)
    - on_error(callback)

    Example:
        ```python
        monitor = AritechMonitor(client)
        monitor.on_zone_changed(lambda e: print(f"Zone {e.id} changed"))
        await monitor.start()
        ```
    """

    def __init__(self, client: AritechClient) -> None:
        """Initialize the monitor with an AritechClient."""
        self.client = client

        # State tracking
        self.zones: list[NamedItem] = []
        self.areas: list[NamedItem] = []
        self.outputs: list[NamedItem] = []
        self.triggers: list[NamedItem] = []
        self.doors: list[NamedItem] = []
        self.zone_states: dict[int, dict[str, Any]] = {}
        self.area_states: dict[int, dict[str, Any]] = {}
        self.output_states: dict[int, dict[str, Any]] = {}
        self.trigger_states: dict[int, dict[str, Any]] = {}
        self.door_states: dict[int, dict[str, Any]] = {}

        # Internal state
        self._running = False

        # Event callbacks
        self._on_zone_changed: list[Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_area_changed: list[Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_output_changed: list[Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_trigger_changed: list[Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_door_changed: list[Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_initialized: list[Callable[[InitializedEvent], Coroutine[Any, Any, None] | None]] = []
        self._on_error: list[Callable[[Exception], Coroutine[Any, Any, None] | None]] = []

    @property
    def running(self) -> bool:
        """Check if the monitor is running."""
        return self._running

    def on_zone_changed(
        self, callback: Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for zone change events."""
        self._on_zone_changed.append(callback)

    def on_area_changed(
        self, callback: Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for area change events."""
        self._on_area_changed.append(callback)

    def on_output_changed(
        self, callback: Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for output change events."""
        self._on_output_changed.append(callback)

    def on_trigger_changed(
        self, callback: Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for trigger change events."""
        self._on_trigger_changed.append(callback)

    def on_door_changed(
        self, callback: Callable[[ChangeEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for door change events."""
        self._on_door_changed.append(callback)

    def on_initialized(
        self, callback: Callable[[InitializedEvent], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for monitor initialized event."""
        self._on_initialized.append(callback)

    def on_error(
        self, callback: Callable[[Exception], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for error events."""
        self._on_error.append(callback)

    async def _emit(self, callbacks: list[Callable], event: Any) -> None:
        """Emit an event to all registered callbacks."""
        for callback in callbacks:
            try:
                result = callback(event)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Error in event callback: {e}")

    async def start(self) -> None:
        """Start monitoring. Initializes state and begins listening for COS events."""
        if self._running:
            raise RuntimeError("Monitor is already running")

        logger.debug("Starting monitor...")

        try:
            await self._initialize()
            self._setup_cos_handler()
            self._running = True

            # Start background reader and enable monitoring
            # Note: start_background_reader sets _reader_should_run before creating the task,
            # so the reader loop will run properly regardless of monitoring_active timing
            self.client.monitoring_active = True
            self.client.start_background_reader()

            logger.debug("Monitor started successfully")
        except Exception as err:
            await self._emit(self._on_error, err)
            raise

    def stop(self) -> None:
        """Stop monitoring and clean up."""
        logger.debug("Stopping monitor...")
        self._running = False
        self.client.monitoring_active = False
        self.client.stop_background_reader()
        logger.debug("Monitor stopped")

    def get_zone_states(self) -> dict[int, dict[str, Any]]:
        """Get current state of all zones."""
        return dict(self.zone_states)

    def get_area_states(self) -> dict[int, dict[str, Any]]:
        """Get current state of all areas."""
        return dict(self.area_states)

    def get_output_states(self) -> dict[int, dict[str, Any]]:
        """Get current state of all outputs."""
        return dict(self.output_states)

    def get_trigger_states(self) -> dict[int, dict[str, Any]]:
        """Get current state of all triggers."""
        return dict(self.trigger_states)

    def get_door_states(self) -> dict[int, dict[str, Any]]:
        """Get current state of all doors."""
        return dict(self.door_states)

    async def _initialize(self) -> None:
        """Initialize by fetching all zone/area names and their current states."""
        logger.debug("Initializing monitor state...")

        # Enable event notifications (like mobile app does after login)
        # Uses getUserInfo (msgId 228) which triggers COS notification setup
        logger.debug("Enabling event notifications...")
        payload = construct_message("getUserInfo", {})
        await self.client.call_encrypted(payload, self.client.session_key)

        # Fetch zone names
        logger.debug("Fetching zone names...")
        self.zones = await self.client.get_zone_names()
        logger.debug(f"Found {len(self.zones)} zones")

        # Fetch area names
        logger.debug("Fetching area names...")
        self.areas = await self.client.get_area_names()
        logger.debug(f"Found {len(self.areas)} areas")

        # Fetch initial zone states
        logger.debug("Fetching initial zone states...")
        zone_states = await self.client.get_zone_states([z.number for z in self.zones])
        for state_result in zone_states:
            self.zone_states[state_result.number] = {
                "state": state_result.state,
                "raw_hex": state_result.raw_hex,
            }
        logger.debug(f"Captured state for {len(self.zone_states)} zones")

        # Fetch initial area states
        logger.debug("Fetching initial area states...")
        area_states = await self.client.get_area_states([a.number for a in self.areas])
        for state_result in area_states:
            self.area_states[state_result.number] = {
                "state": state_result.state,
                "raw_hex": state_result.raw_hex,
            }
        logger.debug(f"Captured state for {len(self.area_states)} areas")

        # Fetch output names
        logger.debug("Fetching output names...")
        self.outputs = await self.client.get_output_names()
        logger.debug(f"Found {len(self.outputs)} outputs")

        # Fetch initial output states
        logger.debug("Fetching initial output states...")
        output_states = await self.client.get_output_states([o.number for o in self.outputs])
        for state_result in output_states:
            self.output_states[state_result.number] = {
                "state": state_result.state,
                "raw_hex": state_result.raw_hex,
            }
        logger.debug(f"Captured state for {len(self.output_states)} outputs")

        # Fetch trigger names
        logger.debug("Fetching trigger names...")
        self.triggers = await self.client.get_trigger_names()
        logger.debug(f"Found {len(self.triggers)} triggers")

        # Fetch initial trigger states
        logger.debug("Fetching initial trigger states...")
        trigger_states = await self.client.get_trigger_states([t.number for t in self.triggers])
        for state_result in trigger_states:
            self.trigger_states[state_result.number] = {
                "state": state_result.state,
                "raw_hex": state_result.raw_hex,
            }
        logger.debug(f"Captured state for {len(self.trigger_states)} triggers")

        # Fetch door names
        logger.debug("Fetching door names...")
        self.doors = await self.client.get_door_names()
        logger.debug(f"Found {len(self.doors)} doors")

        # Fetch initial door states
        logger.debug("Fetching initial door states...")
        door_states = await self.client.get_door_states([d.number for d in self.doors])
        for state_result in door_states:
            self.door_states[state_result.number] = {
                "state": state_result.state,
                "raw_hex": state_result.raw_hex,
            }
        logger.debug(f"Captured state for {len(self.door_states)} doors")

        # Emit initialized event
        event = InitializedEvent(
            zones=self.zones,
            areas=self.areas,
            outputs=self.outputs,
            triggers=self.triggers,
            doors=self.doors,
            zone_states=self.get_zone_states(),
            area_states=self.get_area_states(),
            output_states=self.get_output_states(),
            trigger_states=self.get_trigger_states(),
            door_states=self.get_door_states(),
        )
        await self._emit(self._on_initialized, event)

        logger.debug("Initialization complete")

    def _setup_cos_handler(self) -> None:
        """Set up the COS event handler on the client."""
        self.client.on_cos_event(self._handle_cos_event)

    async def _handle_cos_event(self, status_byte: int | None, payload: bytes) -> None:
        """Handle a COS event by determining what changed and fetching updated state."""
        if not self._running:
            return

        try:
            status_str = f"0x{status_byte:02x}" if status_byte is not None else "??"
            logger.debug(f"Processing COS event, status: {status_str}")
            logger.debug(f"Payload: {payload.hex()}")

            # Parse COS payload to determine what changed
            # Format: 30 00 TT 00 00 00 00 00
            #   TT: 01 = zone, 02 = area, 07 = output, 14 = trigger, ff = all
            change_type = "all"

            if payload and len(payload) >= 3 and payload[0] == 0x30:
                type_byte = payload[2]
                if type_byte == COS_CHANGE_TYPES["ZONE"]:
                    change_type = "zone"
                elif type_byte == COS_CHANGE_TYPES["AREA"]:
                    change_type = "area"
                elif type_byte == COS_CHANGE_TYPES["OUTPUT"]:
                    change_type = "output"
                elif type_byte == COS_CHANGE_TYPES["TRIGGER"]:
                    change_type = "trigger"
                elif type_byte == COS_CHANGE_TYPES["DOOR"]:
                    change_type = "door"
                logger.debug(f"Change type: {change_type}")

            # Note: COS ACK is sent by the client layer in _handle_unsolicited_frame/_handle_cos_inline

            # Small delay before querying
            await asyncio.sleep(0.05)

            # Request change bitmaps and update states
            changed_zones: list[int] = []
            changed_areas: list[int] = []
            changed_outputs: list[int] = []
            changed_triggers: list[int] = []
            changed_doors: list[int] = []

            if change_type in ("zone", "all"):
                changed_zones = await self._get_changes("zone")

            if change_type in ("area", "all"):
                changed_areas = await self._get_changes("area")

            if change_type in ("output", "all"):
                changed_outputs = await self._get_changes("output")

            if change_type in ("trigger", "all"):
                changed_triggers = await self._get_changes("trigger")

            if change_type in ("door", "all"):
                changed_doors = await self._get_changes("door")

            # Update based on what actually changed
            if changed_zones:
                await self._update_zone_states(changed_zones)
            elif change_type in ("zone", "all"):
                # Fallback: fetch all zones if no specific bitmap
                logger.debug("No specific zones in bitmap, fetching all")
                await self._update_zone_states([z.number for z in self.zones])

            if changed_areas:
                await self._update_area_states(changed_areas)
            elif change_type in ("area", "all"):
                logger.debug("No specific areas in bitmap, fetching all")
                await self._update_area_states([a.number for a in self.areas])

            if changed_outputs:
                await self._update_output_states(changed_outputs)
            elif change_type in ("output", "all"):
                logger.debug("No specific outputs in bitmap, fetching all")
                await self._update_output_states([o.number for o in self.outputs])

            if changed_triggers:
                await self._update_trigger_states(changed_triggers)
            elif change_type in ("trigger", "all"):
                logger.debug("No specific triggers in bitmap, fetching all")
                await self._update_trigger_states([t.number for t in self.triggers])

            if changed_doors:
                await self._update_door_states(changed_doors)
            elif change_type in ("door", "all"):
                logger.debug("No specific doors in bitmap, fetching all")
                await self._update_door_states([d.number for d in self.doors])

        except Exception as err:
            logger.error(f"Error handling COS event: {err}")
            await self._emit(self._on_error, err)

    async def _get_changes(self, change_type: str) -> list[int]:
        """Request change bitmap and return list of changed item IDs."""
        msg_names = {
            "zone": "getZoneChanges",
            "area": "getAreaChanges",
            "output": "getOutputChanges",
            "trigger": "getTriggerChanges",
            "door": "getDoorChanges",
        }
        type_codes = {
            "zone": COS_CHANGE_TYPES["ZONE"],
            "area": COS_CHANGE_TYPES["AREA"],
            "output": COS_CHANGE_TYPES["OUTPUT"],
            "trigger": COS_CHANGE_TYPES["TRIGGER"],
            "door": COS_CHANGE_TYPES["DOOR"],
        }
        valid_numbers_map = {
            "zone": [z.number for z in self.zones],
            "area": [a.number for a in self.areas],
            "output": [o.number for o in self.outputs],
            "trigger": [t.number for t in self.triggers],
            "door": [d.number for d in self.doors],
        }

        msg_name = msg_names.get(change_type)
        if not msg_name:
            return []

        payload = construct_message(msg_name, {})
        response = await self.client.call_encrypted(payload, self.client.session_key)

        if not response or len(response) < 3:
            return []

        if response[0] == HEADER_RESPONSE and response[1] == 0x30:
            bitmap_type = response[2]
            bitmap = response[3:]
            logger.debug(f"{change_type} bitmap type: 0x{bitmap_type:02x}, data: {bitmap.hex()}")

            if bitmap_type == type_codes.get(change_type):
                valid_numbers = valid_numbers_map.get(change_type, [])
                changed = self._parse_bitmap(bitmap, valid_numbers)
                logger.debug(f"Changed {change_type}s: {changed or 'none'}")
                return changed

        return []

    def _parse_bitmap(self, bitmap: bytes, valid_numbers: list[int]) -> list[int]:
        """Parse a bitmap to extract which items changed."""
        changed: list[int] = []
        valid_set = set(valid_numbers)

        for byte_idx, byte_val in enumerate(bitmap):
            if byte_val == 0:
                continue  # Skip empty bytes for efficiency

            for bit in range(8):
                if byte_val & (1 << bit):
                    item_num = byte_idx * 8 + bit + 1
                    if item_num in valid_set:
                        changed.append(item_num)

        return changed

    async def _update_zone_states(self, zone_numbers: list[int]) -> None:
        """Update zone states and emit events for changes."""
        if not zone_numbers:
            return

        new_states = await self.client.get_zone_states(zone_numbers)

        for new_state in new_states:
            zone_num = new_state.number
            old_state = self.zone_states.get(zone_num)

            # Check if changed by comparing raw bytes
            has_changed = not old_state or old_state.get("raw_hex") != new_state.raw_hex

            if has_changed:
                # Find zone name
                zone = next((z for z in self.zones if z.number == zone_num), None)
                zone_name = zone.name if zone else f"Zone {zone_num}"

                # Emit event
                event = ChangeEvent(
                    id=zone_num,
                    name=zone_name,
                    old_data=dict(old_state) if old_state else None,
                    new_data={"state": new_state.state, "raw_hex": new_state.raw_hex},
                )
                await self._emit(self._on_zone_changed, event)

                logger.debug(
                    f"Zone {zone_num} ({zone_name}): "
                    f"{old_state.get('raw_hex') if old_state else 'NEW'} -> {new_state.raw_hex}"
                )

            # Update stored state
            self.zone_states[zone_num] = {
                "state": new_state.state,
                "raw_hex": new_state.raw_hex,
            }

    async def _update_area_states(self, area_numbers: list[int]) -> None:
        """Update area states and emit events for changes."""
        if not area_numbers:
            return

        new_states = await self.client.get_area_states(area_numbers)

        for new_state in new_states:
            area_num = new_state.number
            old_state = self.area_states.get(area_num)

            # Check if changed by comparing raw bytes
            has_changed = not old_state or old_state.get("raw_hex") != new_state.raw_hex

            if has_changed:
                # Find area name
                area = next((a for a in self.areas if a.number == area_num), None)
                area_name = area.name if area else f"Area {area_num}"

                # Emit event
                event = ChangeEvent(
                    id=area_num,
                    name=area_name,
                    old_data=dict(old_state) if old_state else None,
                    new_data={"state": new_state.state, "raw_hex": new_state.raw_hex},
                )
                await self._emit(self._on_area_changed, event)

                logger.debug(
                    f"Area {area_num} ({area_name}): "
                    f"{old_state.get('raw_hex') if old_state else 'NEW'} -> {new_state.raw_hex}"
                )

            # Update stored state
            self.area_states[area_num] = {
                "state": new_state.state,
                "raw_hex": new_state.raw_hex,
            }

    async def _update_output_states(self, output_numbers: list[int]) -> None:
        """Update output states and emit events for changes."""
        if not output_numbers:
            return

        new_states = await self.client.get_output_states(output_numbers)

        for new_state in new_states:
            output_num = new_state.number
            old_state = self.output_states.get(output_num)

            # Check if changed by comparing raw bytes
            has_changed = not old_state or old_state.get("raw_hex") != new_state.raw_hex

            if has_changed:
                # Find output name
                output = next((o for o in self.outputs if o.number == output_num), None)
                output_name = output.name if output else f"Output {output_num}"

                # Emit event
                event = ChangeEvent(
                    id=output_num,
                    name=output_name,
                    old_data=dict(old_state) if old_state else None,
                    new_data={"state": new_state.state, "raw_hex": new_state.raw_hex},
                )
                await self._emit(self._on_output_changed, event)

                logger.debug(
                    f"Output {output_num} ({output_name}): "
                    f"{old_state.get('raw_hex') if old_state else 'NEW'} -> {new_state.raw_hex}"
                )

            # Update stored state
            self.output_states[output_num] = {
                "state": new_state.state,
                "raw_hex": new_state.raw_hex,
            }

    async def _update_trigger_states(self, trigger_numbers: list[int]) -> None:
        """Update trigger states and emit events for changes."""
        if not trigger_numbers:
            return

        new_states = await self.client.get_trigger_states(trigger_numbers)

        for new_state in new_states:
            trigger_num = new_state.number
            old_state = self.trigger_states.get(trigger_num)

            # Check if changed by comparing raw bytes
            has_changed = not old_state or old_state.get("raw_hex") != new_state.raw_hex

            if has_changed:
                # Find trigger name
                trigger = next((t for t in self.triggers if t.number == trigger_num), None)
                trigger_name = trigger.name if trigger else f"Trigger {trigger_num}"

                # Emit event
                event = ChangeEvent(
                    id=trigger_num,
                    name=trigger_name,
                    old_data=dict(old_state) if old_state else None,
                    new_data={"state": new_state.state, "raw_hex": new_state.raw_hex},
                )
                await self._emit(self._on_trigger_changed, event)

                logger.debug(
                    f"Trigger {trigger_num} ({trigger_name}): "
                    f"{old_state.get('raw_hex') if old_state else 'NEW'} -> {new_state.raw_hex}"
                )

            # Update stored state
            self.trigger_states[trigger_num] = {
                "state": new_state.state,
                "raw_hex": new_state.raw_hex,
            }

    async def _update_door_states(self, door_numbers: list[int]) -> None:
        """Update door states and emit events for changes."""
        if not door_numbers:
            return

        new_states = await self.client.get_door_states(door_numbers)

        for new_state in new_states:
            door_num = new_state.number
            old_state = self.door_states.get(door_num)

            # Check if changed by comparing raw bytes
            has_changed = not old_state or old_state.get("raw_hex") != new_state.raw_hex

            if has_changed:
                # Find door name
                door = next((d for d in self.doors if d.number == door_num), None)
                door_name = door.name if door else f"Door {door_num}"

                # Emit event
                event = ChangeEvent(
                    id=door_num,
                    name=door_name,
                    old_data=dict(old_state) if old_state else None,
                    new_data={"state": new_state.state, "raw_hex": new_state.raw_hex},
                )
                await self._emit(self._on_door_changed, event)

                logger.debug(
                    f"Door {door_num} ({door_name}): "
                    f"{old_state.get('raw_hex') if old_state else 'NEW'} -> {new_state.raw_hex}"
                )

            # Update stored state
            self.door_states[door_num] = {
                "state": new_state.state,
                "raw_hex": new_state.raw_hex,
            }
