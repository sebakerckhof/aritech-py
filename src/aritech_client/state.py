"""
State classes for parsing status responses from ATS panels.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .messages import MessageTemplate

from .messages import MESSAGE_TEMPLATES


def _snake_to_camel(name: str) -> str:
    """Convert snake_case to camelCase."""
    components = name.split("_")
    return components[0] + "".join(x.title() for x in components[1:])


def _get_all_properties(template_name: str, payload: bytes) -> dict[str, Any]:
    """Extract all properties from a response payload."""
    template = MESSAGE_TEMPLATES.get(template_name)
    if not template:
        return {}

    result: dict[str, Any] = {}

    for prop_name, prop_defs in template.properties.items():
        if not prop_defs:
            continue

        try:
            # Handle multi-byte properties
            if len(prop_defs) > 1 and all(p.mask == 0xFF for p in prop_defs):
                value = 0
                valid = True
                for i, prop_def in enumerate(prop_defs):
                    if 0 <= prop_def.byte < len(payload):
                        value |= payload[prop_def.byte] << (i * 8)
                    else:
                        valid = False
                        break
                if valid:
                    result[prop_name] = value
                continue

            prop_def = prop_defs[0]
            byte_offset = prop_def.byte
            mask = prop_def.mask
            prop_type = prop_def.prop_type

            if 0 <= byte_offset < len(payload):
                if prop_type == "string":
                    str_len = payload[byte_offset]
                    if str_len > 0 and byte_offset + 1 + str_len <= len(payload):
                        result[prop_name] = (
                            payload[byte_offset + 1 : byte_offset + 1 + str_len]
                            .decode("ascii", errors="ignore")
                            .rstrip("\x00")
                            .strip()
                        )
                    else:
                        result[prop_name] = ""
                elif prop_type == "bool":
                    result[prop_name] = payload[byte_offset] != 0
                elif mask == 0xFF:
                    result[prop_name] = payload[byte_offset]
                else:
                    result[prop_name] = (payload[byte_offset] & mask) != 0
        except (IndexError, ValueError):
            pass

    return result


@dataclass(slots=True)
class AreaState:
    """Parsed area status."""

    is_full_set: bool = False
    is_partially_set: bool = False
    is_partially_set_2: bool = False
    is_unset: bool = False
    is_alarming: bool = False
    is_alarm_acknowledged: bool = False
    is_tampered: bool = False
    is_exiting: bool = False
    is_entering: bool = False
    is_ready_to_arm: bool = False
    has_fire: bool = False
    has_panic: bool = False
    has_medical: bool = False
    has_technical: bool = False
    has_duress: bool = False
    has_active_zones: bool = False
    has_inhibited_zones: bool = False
    has_isolated_zones: bool = False
    has_zone_faults: bool = False
    has_zone_tamper: bool = False
    is_buzzer_active: bool = False
    is_internal_siren: bool = False
    is_external_siren: bool = False
    is_strobe_active: bool = False
    raw_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> AreaState:
        """Parse area status from response bytes."""
        state = cls()
        if not data or len(data) < 4:
            return state

        state.raw_flags = _get_all_properties("areaStatus", data)
        for f in fields(state):
            if f.name != "raw_flags":
                camel_name = _snake_to_camel(f.name)
                setattr(state, f.name, state.raw_flags.get(camel_name, False))

        return state

    def __str__(self) -> str:
        states = []
        if self.is_full_set:
            states.append("Armed")
        elif self.is_partially_set:
            states.append("Part-Armed")
        elif self.is_partially_set_2:
            states.append("Part-Armed 2")
        elif self.is_unset:
            states.append("Disarmed")
        if self.is_alarming:
            states.append("ALARM")
        if self.is_exiting:
            states.append("Exit")
        if self.is_entering:
            states.append("Entry")
        if self.is_ready_to_arm:
            states.append("Ready")
        return ", ".join(states) if states else "Unknown"


@dataclass(slots=True)
class ZoneState:
    """Parsed zone status."""

    is_active: bool = False
    is_set: bool = False
    is_tampered: bool = False
    has_fault: bool = False
    is_inhibited: bool = False
    is_isolated: bool = False
    is_alarming: bool = False
    is_anti_mask: bool = False
    is_in_soak_test: bool = False
    has_battery_fault: bool = False
    is_dirty: bool = False
    raw_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> ZoneState:
        """Parse zone status from response bytes."""
        state = cls()
        if not data or len(data) < 4:
            return state

        state.raw_flags = _get_all_properties("zoneStatus", data)
        for f in fields(state):
            if f.name != "raw_flags":
                camel_name = _snake_to_camel(f.name)
                setattr(state, f.name, state.raw_flags.get(camel_name, False))

        return state

    def __str__(self) -> str:
        states = []
        if self.is_active:
            states.append("Active")
        if self.is_set:
            states.append("Armed")
        if self.is_alarming:
            states.append("ALARM")
        if self.is_inhibited:
            states.append("Inhibited")
        if self.is_isolated:
            states.append("Isolated")
        if self.is_tampered:
            states.append("Tamper")
        if self.has_fault:
            states.append("Fault")
        return ", ".join(states) if states else "OK"


@dataclass(slots=True)
class OutputState:
    """Parsed output status."""

    is_active: bool = False
    is_on: bool = False
    is_forced: bool = False
    raw_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> OutputState:
        """Parse output status from response bytes."""
        state = cls()
        if not data or len(data) < 5:
            return state

        state.raw_flags = _get_all_properties("outputStatus", data)
        for f in fields(state):
            if f.name != "raw_flags":
                camel_name = _snake_to_camel(f.name)
                setattr(state, f.name, state.raw_flags.get(camel_name, False))

        return state

    def __str__(self) -> str:
        states = []
        if self.is_on:
            states.append("On")
        if self.is_active:
            states.append("Active")
        if self.is_forced:
            states.append("Forced")
        return ", ".join(states) if states else "Off"


@dataclass(slots=True)
class TriggerState:
    """Parsed trigger status."""

    is_remote_output: bool = False
    is_fob: bool = False
    is_keyfob_switch1: bool = False
    is_keyfob_switch2: bool = False
    is_keyfob_switch12: bool = False
    is_schedule: bool = False
    is_function_key: bool = False
    raw_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> TriggerState:
        """Parse trigger status from response bytes."""
        state = cls()
        if not data or len(data) < 5:
            return state

        state.raw_flags = _get_all_properties("triggerStatus", data)
        for f in fields(state):
            if f.name != "raw_flags":
                camel_name = _snake_to_camel(f.name)
                setattr(state, f.name, state.raw_flags.get(camel_name, False))

        return state

    @property
    def is_active(self) -> bool:
        """Trigger is active if any activation source is true."""
        return (
            self.is_remote_output
            or self.is_fob
            or self.is_keyfob_switch1
            or self.is_keyfob_switch2
            or self.is_keyfob_switch12
            or self.is_schedule
            or self.is_function_key
        )

    def __str__(self) -> str:
        sources = []
        if self.is_remote_output:
            sources.append("RemoteOut")
        if self.is_fob:
            sources.append("Fob")
        if self.is_keyfob_switch1:
            sources.append("KeyfobSw1")
        if self.is_keyfob_switch2:
            sources.append("KeyfobSw2")
        if self.is_keyfob_switch12:
            sources.append("KeyfobSw12")
        if self.is_schedule:
            sources.append("Schedule")
        if self.is_function_key:
            sources.append("FKey")
        return f"Active ({', '.join(sources)})" if sources else "Inactive"


@dataclass(slots=True)
class DoorState:
    """Parsed door status."""

    # Byte 4 flags
    is_disabled: bool = False
    is_unlocked: bool = False
    is_unlocked_period: bool = False
    is_time_unlocked: bool = False
    is_standard_time_unlocked: bool = False
    is_opened: bool = False
    is_forced: bool = False
    is_door_open_too_long: bool = False
    # Byte 5 flags
    is_shunting: bool = False
    is_shunt_warning: bool = False
    is_reader_fault: bool = False
    is_reader_tamper: bool = False
    is_unsecured: bool = False
    is_input_active: bool = False
    is_output_active: bool = False
    raw_flags: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, data: bytes) -> DoorState:
        """Parse door status from response bytes."""
        state = cls()
        if not data or len(data) < 6:
            return state

        state.raw_flags = _get_all_properties("doorStatus", data)
        for f in fields(state):
            if f.name != "raw_flags":
                camel_name = _snake_to_camel(f.name)
                setattr(state, f.name, state.raw_flags.get(camel_name, False))

        return state

    @property
    def is_locked(self) -> bool:
        """Door is locked if not unlocked in any way."""
        return (
            not self.is_unlocked
            and not self.is_unlocked_period
            and not self.is_time_unlocked
            and not self.is_standard_time_unlocked
        )

    def __str__(self) -> str:
        states = []

        # Lock state
        if (
            self.is_unlocked
            or self.is_standard_time_unlocked
            or self.is_time_unlocked
            or self.is_unlocked_period
        ):
            states.append("Unlocked")
        else:
            states.append("Locked")

        if self.is_unlocked:
            states.append("FullUnlocked")
        if self.is_time_unlocked:
            states.append("TimeUnlocked")
        if self.is_standard_time_unlocked:
            states.append("StandardTimeUnlocked")
        if self.is_unlocked_period:
            states.append("PeriodUnlocked")

        # Open state
        if self.is_opened:
            states.append("Opened")

        # Alarm states
        if self.is_forced:
            states.append("Forced")
        if self.is_door_open_too_long:
            states.append("OpenTooLong")
        if self.is_disabled:
            states.append("Disabled")

        # Fault states
        if self.is_reader_fault:
            states.append("ReaderFault")
        if self.is_reader_tamper:
            states.append("ReaderTamper")
        if self.is_unsecured:
            states.append("Unsecured")

        return ", ".join(states)
