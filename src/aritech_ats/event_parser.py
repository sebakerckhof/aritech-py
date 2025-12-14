"""
Aritech ATS Event Log Parser.

Parses 70-byte event messages into structured data.

Event data structure (70 bytes total):
  Bytes 0-1:   Internal header (0x0020)
  Bytes 2-7:   Timestamp in BCD format (YYMMDDhhmmss)
  Bytes 8-11:  Reserved/unknown
  Byte 12:     Sequence number (0-255, decrements from newest to oldest)
  Byte 13:     Log type
  Bytes 14-15: Event ID (big-endian, maps to EVENT_TYPES)
  Byte 16:     Event source/class ID (high byte of class/device)
  Byte 17:     Source sub-ID
  Bytes 18-19: Entity ID / sub-type (big-endian)
  Byte 20:     Area ID
  Bytes 21-27: Detail fields (context-dependent)
  Bytes 28-69: Description text (42 bytes, NULL-padded ASCII)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any

from .event_types import (
    CLASS_ID_STRINGS,
    EVENT_TYPES,
    EventCategory,
    EventType,
    get_class_name,
    get_event_type,
)


class EntityType(StrEnum):
    """Entity types for events."""

    ZONE = "zone"
    AREA = "area"
    USER_GROUP = "user_group"
    DGP = "dgp"
    EXPANDER = "expander"
    USER = "user"
    OUTPUT = "output"
    PANEL = "panel"
    RAS = "ras"
    CENTRAL_STATION = "central_station"
    PC_CONNECTION = "pc_connection"
    FILTER = "filter"
    SYSTEM = "system"
    TRIGGER = "trigger"
    CALENDAR = "calendar"
    FOB = "fob"
    CAMERA = "camera"
    AREA_GROUP = "area_group"
    REGION = "region"
    DOOR = "door"
    DOOR_GROUP = "door_group"
    SPECIAL_DAY = "special_day"
    READER = "reader"
    AUDIO_DEVICE = "audio_device"
    NOTIFICATION = "notification"
    UNKNOWN = "unknown"


# Entity class definitions - maps class ID to entity type and whether
# the low byte represents an area ID or extra data.
ENTITY_CLASSES: dict[int, tuple[EntityType, bool]] = {
    0: (EntityType.ZONE, True),  # ZonesDev
    1: (EntityType.ZONE, True),  # AreasDev
    2: (EntityType.USER_GROUP, True),  # UserGrpDev
    3: (EntityType.DGP, False),  # DgpDev
    5: (EntityType.EXPANDER, False),  # DGPZoneSensor/DGP0
    6: (EntityType.USER, True),  # UserDev
    7: (EntityType.OUTPUT, False),  # OutputDev
    8: (EntityType.PANEL, False),  # PanelDev
    9: (EntityType.RAS, False),  # RasDev
    10: (EntityType.CENTRAL_STATION, False),  # CSDev
    11: (EntityType.PC_CONNECTION, False),  # PCConnDev
    14: (EntityType.OUTPUT, False),  # OutputDev
    15: (EntityType.FILTER, False),  # FilterDev
    16: (EntityType.USER, True),  # UserDev
    17: (EntityType.SYSTEM, False),  # SystemDev
    19: (EntityType.TRIGGER, False),  # TriggerDev
    20: (EntityType.CALENDAR, False),  # CalendarDev
    25: (EntityType.FOB, True),  # FobDev
    26: (EntityType.CAMERA, False),  # CameraDev
    32: (EntityType.AREA_GROUP, False),  # AreaGroupsDev
    35: (EntityType.REGION, False),  # RegionDev
    36: (EntityType.DOOR, False),  # DoorDev
    37: (EntityType.DOOR_GROUP, False),  # DoorGroupDev
    39: (EntityType.SPECIAL_DAY, False),  # SpecialDayDev
    41: (EntityType.READER, False),  # ReaderDev
    42: (EntityType.AUDIO_DEVICE, False),  # VocDev
    43: (EntityType.NOTIFICATION, False),  # NotifyDev
}


@dataclass(slots=True)
class EventEntity:
    """Parsed entity information from an event."""

    type: EntityType
    id: int
    description: str | None = None
    area: int | None = None
    extra: int | None = None


@dataclass(slots=True)
class ParsedEvent:
    """Parsed event from 70-byte event buffer."""

    raw: bytes
    timestamp: datetime
    sequence: int
    log_type: int
    event_id: int
    event_type: EventType
    class_id: int
    class_type: str
    area_id: int | None
    entity: EventEntity
    details: bytes

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "raw": self.raw.hex(),
            "timestamp": self.timestamp.isoformat(),
            "sequence": self.sequence,
            "logType": self.log_type,
            "type": self.event_id,
            "name": self.event_type.name,
            "category": self.event_type.category,
            "classId": self.class_id,
            "classType": self.class_type,
            "area": {"id": str(self.area_id)} if self.area_id else None,
            "entity": {
                "type": self.entity.type,
                "id": self.entity.id,
                "description": self.entity.description,
            },
            "details": self.details.hex(),
        }

    def __str__(self) -> str:
        return (
            f"{self.timestamp.isoformat()} [{self.event_type.category}] "
            f"{self.event_type.name} - {self.entity.type}:{self.entity.id}"
            + (f" (Area {self.area_id})" if self.area_id else "")
            + (f" - {self.entity.description}" if self.entity.description else "")
        )


def _parse_bcd_timestamp(data: bytes, offset: int) -> datetime:
    """
    Parse BCD timestamp bytes into a datetime object.

    BCD format: each byte represents two decimal digits in hex.
    e.g., 0x25 = year 25 (2025), 0x12 = month 12
    """
    try:
        year = int(f"{data[offset]:02x}")
        month = int(f"{data[offset + 1]:02x}")
        day = int(f"{data[offset + 2]:02x}")
        hour = int(f"{data[offset + 3]:02x}")
        minute = int(f"{data[offset + 4]:02x}")
        second = int(f"{data[offset + 5]:02x}")

        return datetime(2000 + year, month, day, hour, minute, second)
    except (ValueError, IndexError):
        return datetime(2000, 1, 1, 0, 0, 0)


def _parse_entity(class_device_id: int, sub_type: int) -> tuple[int, str, EventEntity]:
    """
    Parse entity information from class/device ID and sub-type fields.

    Args:
        class_device_id: Class/Device ID (bytes 16-17 combined)
        sub_type: Sub-type value (bytes 18-19, entity ID)

    Returns:
        Tuple of (class_id, class_type, EventEntity)
    """
    # Extract class ID from high byte
    class_id = (class_device_id >> 8) & 0xFF
    class_type = get_class_name(class_id)

    # Extract entity number from sub-type (high byte = entity ID, low byte = area or extra)
    entity_number = (sub_type >> 8) & 0xFF
    entity_low_byte = sub_type & 0xFF

    # Look up class definition
    entity_type, has_area = ENTITY_CLASSES.get(class_id, (EntityType.UNKNOWN, False))

    entity = EventEntity(type=entity_type, id=entity_number)

    if has_area:
        entity.area = entity_low_byte
    elif entity_low_byte != 0:
        entity.extra = entity_low_byte

    return class_id, class_type, entity


def parse_event(event_buffer: bytes) -> ParsedEvent:
    """
    Parse a 70-byte event buffer into structured data.

    Args:
        event_buffer: 70-byte event data

    Returns:
        ParsedEvent object

    Raises:
        ValueError: If buffer is not exactly 70 bytes
    """
    if len(event_buffer) != 70:
        raise ValueError(f"Event buffer must be exactly 70 bytes, got {len(event_buffer)}")

    # Parse timestamp from BCD bytes (offset 2)
    timestamp = _parse_bcd_timestamp(event_buffer, 2)

    # Read event identification fields
    sequence = event_buffer[12]
    log_type = event_buffer[13]
    event_id = (event_buffer[14] << 8) | event_buffer[15]  # big-endian
    event_source = event_buffer[16]
    source_sub_id = event_buffer[17]
    entity_id = (event_buffer[18] << 8) | event_buffer[19]  # big-endian
    area_id = event_buffer[20]

    # Description text (bytes 28-69, 42 bytes)
    description = (
        event_buffer[28:70].decode("ascii", errors="ignore").rstrip("\x00").strip()
    )

    # Look up event type info
    event_type = get_event_type(event_id)

    # Construct class/device ID for entity parsing
    class_device_id = (event_source << 8) | source_sub_id

    # Parse entity information
    class_id, class_type, entity = _parse_entity(class_device_id, entity_id)
    entity.description = description if description else None

    # Detail bytes (21-27)
    details = event_buffer[21:28]

    return ParsedEvent(
        raw=event_buffer,
        timestamp=timestamp,
        sequence=sequence,
        log_type=log_type,
        event_id=event_id,
        event_type=event_type,
        class_id=class_id,
        class_type=class_type,
        area_id=area_id if area_id else None,
        entity=entity,
        details=details,
    )


def parse_events(buffer: bytes) -> list[ParsedEvent | dict[str, Any]]:
    """
    Parse multiple events from a buffer.

    Args:
        buffer: Buffer containing one or more 70-byte events

    Returns:
        List of ParsedEvent objects or error dicts
    """
    events: list[ParsedEvent | dict[str, Any]] = []
    event_count = len(buffer) // 70

    for i in range(event_count):
        offset = i * 70
        event_buffer = buffer[offset : offset + 70]

        if len(event_buffer) == 70:
            try:
                events.append(parse_event(event_buffer))
            except Exception as e:
                events.append(
                    {
                        "error": str(e),
                        "offset": offset,
                        "raw": event_buffer.hex(),
                    }
                )

    return events
