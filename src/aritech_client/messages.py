"""
Message templates for ATS panel communication.

Each message template defines the structure for constructing and parsing
protocol messages.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class PropertyDef:
    """Definition of a property within a message."""

    byte: int
    mask: int = 0xFF
    length: int | None = None
    prop_type: str | None = None  # 'string', 'bool', or None for numeric


@dataclass(slots=True)
class MessageTemplate:
    """Template for a protocol message."""

    name: str
    msg_id: int
    msg_id_bytes: bytes
    template_bytes: bytes
    payload_length: int
    properties: dict[str, list[PropertyDef]] = field(default_factory=dict)


def _generate_bitmask_props(
    prefix: str, start_byte: int, start_index: int, end_index: int
) -> dict[str, list[PropertyDef]]:
    """Generate bitmask properties for area/zone selection."""
    props: dict[str, list[PropertyDef]] = {}
    for i in range(start_index, end_index + 1):
        byte_offset = (i - start_index) // 8
        bit_offset = (i - start_index) % 8
        mask = 1 << bit_offset
        props[f"{prefix}.{i}"] = [PropertyDef(byte=start_byte + byte_offset, mask=mask)]
    return props


# Message templates dictionary
MESSAGE_TEMPLATES: dict[str, MessageTemplate] = {}


def _register(
    name: str,
    msg_id: int,
    msg_id_bytes: list[int],
    template_bytes: list[int],
    payload_length: int,
    properties: dict[str, list[dict[str, Any]]] | None = None,
) -> None:
    """Register a message template."""
    props: dict[str, list[PropertyDef]] = {}
    if properties:
        for prop_name, prop_defs in properties.items():
            props[prop_name] = [
                PropertyDef(
                    byte=p["byte"],
                    mask=p.get("mask", 0xFF),
                    length=p.get("length"),
                    prop_type=p.get("type"),
                )
                for p in prop_defs
            ]

    MESSAGE_TEMPLATES[name] = MessageTemplate(
        name=name,
        msg_id=msg_id,
        msg_id_bytes=bytes(msg_id_bytes),
        template_bytes=bytes(template_bytes),
        payload_length=payload_length,
        properties=props,
    )


# Session management
_register(
    "createSession",
    msg_id=120,
    msg_id_bytes=[0xF0, 0x01],
    template_bytes=[0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    payload_length=20,
    properties={
        "typeId": [{"byte": 3}],
        "data": [{"byte": 4, "length": 16}],
    },
)

_register(
    "enableEncryptionKey",
    msg_id=120,
    msg_id_bytes=[0xF0, 0x01],
    template_bytes=[0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

_register(
    "batch",
    msg_id=116250679,
    msg_id_bytes=[0xEE, 0xE0, 0xEE, 0xEE],
    template_bytes=[],
    payload_length=5,
    properties={},
)

# Area control sessions
for name, msg_id, msg_id_bytes in [
    ("createPartArmSession", 294, [0xCC, 0x04]),
    ("createPartArm2Session", 1062, [0xCC, 0x10]),
    ("createArmSession", 358, [0xCC, 0x05]),
    ("createDisarmSession", 230, [0xCC, 0x03]),
]:
    props = {
        "typeId": [{"byte": 3}],
        "areas-1-32": [{"byte": 4}],
        "areas-33-64": [{"byte": 8}],
    }
    # Add area.N properties
    for i in range(1, 65):
        byte_offset = (i - 1) // 8
        bit_offset = (i - 1) % 8
        props[f"area.{i}"] = [{"byte": 4 + byte_offset, "mask": 1 << bit_offset}]

    _register(
        name,
        msg_id=msg_id,
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        payload_length=10 if name != "createOutputControlSession" else 8,
        properties=props,
    )

# Output/Trigger/Zone control sessions
for name, msg_id, msg_id_bytes, payload_len in [
    ("createOutputControlSession", 934, [0xCC, 0x0E], 8),
    ("createTriggerControlSession", 678, [0xCC, 0x0A], 12),
    ("createZoneControlSession", 550, [0xCC, 0x08], 12),
]:
    props = {
        "typeId": [{"byte": 3}],
        "areas-1-32": [{"byte": 4}],
        "areas-33-64": [{"byte": 8}],
    }
    for i in range(1, 65):
        byte_offset = (i - 1) // 8
        bit_offset = (i - 1) % 8
        props[f"area.{i}"] = [{"byte": 4 + byte_offset, "mask": 1 << bit_offset}]

    _register(
        name,
        msg_id=msg_id,
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x00, 0x04, 0x00, 0x00, 0x00, 0x00] if payload_len == 8 else [0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        payload_length=payload_len,
        properties=props,
    )

_register(
    "destroyControlSession",
    msg_id=-39,
    msg_id_bytes=[0xCD, 0x00],
    template_bytes=[0x00, 0x03, 0x00, 0x00],
    payload_length=7,
    properties={
        "typeId": [{"byte": 3}],
        "sessionId": [{"byte": 4}],
    },
)

# Device messages
_register(
    "deviceDescription",
    msg_id=4,
    msg_id_bytes=[0x08],
    template_bytes=[0x50, 0x10] + [0x00] * 85,
    payload_length=88,
    properties={
        "typeId": [{"byte": 1}],
        "deviceName": [{"byte": 3, "length": 16, "type": "string"}],
        "productName": [{"byte": 20, "length": 16, "type": "string"}],
        "flexibleNumbering": [{"byte": 35, "mask": 0x1}],
        "cdcMode": [{"byte": 35, "mask": 0x2}],
        "firmwareVersion": [{"byte": 37, "length": 16, "type": "string"}],
        "serialNumber": [{"byte": 54, "length": 16, "type": "string"}],
        "hardwareVariant": [{"byte": 71}],
        "macAddress": [{"byte": 72, "length": 6}],
        "encryptionMode": [{"byte": 78}],
        "panelNorm": [{"byte": 79}],
        "utcOffset": [{"byte": 84}],
        "panelLanguage": [{"byte": 87}],
    },
)

_register(
    "logout",
    msg_id=-8,
    msg_id_bytes=[0x0F],
    template_bytes=[0x06, 0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

# x500 panels: PIN-based login (device.getConnect)
_register(
    "loginWithPin",
    msg_id=3,
    msg_id_bytes=[0x06],
    template_bytes=[0x06, 0x0B, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    payload_length=25,
    properties={
        "typeId": [{"byte": 3}],
        "canUpload": [{"byte": 4}],
        "canDownload": [{"byte": 5}],
        "canControl": [{"byte": 6}],
        "canMonitor": [{"byte": 7}],
        "canDiagnose": [{"byte": 8}],
        "canReadLogs": [{"byte": 9}],
        "pinCode": [{"byte": 11, "length": 10}],
        "connectionMethod": [{"byte": 22}],
    },
)

# x700 panels: Username/password login (device.getLogPassConnect)
# Based on mobile app capture - payloadLength 79 bytes (including msgId byte)
# Byte layout: [0x06][0x0f][0x06][6 permission flags][0x20 usrlen][32-byte username][0x20 pwdlen][32-byte password][connMethod][connMethodExt][RFU]
# Mobile app payload: 060f06 010001010101 20 cccc...32bytes... 20 cccc...32bytes... 030000
_register(
    "loginWithAccount",
    msg_id=3,
    msg_id_bytes=[0x06],
    template_bytes=[
        0x06, 0x0F, 0x06,  # templateBytes 0-2: sub-type markers
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # templateBytes 3-8: 6 permission flags (upload, download, control, monitor, diagnose, readLogs)
        0x20,              # templateBytes 9: username length marker (0x20 = 32, fixed)
        *([0x00] * 32),    # templateBytes 10-41: username (32 bytes, null-padded)
        0x20,              # templateBytes 42: password length marker (0x20 = 32, fixed)
        *([0x00] * 32),    # templateBytes 43-74: password (32 bytes, null-padded)
        0x00, 0x00, 0x00,  # templateBytes 75-77: connMethod, connMethodExt, RFU
    ],
    payload_length=79,
    properties={
        # Byte offsets are relative to after header (byte 0 = msgId), so bufferIndex = byteOffset + 1
        "canUpload": [{"byte": 4}],
        "canDownload": [{"byte": 5}],
        "canControl": [{"byte": 6}],
        "canMonitor": [{"byte": 7}],
        "canDiagnose": [{"byte": 8}],
        "canReadLogs": [{"byte": 9}],
        "username": [{"byte": 11, "length": 32}],  # skip len marker at byte 10
        "password": [{"byte": 44, "length": 32}],  # skip len marker at byte 43
        "connectionMethod": [{"byte": 76}],
        "connectionMethodExtended": [{"byte": 77}],
        "reservedForFutureUse": [{"byte": 78}],
    },
)

_register(
    "getDeviceInfo",
    msg_id=-2,
    msg_id_bytes=[0x03],
    template_bytes=[0x50, 0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

_register(
    "ping",
    msg_id=3,
    msg_id_bytes=[0x06],
    template_bytes=[0x68, 0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

# Area control commands
_register(
    "setAreaForced",
    msg_id=-5416,
    msg_id_bytes=[0xCF, 0x54],
    template_bytes=[0x00, 0x03, 0x00, 0x00],
    payload_length=7,
    properties={
        "typeId": [{"byte": 3}],
        "sessionId": [{"byte": 4}, {"byte": 5}],
    },
)

_register(
    "armAreas",
    msg_id=-5224,
    msg_id_bytes=[0xCF, 0x51],
    template_bytes=[0x00, 0x03, 0x00, 0x00],
    payload_length=7,
    properties={
        "typeId": [{"byte": 3}],
        "sessionId": [{"byte": 4}],
    },
)

_register(
    "disarmAreas",
    msg_id=-3176,
    msg_id_bytes=[0xCF, 0x31],
    template_bytes=[0x00, 0x03, 0x00, 0x00],
    payload_length=7,
    properties={
        "typeId": [{"byte": 3}],
        "sessionId": [{"byte": 4}],
    },
)

# Zone info commands
for name, msg_id_bytes in [
    ("getActiveZones", [0xCF, 0x55]),
    ("getFaultZones", [0xCF, 0x52]),
    ("getInhibitedZones", [0xCF, 0x57]),
]:
    _register(
        name,
        msg_id=-5480 if name == "getActiveZones" else (-5288 if name == "getFaultZones" else -5608),
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        payload_length=8,
        properties={
            "typeId": [{"byte": 3}],
            "sessionId": [{"byte": 5}, {"byte": 6}],
            "next": [{"byte": 7}],
        },
    )

# Output/Trigger/Zone control
for name, msg_id, msg_id_bytes, payload_len in [
    ("activateOutput", -276584, [0xCF, 0xE1, 0x21], 8),
    ("deactivateOutput", -276648, [0xCF, 0xE2, 0x21], 8),
    ("activateTrigger", -272488, [0xCF, 0xA1, 0x21], 9),
    ("deactivateTrigger", -272552, [0xCF, 0xA2, 0x21], 9),
    ("inhibitZone", -270568, [0xCF, 0x83, 0x21], 8),
    ("uninhibitZone", -270632, [0xCF, 0x84, 0x21], 8),
]:
    _register(
        name,
        msg_id=msg_id,
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x02, 0x00, 0x00, 0x00, 0x00],
        payload_length=payload_len,
        properties={
            "typeId": [{"byte": 3}],
            "sessionId": [{"byte": 4}],
            "objectId": [{"byte": 7}],
        },
    )

# Query messages
_register(
    "getZonesAssignedToAreas",
    msg_id=484,
    msg_id_bytes=[0xC8, 0x07],
    template_bytes=[0x21, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    payload_length=12,
    properties={
        "typeId": [{"byte": 3}],
        "areas-1-32": [{"byte": 4}, {"byte": 5}, {"byte": 6}, {"byte": 7}],
        "areas-33-64": [{"byte": 8}, {"byte": 9}, {"byte": 10}, {"byte": 11}],
    },
)

# Get user info (enables COS event notifications)
_register(
    "getUserInfo",
    msg_id=228,
    msg_id_bytes=[0xC8, 0x03],
    template_bytes=[0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

# Change-of-state queries
for name, msg_id, msg_id_bytes in [
    ("getAreaChanges", 165, [0xCA, 0x02]),
    ("getOutputChanges", 485, [0xCA, 0x07]),
    ("getTriggerChanges", 1317, [0xCA, 0x14]),
    ("getZoneChanges", 101, [0xCA, 0x01]),
]:
    _register(
        name,
        msg_id=msg_id,
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x00, 0x00],
        payload_length=4,
        properties={"typeId": [{"byte": 3}]},
    )

# Status queries
for name, msg_id, msg_id_bytes in [
    ("getAreaStatus", -166, [0xCB, 0x02]),
    ("getOutputStatus", -486, [0xCB, 0x07]),
    ("getTriggerStatus", -1318, [0xCB, 0x14]),
    ("getZoneStatus", -102, [0xCB, 0x01]),
]:
    _register(
        name,
        msg_id=msg_id,
        msg_id_bytes=msg_id_bytes,
        template_bytes=[0x00, 0x03, 0x00, 0x00],
        payload_length=6,
        properties={
            "typeId": [{"byte": 3}],
            "objectId": [{"byte": 5}],
        },
    )

_register(
    "getValidAreas",
    msg_id=13,
    msg_id_bytes=[0x1A],
    template_bytes=[0x02, 0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

_register(
    "getControlSessionStatus",
    msg_id=39,
    msg_id_bytes=[0xCE, 0x00],
    template_bytes=[0x00, 0x03, 0x00, 0x00],
    payload_length=7,
    properties={
        "typeId": [{"byte": 3}],
        "sessionId": [{"byte": 4}],
    },
)

# Name queries
for name, type_byte in [
    ("getAreaNames", 0x02),
    ("getOutputNames", 0x07),
    ("getTriggerNames", 0x14),
    ("getZoneNames", 0x01),
]:
    _register(
        name,
        msg_id=12,
        msg_id_bytes=[0x18],
        template_bytes=[type_byte, 0x00, 0x03, 0x00, 0x00],
        payload_length=6,
        properties={
            "typeId": [{"byte": 3}],
            "index": [{"byte": 5}],
        },
    )

# Extended format for name queries (x700 panels and x500 panels with protocol 4.4+)
# Uses 0x19 message ID (same as response), 30-byte names, 4 names per page
_register(
    "getAreaNamesExtended",
    msg_id=-13,
    msg_id_bytes=[0x19],
    template_bytes=[0x02, 0x00, 0x03, 0x00, 0x00],
    payload_length=6,
    properties={
        "typeId": [{"byte": 3}],
        "index": [{"byte": 5}],
    },
)

_register(
    "getZoneNamesExtended",
    msg_id=-13,
    msg_id_bytes=[0x19],
    template_bytes=[0x01, 0x00, 0x03, 0x00, 0x00],
    payload_length=6,
    properties={
        "typeId": [{"byte": 3}],
        "index": [{"byte": 5}],
    },
)

# Name responses
for name, type_byte in [
    ("areaNames", 0x02),
    ("outputNames", 0x07),
    ("triggerNames", 0x14),
    ("zoneNames", 0x01),
]:
    _register(
        name,
        msg_id=-13,
        msg_id_bytes=[0x19],
        template_bytes=[type_byte, 0x00, 0x00, 0x10],
        payload_length=5,
        properties={
            "name": [{"byte": -1, "length": 16, "type": "string"}],
            "index": [{"byte": 3}],
        },
    )

# Response messages
_register(
    "booleanResponse",
    msg_id=0,
    msg_id_bytes=[0x00],
    template_bytes=[0x01, 0x00],
    payload_length=3,
    properties={"result": [{"byte": 2, "type": "bool"}]},
)

_register(
    "shortResponse",
    msg_id=0,
    msg_id_bytes=[0x00],
    template_bytes=[0x03, 0x00, 0x00],
    payload_length=4,
    properties={"result": [{"byte": 2}, {"byte": 3}]},
)

_register(
    "controlSessionStatus",
    msg_id=16,
    msg_id_bytes=[0x20],
    template_bytes=[0x00, 0x00, 0x00],
    payload_length=4,
    properties={"stateId": [{"byte": 3}, {"byte": 2}]},  # Big-endian
)

_register(
    "validAreas",
    msg_id=-14,
    msg_id_bytes=[0x1B],
    template_bytes=[0x02],
    payload_length=2,
    properties={"bitset": [{"byte": 2}]},
)

_register(
    "zonesAssignedToAreas",
    msg_id=16,
    msg_id_bytes=[0x20],
    template_bytes=[0x0A],
    payload_length=2,
    properties={"bitset": [{"byte": 2}]},
)

# Status responses
_register(
    "areaStatus",
    msg_id=-25,
    msg_id_bytes=[0x31],
    template_bytes=[0x02, 0x00, 0x00] + [0x00] * 10,
    payload_length=14,
    properties={
        "objectId": [{"byte": 3}],
        "isFullSet": [{"byte": 4, "mask": 0x01}],
        "isPartiallySet": [{"byte": 4, "mask": 0x02}],
        "isUnset": [{"byte": 4, "mask": 0x04}],
        "isAlarming": [{"byte": 4, "mask": 0x08}],
        "hasFire": [{"byte": 5, "mask": 0x20}],
        "hasPanic": [{"byte": 6, "mask": 0x04}],
        "hasMedical": [{"byte": 6, "mask": 0x80}],
        "hasTechnical": [{"byte": 7, "mask": 0x10}],
        "hasDuress": [{"byte": 10, "mask": 0x08}],
        "isTampered": [{"byte": 8, "mask": 0x02}],
        "hasActiveZones": [{"byte": 9, "mask": 0x02}],
        "hasInhibitedZones": [{"byte": 9, "mask": 0x04}],
        "hasIsolatedZones": [{"byte": 9, "mask": 0x08}],
        "hasZoneFaults": [{"byte": 9, "mask": 0x10}],
        "hasZoneTamper": [{"byte": 9, "mask": 0x40}],
        "isExiting": [{"byte": 11, "mask": 0x04}],
        "isEntering": [{"byte": 11, "mask": 0x02}],
        "isReadyToArm": [{"byte": 11, "mask": 0x10}],
        "isAlarmAcknowledged": [{"byte": 12, "mask": 0x01}],
        "isBuzzerActive": [{"byte": 13, "mask": 0x02}],
        "isInternalSiren": [{"byte": 12, "mask": 0x40}],
        "isExternalSiren": [{"byte": 12, "mask": 0x80}],
        "isStrobeActive": [{"byte": 13, "mask": 0x01}],
        "isPartiallySet2": [{"byte": 13, "mask": 0x08}],
    },
)

_register(
    "outputStatus",
    msg_id=-25,
    msg_id_bytes=[0x31],
    template_bytes=[0x07, 0x00, 0x00, 0x00],
    payload_length=5,
    properties={
        "objectId": [{"byte": 3}],
        "isActive": [{"byte": 4, "mask": 0x01}],
        "isOn": [{"byte": 4, "mask": 0x02}],
        "isForced": [{"byte": 4, "mask": 0x04}],
    },
)

_register(
    "triggerStatus",
    msg_id=-25,
    msg_id_bytes=[0x31],
    template_bytes=[0x14, 0x00, 0x00, 0x00],
    payload_length=5,
    properties={
        "objectId": [{"byte": 3}],
        "isRemoteOutput": [{"byte": 4, "mask": 0x08}],
        "isFob": [{"byte": 4, "mask": 0x40}],
        "isKeyfobSwitch1": [{"byte": 4, "mask": 0x01}],
        "isKeyfobSwitch2": [{"byte": 4, "mask": 0x02}],
        "isKeyfobSwitch12": [{"byte": 4, "mask": 0x04}],
        "isSchedule": [{"byte": 4, "mask": 0x20}],
        "isFunctionKey": [{"byte": 4, "mask": 0x10}],
    },
)

_register(
    "zoneStatus",
    msg_id=-25,
    msg_id_bytes=[0x31],
    template_bytes=[0x01, 0x00, 0x00, 0x00, 0x00, 0x00],
    payload_length=7,
    properties={
        "objectId": [{"byte": 3}],
        "isActive": [{"byte": 4, "mask": 0x01}],
        "isTampered": [{"byte": 4, "mask": 0x02}],
        "isAntiMask": [{"byte": 4, "mask": 0x04}],
        "hasBatteryFault": [{"byte": 4, "mask": 0x08}],
        "hasFault": [{"byte": 4, "mask": 0x10}],
        "isDirty": [{"byte": 4, "mask": 0x20}],
        "isInhibited": [{"byte": 5, "mask": 0x01}],
        "isIsolated": [{"byte": 5, "mask": 0x02}],
        "isInSoakTest": [{"byte": 5, "mask": 0x04}],
        "isSet": [{"byte": 5, "mask": 0x08}],
        "isAlarming": [{"byte": 5, "mask": 0x10}],
    },
)

# Log messages
_register(
    "openLog",
    msg_id=3,
    msg_id_bytes=[0x06],
    template_bytes=[0x0D, 0x00, 0x00],
    payload_length=4,
    properties={"typeId": [{"byte": 3}]},
)

_register(
    "selectLogEntry",
    msg_id=-2,
    msg_id_bytes=[0x03],
    template_bytes=[0x0D, 0x00, 0x02, 0x00],
    payload_length=5,
    properties={
        "typeId": [{"byte": 3}],
        "logReadingDirection": [{"byte": 4}],
    },
)

_register(
    "logEntry",
    msg_id=-7,
    msg_id_bytes=[0x0D],
    template_bytes=[0x00] * 60,
    payload_length=61,
    properties={
        "timestamp": [{"byte": 9}],
        "uniqueId": [{"byte": 13}],
        "logType": [{"byte": 14}],
        "eventId": [{"byte": 16}],
        "eventSource": [{"byte": 17}],
        "sourceId": [{"byte": 19}],
        "area": [{"byte": 20}],
        "eventText": [{"byte": 29, "length": 32, "type": "string"}],
    },
)

# x700 panels require start.MONITOR before reading event logs
_register(
    "startMonitor",
    msg_id=-101,
    msg_id_bytes=[0xC9, 0x01],
    template_bytes=[0x00, 0x00],
    payload_length=4,
    properties={},
)


def get_template(name: str) -> MessageTemplate | None:
    """Get a message template by name."""
    return MESSAGE_TEMPLATES.get(name)
