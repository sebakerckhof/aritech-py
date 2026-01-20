"""
Async client for ATS alarm panel communication.

This module provides the main AritechClient class for connecting to and
communicating with ATS alarm panels over TCP/IP.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections.abc import AsyncIterator, Callable, Coroutine
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .event_parser import ParsedEvent

from .errors import AritechError, ErrorCode
from .message_helpers import (
    HEADER_ERROR,
    HEADER_REQUEST,
    HEADER_RESPONSE,
    build_batch_stat_request,
    build_get_event_log_message,
    build_get_stat_request,
    build_get_valid_zones_message,
    check_response_error,
    construct_message,
    get_property,
    is_message_type,
    parse_create_cc_response,
    parse_return_bool,
    split_batch_response,
)
from .protocol import (
    SLIP_END,
    append_crc,
    calculate_protocol_version,
    decrypt_message,
    decode_serial,
    encrypt_message,
    make_encryption_key,
    make_encryption_key_pbkdf2,
    slip_decode,
    slip_encode,
    verify_crc,
)
from .state import AreaState, DoorState, FilterState, OutputState, TriggerState, ZoneState

logger = logging.getLogger(__name__)


class LoginType:
    """Login type constants for authentication.

    INSTALLER: Login as installer (0x01) - full access but only one session allowed.
               Note: ATS8500 will not work correctly while logged in as installer.
    USER: Login as user (0x03) - standard user access.
    """

    INSTALLER = 0x01
    USER = 0x03


def _debug_enabled() -> bool:
    """Check if debug logging is enabled."""
    return logger.isEnabledFor(logging.DEBUG)


@dataclass(slots=True)
class AritechConfig:
    """Configuration for AritechClient.

    For x500 panels: use pin
    For x700 panels: use username (password defaults to username if not set)
    """

    host: str
    port: int = 3001
    pin: str = ""
    encryption_key: str = ""
    serial: str | None = None
    username: str = ""
    password: str = ""  # Defaults to username if not set


@dataclass(slots=True)
class NamedItem:
    """A named item (area, zone, output, or trigger)."""

    number: int
    name: str


@dataclass(slots=True)
class StateResult:
    """Result of a status query."""

    number: int
    state: Any
    raw_hex: str = ""


# Model configuration
MODEL_AREAS = {
    "ATS1000": 4,
    "ATS1500": 4,
    "ATS1700": 4,
    "ATS2000": 8,
    "ATS3500": 8,
    "ATS3700": 8,
    "ATS4500": 64,
    "ATS4700": 64,
}

MODEL_ZONES = {
    "ATS1000": 368,
    "ATS1500": 240,
    "ATS1700": 240,
    "ATS2000": 368,
    "ATS3500": 496,
    "ATS3700": 496,
    "ATS4500": 976,
    "ATS4700": 976,
}

# Response parsing constants for standard format (x500 panels with protocol < 4.4)
NAMES_START_OFFSET = 6  # Offset where names begin in getName responses
NAME_LENGTH = 16  # Each name is 16 bytes, null-padded
NAMES_PER_PAGE = 16  # Panel returns 16 names per request

# Response parsing constants for extended format (x700 panels and x500 panels with protocol 4.4+)
EXTENDED_NAME_LENGTH = 30  # Extended format uses 30-byte names
EXTENDED_NAMES_PER_PAGE = 4  # Extended format returns 4 names per request

# Event log direction constants
EVENT_LOG_FIRST = 0x00
EVENT_LOG_NEXT = 0x03

# Control context status codes for arm operations
CC_STATUS = {
    # Part set statuses (0x04xx)
    "PartSetFault": 0x0401,
    "PartSetActiveStates": 0x0402,
    "PartSetInhibited": 0x0403,
    "PartSetSetting": 0x0404,
    "PartSetSet": 0x0405,
    # Full set statuses (0x05xx)
    "FullSetFault": 0x0501,
    "FullSetActiveStates": 0x0502,
    "FullSetInhibited": 0x0503,
    "FullSetSetting": 0x0504,
    "FullSetSet": 0x0505,
    # Part set 2 statuses (0x10xx)
    "PartSet2Fault": 0x1001,
    "PartSet2ActiveStates": 0x1002,
    "PartSet2Inhibited": 0x1003,
    "PartSet2Setting": 0x1004,
    "PartSet2Set": 0x1005,
}


class AritechClient:
    """
    Async client for Aritech ATS alarm panels.

    Example usage:
        ```python
        async with AritechClient(config) as client:
            await client.initialize()
            areas = await client.get_area_names()
            states = await client.get_area_states([a.number for a in areas])
        ```
    """

    def __init__(self, config: dict[str, Any] | AritechConfig) -> None:
        """
        Initialize the Aritech client.

        Args:
            config: Configuration dict or AritechConfig instance
        """
        if isinstance(config, dict):
            self.config = AritechConfig(
                host=config.get("host", ""),
                port=config.get("port", 3001),
                pin=config.get("pin", ""),
                encryption_key=config.get(
                    "encryption_key", config.get("encryptionKey", "")
                ),
                serial=config.get("serial"),
                username=config.get("username", ""),
                password=config.get("password", ""),
            )
        else:
            self.config = config

        # Connection state
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._receive_buffer = bytearray()

        # Event listeners for COS events
        self._event_listeners: list[Callable[[bytes], Coroutine[Any, Any, None]]] = []

        # Encryption keys
        self._initial_key = make_encryption_key(self.config.encryption_key)
        self._serial_bytes: bytes | None = None
        self._session_key: bytes | None = None

        # Panel info
        self._panel_model: str | None = None
        self._panel_name: str | None = None
        self._firmware_version: str | None = None
        self._protocol_version: int | None = None
        self._encryption_mode: int | None = None  # 1=AES-128, 2=AES-256, 5=PBKDF2+AES-256

        # Monitoring state
        self._monitoring_active = False
        self._processing_cos = False
        self._valid_area_numbers: list[int] | None = None
        self._zone_areas: dict[int, list[int]] = {}

        # Keep-alive task
        self._keepalive_task: asyncio.Task[None] | None = None
        self._keepalive_failures: int = 0
        self._max_keepalive_failures: int = 3  # Trigger connection lost after 3 failures

        # Connection lost callbacks
        self._on_connection_lost: list[Callable[[], Coroutine[Any, Any, None] | None]] = []

        # Background reader task - single reader that fans out messages
        self._reader_task: asyncio.Task[None] | None = None
        self._reader_should_run: bool = False  # Controls reader loop, separate from monitoring_active
        # Pending response future - commands wait on this for their response
        self._pending_response: asyncio.Future[bytes] | None = None
        # Command queue lock - ensures control operations are serialized
        # This prevents conflicts when:
        # 1. The same entity can only have one active control session
        # 2. Requests don't have unique IDs, so responses must be sequential
        self._command_lock: asyncio.Lock = asyncio.Lock()
        self._command_lock_depth: ContextVar[int] = ContextVar(
            "aritech_command_lock_depth", default=0
        )

    @property
    def panel_model(self) -> str | None:
        """Panel model (e.g., 'ATS1500')."""
        return self._panel_model

    @property
    def panel_name(self) -> str | None:
        """Panel name configured in the panel."""
        return self._panel_name

    @property
    def firmware_version(self) -> str | None:
        """Panel firmware version."""
        return self._firmware_version

    @property
    def is_connected(self) -> bool:
        """Check if connected to panel."""
        return self._writer is not None and not self._writer.is_closing()

    @property
    def max_area_count(self) -> int:
        """Maximum number of areas for this panel model."""
        return MODEL_AREAS.get(self._panel_model or "", 4)

    @property
    def max_zone_count(self) -> int:
        """Maximum number of zones for this panel model."""
        return MODEL_ZONES.get(self._panel_model or "", 240)

    @property
    def is_x700_panel(self) -> bool:
        """Check if this is an x700 series panel.

        x700 panels (ATS1700, ATS3700, ATS4700) use different message formats.
        """
        return bool(self._panel_model and re.match(r"ATS\d700", self._panel_model))

    @property
    def uses_pbkdf2(self) -> bool:
        """Check if this panel uses PBKDF2 key derivation.

        Encryption mode 5 uses PBKDF2 + AES-256 with 32-byte session keys.
        Other modes (1, 2) use grayPack key derivation with 16-byte session keys.
        """
        return self._encryption_mode == 5

    async def __aenter__(self) -> AritechClient:
        """Async context manager entry."""
        await self.connect()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Async context manager exit."""
        await self.disconnect()

    async def connect(self) -> None:
        """Connect to the panel."""
        logger.debug(f"Connecting to {self.config.host}:{self.config.port}...")

        try:
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.config.host, self.config.port),
                timeout=10.0,
            )
            logger.debug("Socket connected")
        except asyncio.TimeoutError as e:
            raise AritechError(
                "Connection timeout", code=ErrorCode.CONNECTION_FAILED
            ) from e
        except OSError as e:
            raise AritechError(
                f"Connection failed: {e}", code=ErrorCode.CONNECTION_FAILED
            ) from e

    async def disconnect(self) -> None:
        """Disconnect from the panel gracefully."""
        if not self._writer:
            return

        # Stop keep-alive
        self._stop_keepalive()

        try:
            if self._session_key:
                logger.debug("Sending logout...")
                msg = construct_message("logout", {})
                await self._call_encrypted(msg, self._session_key)
                self._session_key = None
        except Exception as e:
            logger.debug(f"Disconnect message failed: {e}")

        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None

        logger.debug("Disconnected from panel")

    async def initialize(self) -> None:
        """
        Initialize the connection.

        Performs description query, key exchange, and login.
        """
        await self.get_description()
        await self._change_session_key()
        await self._login()
        self._start_keepalive()

    async def get_description(self) -> dict[str, Any]:
        """Get panel description (unencrypted)."""
        logger.debug("Getting panel description...")

        msg = construct_message("getDeviceInfo", {})
        decoded = await self._call_plain(msg)
        payload = decoded[:-2]  # Strip CRC

        # Parse panel info
        try:
            self._panel_name = get_property("deviceDescription", payload, "deviceName")
            product_name = get_property("deviceDescription", payload, "productName")
            match = re.search(r"ATS\d+", product_name or "")
            if match:
                self._panel_model = match.group(0)

            self._firmware_version = get_property(
                "deviceDescription", payload, "firmwareVersion"
            )
            if self._firmware_version:
                self._protocol_version = calculate_protocol_version(
                    self._firmware_version
                )

            serial = get_property("deviceDescription", payload, "serialNumber")
            if serial and re.match(r"^[A-Za-z0-9_+-]{16}$", serial):
                self.config.serial = serial
                self._serial_bytes = decode_serial(serial)

            # Encryption mode - byte 79 from start of response
            # Mode 1/2: grayPack + AES-128/192/256 with 16-byte session key
            # Mode 5: PBKDF2 + AES-256 with 32-byte session key
            if len(payload) > 79:
                self._encryption_mode = payload[79]

            logger.debug(f"Panel: {self._panel_name or 'unknown'}")
            logger.debug(f"Model: {self._panel_model or 'unknown'}")
            logger.debug(f"Firmware: {self._firmware_version or 'unknown'}")
            logger.debug(f"Encryption mode: {self._encryption_mode}")
        except Exception as e:
            logger.debug(f"Could not parse panel description: {e}")

        # Encryption mode 5 uses PBKDF2 key derivation with AES-256
        # Other modes (1, 2) use grayPack with AES-128/192/256
        if self.uses_pbkdf2:
            logger.debug(
                f"Encryption mode {self._encryption_mode} - using PBKDF2 key derivation (AES-256)"
            )
            self._initial_key = make_encryption_key_pbkdf2(self.config.encryption_key)
            logger.debug(f"New initial key (32 bytes): {self._initial_key.hex()}")

        return {
            "panelName": self._panel_name,
            "panelModel": self._panel_model,
            "serial": self.config.serial,
            "firmwareVersion": self._firmware_version,
            "protocolVersion": self._protocol_version,
            "encryptionMode": self._encryption_mode,
        }

    async def _change_session_key(self) -> None:
        """Perform key exchange."""
        logger.debug("Starting key exchange...")
        logger.debug(f"Initial key: {self._initial_key.hex()}")

        # 1. Send createSession with client key contribution
        # PBKDF2 mode (5): 16-byte client key → 32-byte session key (AES-256)
        # Other modes: 8-byte client key + 8-byte padding → 16-byte session key (AES-128)
        if self.uses_pbkdf2:
            client_key = bytes(16)
            begin_payload = construct_message(
                "createSession",
                {"typeId": 0x09, "data": client_key},  # PBKDF2: full 16 bytes
            )
        else:
            client_key = bytes(8)
            begin_payload = construct_message(
                "createSession",
                {"typeId": 0x09, "data": client_key + bytes(8)},  # grayPack: 8-byte key + 8-byte padding
            )

        logger.debug("Sending createSession...")
        begin_response = await self._call_encrypted(begin_payload, self._initial_key)
        if not begin_response:
            raise AritechError(
                "Failed to decrypt createSession response",
                code=ErrorCode.KEY_EXCHANGE_FAILED,
            )

        # 2. Extract panel's key contribution and build session key
        # Response format: [0xA0 header][0x00 0x09 msgId + data][panel key bytes]
        if self.uses_pbkdf2:
            # PBKDF2 mode: extract 16-byte panel key, build 32-byte session key
            panel_key = begin_response[3:19]
            logger.debug(f"Panel key bytes (16): {panel_key.hex()}")
            self._session_key = client_key + panel_key
            logger.debug(f"Session key (32 bytes): {self._session_key.hex()}")
        else:
            # grayPack mode: extract 8-byte panel key, build 16-byte session key
            panel_key = begin_response[3:11]
            logger.debug(f"Panel key bytes (8): {panel_key.hex()}")
            self._session_key = client_key + panel_key
            logger.debug(f"Session key (16 bytes): {self._session_key.hex()}")

        # 3. Send enableEncryptionKey (still with initial key)
        end_payload = construct_message("enableEncryptionKey", {"typeId": 0x00})
        end_response = await self._call_encrypted(end_payload, self._initial_key)
        if not end_response:
            raise AritechError(
                "Failed to decrypt enableEncryptionKey response",
                code=ErrorCode.KEY_EXCHANGE_FAILED,
            )

        logger.debug("Key exchange complete")

    async def _login(self, login_type: int = LoginType.USER) -> None:
        """Login - auto-selects method based on config.

        Uses loginWithAccount if username is configured, otherwise loginWithPin.

        Args:
            login_type: Login type from LoginType enum (USER or INSTALLER).
        """
        if self.config.username:
            await self._login_with_account(login_type)
        else:
            await self._login_with_pin(login_type)

    async def _login_with_pin(self, login_type: int = LoginType.USER) -> None:
        """Login with PIN (x500 panels).

        Args:
            login_type: Login type from LoginType enum (USER or INSTALLER).
        """
        logger.debug(f"Logging in with PIN: {self.config.pin}")

        login_payload = construct_message(
            "loginWithPin",
            {
                "canUpload": True,
                "canDownload": False,
                "canControl": True,
                "canMonitor": True,
                "canDiagnose": True,
                "canReadLogs": True,
                "pinCode": self.config.pin,
                "connectionMethod": login_type,
            },
        )

        response = await self._call_encrypted(login_payload, self._session_key)
        if not response:
            raise AritechError("Login failed - no response", code=ErrorCode.LOGIN_FAILED)

        # Check response: a0 00 00 means success (header + msgId 0 + status 0)
        if (
            len(response) >= 3
            and response[0] == HEADER_RESPONSE
            and response[2] == 0x00
        ):
            logger.debug("Login successful")
            self._start_keepalive()
            return

        # Login failed
        status_code = response[2] if len(response) >= 3 else 0xFF
        raise AritechError(
            f"Login failed - status code 0x{status_code:02x}",
            code=ErrorCode.LOGIN_FAILED,
            status=status_code,
        )

    async def _login_with_account(self, login_type: int = LoginType.USER) -> None:
        """Login with username/password (x700 panels).

        Args:
            login_type: Login type from LoginType enum (USER or INSTALLER).
        """
        logger.debug(f"Logging in with username: {self.config.username}")

        # Default password to username if not set
        password = self.config.password or self.config.username

        # All permissions set to true except canDownload (matches mobile app for zone control)
        login_payload = construct_message(
            "loginWithAccount",
            {
                "canUpload": True,
                "canDownload": False,
                "canControl": True,
                "canMonitor": True,
                "canDiagnose": True,
                "canReadLogs": True,
                "username": self.config.username,
                "password": password,
                "connectionMethod": login_type,
            },
        )

        response = await self._call_encrypted(login_payload, self._session_key)
        if not response:
            raise AritechError("Login failed - no response", code=ErrorCode.LOGIN_FAILED)

        # Check response: a0 00 00 means success (header + msgId 0 + status 0)
        if (
            len(response) >= 3
            and response[0] == HEADER_RESPONSE
            and response[2] == 0x00
        ):
            logger.debug("Login successful")

            # x700 panels require getUserInfo call after login to activate session permissions
            await self._get_user_info()

            self._start_keepalive()
            return

        # Login failed
        status_code = response[2] if len(response) >= 3 else 0xFF
        raise AritechError(
            f"Login failed - status code 0x{status_code:02x}",
            code=ErrorCode.LOGIN_FAILED,
            status=status_code,
        )

    async def _get_user_info(self) -> None:
        """Get user info from panel - required on x700 after login to activate permissions."""
        logger.debug("Getting user info...")
        payload = construct_message("getUserInfo", {})
        response = await self._call_encrypted(payload, self._session_key)

        if response and response[0] == HEADER_RESPONSE:
            # Response contains user name at offset 6, 16 bytes
            if len(response) >= 22:
                user_name = (
                    response[6:22].decode("ascii", errors="ignore").rstrip("\x00").strip()
                )
                if user_name:
                    logger.debug(f"Logged in as: {user_name}")
            logger.debug("User session activated")

    def _start_keepalive(self) -> None:
        """Start keep-alive task."""
        if self._keepalive_task:
            return

        self._keepalive_failures = 0

        async def keepalive() -> None:
            try:
                while True:
                    try:
                        await asyncio.sleep(30)
                        if self._session_key and self._writer:
                            msg = construct_message("ping", {})
                            await self._call_encrypted(msg, self._session_key)
                            # Successful ping, reset failure counter
                            self._keepalive_failures = 0
                        else:
                            # No session/writer, stop keepalive
                            logger.debug("Keep-alive stopping: no session/writer")
                            await self._emit_connection_lost()
                            break
                    except asyncio.CancelledError:
                        # Task was cancelled, exit cleanly
                        raise
                    except Exception as e:
                        self._keepalive_failures += 1
                        logger.warning(
                            f"Keep-alive failed ({self._keepalive_failures}/{self._max_keepalive_failures}): {e}"
                        )
                        if self._keepalive_failures >= self._max_keepalive_failures:
                            logger.error(
                                f"Connection lost: {self._keepalive_failures} consecutive keep-alive failures"
                            )
                            await self._emit_connection_lost()
                            break
            finally:
                # Clear task reference so _start_keepalive can restart on reconnect
                self._keepalive_task = None

        self._keepalive_task = asyncio.create_task(keepalive())

    def _stop_keepalive(self) -> None:
        """Stop keep-alive task."""
        if self._keepalive_task:
            self._keepalive_task.cancel()
            self._keepalive_task = None

    def start_background_reader(self) -> None:
        """Start background reader task that fans out all incoming messages."""
        if self._reader_task:
            return

        self._reader_should_run = True

        async def reader_loop() -> None:
            """
            Single reader that handles ALL incoming frames.

            - COS events → queued and processed via callbacks
            - Command responses → delivered to waiting command via Future
            """
            logger.debug("Background reader started")
            frame_count = 0

            try:
                while self._reader_should_run and self._reader and self._session_key:
                    try:
                        # Read next frame (with timeout so we can check loop condition)
                        frame = await self._read_frame_direct(timeout=1.0)

                        frame_count += 1
                        logger.debug(f"Background reader got frame #{frame_count}: {len(frame)} bytes")

                        # Check if it's an unsolicited message (COS or other panel notification)
                        if self._is_unsolicited_message(frame):
                            logger.debug("  -> Unsolicited message, processing...")
                            await self._handle_unsolicited_frame(frame)
                        else:
                            # It's a command response - deliver to waiting command
                            logger.debug("  -> Command response")
                            if self._pending_response and not self._pending_response.done():
                                self._pending_response.set_result(frame)
                            else:
                                # No one waiting - this shouldn't happen normally
                                logger.debug("  -> No pending command, discarding")

                    except asyncio.TimeoutError:
                        # No data available, continue polling
                        continue
                    except asyncio.CancelledError:
                        # Task was cancelled, propagate through finally
                        raise
                    except AritechError as e:
                        # Connection lost or other protocol error - fail pending commands and exit
                        logger.error(f"Background reader error: {e}")
                        if self._pending_response and not self._pending_response.done():
                            self._pending_response.set_exception(e)
                        await self._emit_connection_lost()
                        break
                    except Exception as e:
                        logger.debug(f"Background reader unexpected error: {e}")
                        await asyncio.sleep(0.1)
            finally:
                # Clear state so commands don't route to dead reader and restarts are possible
                logger.debug(f"Background reader stopped (read {frame_count} frames)")
                self._reader_task = None
                self._reader_should_run = False
                self._monitoring_active = False

        self._reader_task = asyncio.create_task(reader_loop())

    async def _read_frame_direct(self, timeout: float = 5.0) -> bytes:
        """Read a single SLIP frame directly from socket (no fan-out logic).

        Raises:
            AritechError: If connection is closed (EOF) or not connected
            asyncio.TimeoutError: If timeout expires before a complete frame
        """
        if not self._reader:
            raise AritechError("Not connected", code=ErrorCode.CONNECTION_FAILED)

        end_time = asyncio.get_event_loop().time() + timeout

        while True:
            # Check for complete frame in buffer
            if SLIP_END in self._receive_buffer:
                start = 0
                if self._receive_buffer[0] == SLIP_END:
                    start = 1
                end = self._receive_buffer.index(SLIP_END, start)
                if end > start:
                    frame = bytes(self._receive_buffer[: end + 1])
                    del self._receive_buffer[: end + 1]
                    return frame
                del self._receive_buffer[: end + 1]

            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise asyncio.TimeoutError()

            try:
                data = await asyncio.wait_for(
                    self._reader.read(1024), timeout=min(remaining, 0.5)
                )
                if not data:
                    # EOF - connection closed by remote
                    raise AritechError(
                        "Connection closed by panel", code=ErrorCode.CONNECTION_FAILED
                    )
                self._receive_buffer.extend(data)
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= end_time:
                    raise
                # Short timeout for responsiveness, continue

    def _is_unsolicited_message(self, frame: bytes) -> bool:
        """
        Check if frame is an unsolicited message from the panel.

        Unsolicited messages have header 0xC0 (request from panel to client).
        Responses have header 0xA0, errors have 0xF0.

        Returns True if the message is unsolicited and should NOT be treated as a response.
        """
        if not self._session_key:
            return False

        try:
            decrypted = decrypt_message(frame, self._session_key, self._serial_bytes)
            if not decrypted or len(decrypted) < 2:
                return False

            # Check if this is an unsolicited message (header 0xC0 = request from panel)
            return decrypted[0] == HEADER_REQUEST
        except Exception:
            return False

    async def _send_cos_ack(self) -> None:
        """Send COS acknowledgment to the panel.

        Format: a0 00 01 01 (response header 0xA0, msgId 0, ack bytes)
        Bypasses command lock to avoid being delayed by in-flight commands.
        """
        ack_payload = bytes([0xA0, 0x00, 0x01, 0x01])
        try:
            await self.send_encrypted(ack_payload, self._session_key, bypass_lock=True)
        except Exception as e:
            logger.debug(f"Failed to send COS ACK: {e}")

    async def _handle_unsolicited_frame(self, frame: bytes) -> None:
        """
        Process an unsolicited message from the panel.

        If it's a COS message (0xCA prefix), sends ACK and spawns listener tasks.
        Otherwise, logs a warning about unhandled unsolicited message.
        """
        try:
            decrypted = decrypt_message(frame, self._session_key, self._serial_bytes)
            if not decrypted or len(decrypted) < 2:
                return

            # Check if it's a COS message (0xCA prefix = COS message type)
            if decrypted[1] == 0xCA:
                cos_type = decrypted[2] if len(decrypted) >= 3 else 0
                payload = decrypted[3:]  # Skip C0 CA XX
                status_byte = payload[2] if len(payload) >= 3 else None

                status_val = status_byte if status_byte is not None else 0
                logger.debug(
                    f"COS event received: type=0x{cos_type:02x}, "
                    f"status=0x{status_val:02x}"
                )

                # Send ACK immediately to prevent panel retransmits
                await self._send_cos_ack()

                # Spawn listener tasks - don't await them!
                # This prevents deadlock: listeners may send commands that need
                # responses from the background reader, so we can't block here.
                for listener in self._event_listeners:
                    asyncio.create_task(
                        self._run_cos_listener(listener, status_byte, payload)
                    )
            else:
                # Unsolicited message but not a COS - log it
                msg_id_byte = decrypted[1]
                logger.warning(
                    f"Received unsolicited message from panel (no handler): "
                    f"msgId=0x{msg_id_byte:02x}, data={decrypted.hex()}"
                )

        except Exception as e:
            logger.error(f"Error handling unsolicited frame: {e}")

    async def _run_cos_listener(
        self,
        listener: Callable[[int | None, bytes], Coroutine[Any, Any, None]],
        status_byte: int | None,
        payload: bytes,
    ) -> None:
        """Run a COS listener in a separate task with error handling."""
        try:
            await listener(status_byte, payload)
        except Exception as e:
            logger.error(f"Error in COS listener: {e}")

    async def _handle_cos_inline(self, decrypted: bytes) -> None:
        """
        Handle a COS message that arrived during a request/response cycle.

        Sends ACK and spawns listener tasks to prevent deadlock.
        """
        if len(decrypted) < 3:
            return

        cos_type = decrypted[2]
        payload = decrypted[3:]  # Skip C0 CA XX
        status_byte = payload[2] if len(payload) >= 3 else None

        status_val = status_byte if status_byte is not None else 0
        logger.debug(
            f"COS inline: type=0x{cos_type:02x}, status=0x{status_val:02x}"
        )

        # Send ACK immediately to prevent panel retransmits
        await self._send_cos_ack()

        # Spawn listener tasks (don't await to prevent deadlock)
        for listener in self._event_listeners:
            asyncio.create_task(
                self._run_cos_listener(listener, status_byte, payload)
            )

    def stop_background_reader(self) -> None:
        """Stop background reader task."""
        self._reader_should_run = False
        if self._reader_task:
            self._reader_task.cancel()
            self._reader_task = None

    @asynccontextmanager
    async def _with_command_lock(self) -> AsyncIterator[None]:
        """Re-entrant lock guard to serialize command traffic."""
        depth = self._command_lock_depth.get()
        if depth > 0:
            token = self._command_lock_depth.set(depth + 1)
            try:
                yield
            finally:
                self._command_lock_depth.reset(token)
            return

        await self._command_lock.acquire()
        token = self._command_lock_depth.set(1)
        try:
            yield
        finally:
            self._command_lock_depth.reset(token)
            self._command_lock.release()

    # ========================================================================
    # Low-level communication
    # ========================================================================

    @property
    def session_key(self) -> bytes | None:
        """Session key for encrypted communication."""
        return self._session_key

    @property
    def monitoring_active(self) -> bool:
        """Whether monitoring mode is active."""
        return self._monitoring_active

    @monitoring_active.setter
    def monitoring_active(self, value: bool) -> None:
        """Set monitoring mode state."""
        self._monitoring_active = value

    def on_cos_event(
        self, callback: Callable[[int | None, bytes], Coroutine[Any, Any, None]]
    ) -> None:
        """Register a callback for COS (Change of Status) events."""
        self._event_listeners.append(callback)

    def on_connection_lost(
        self, callback: Callable[[], Coroutine[Any, Any, None] | None]
    ) -> None:
        """Register a callback for connection lost events.

        Called when the client detects the connection has been lost
        (e.g., after multiple consecutive keep-alive failures).
        """
        self._on_connection_lost.append(callback)

    async def _emit_connection_lost(self) -> None:
        """Emit connection lost event to all registered callbacks."""
        for callback in self._on_connection_lost:
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.error(f"Error in connection lost callback: {e}")

    async def _send_raw(self, data: bytes) -> None:
        """Send raw bytes."""
        if not self._writer:
            raise AritechError("Not connected", code=ErrorCode.CONNECTION_FAILED)
        self._writer.write(data)
        await self._writer.drain()

    async def _receive_frame(self, timeout: float = 5.0) -> bytes:
        """Receive a SLIP frame."""
        if not self._reader:
            raise AritechError("Not connected", code=ErrorCode.CONNECTION_FAILED)

        # If background reader is active, wait for it to deliver the response
        if self._monitoring_active and self._reader_task:
            return await self._receive_frame_via_reader(timeout)

        # Otherwise read directly (used during initialization before monitoring starts)
        return await self._receive_frame_direct(timeout)

    async def _receive_frame_via_reader(self, timeout: float) -> bytes:
        """Wait for background reader to deliver a response frame."""
        # Future should be created by caller before sending
        if not self._pending_response:
            raise AritechError("No pending response future", code=ErrorCode.PROTOCOL_ERROR)

        try:
            frame = await asyncio.wait_for(self._pending_response, timeout=timeout)
            return frame
        except asyncio.TimeoutError:
            raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)
        finally:
            self._pending_response = None

    async def _receive_frame_direct(self, timeout: float) -> bytes:
        """Read a SLIP frame directly (when monitoring not active)."""
        end_time = asyncio.get_event_loop().time() + timeout

        while True:
            # Check for complete frame in buffer
            if SLIP_END in self._receive_buffer:
                start = 0
                if self._receive_buffer[0] == SLIP_END:
                    start = 1
                end = self._receive_buffer.index(SLIP_END, start)
                if end > start:
                    frame = bytes(self._receive_buffer[: end + 1])
                    del self._receive_buffer[: end + 1]
                    return frame
                del self._receive_buffer[: end + 1]

            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)

            try:
                data = await asyncio.wait_for(
                    self._reader.read(1024), timeout=min(remaining, 0.5)
                )
                if not data:
                    raise AritechError(
                        "Connection closed", code=ErrorCode.CONNECTION_FAILED
                    )
                self._receive_buffer.extend(data)
            except asyncio.TimeoutError:
                if asyncio.get_event_loop().time() >= end_time:
                    raise AritechError("Receive timeout", code=ErrorCode.TIMEOUT)

    async def send_encrypted(
        self, payload: bytes, key: bytes | None = None, *, bypass_lock: bool = False
    ) -> None:
        """Send an encrypted message without waiting for response.

        Args:
            payload: The message payload to send
            key: Encryption key (defaults to session key)
            bypass_lock: If True, skip the command lock. Use for time-critical
                messages like COS acknowledgments that shouldn't be delayed
                by in-flight commands.
        """
        if key is None:
            key = self._session_key
        if not key or not self._serial_bytes:
            raise AritechError("No encryption key", code=ErrorCode.PROTOCOL_ERROR)

        encrypted = encrypt_message(payload, key, self._serial_bytes)
        frame = slip_encode(encrypted)

        if bypass_lock:
            logger.debug(f"TX (enc, no-wait, no-lock): {frame.hex()}")
            await self._send_raw(frame)
        else:
            async with self._with_command_lock():
                logger.debug(f"TX (enc, no-wait): {frame.hex()}")
                await self._send_raw(frame)

    async def _call_plain(self, payload: bytes) -> bytes:
        """Send unencrypted message and receive response."""
        with_crc = append_crc(payload)
        frame = slip_encode(with_crc)

        async with self._with_command_lock():
            logger.debug(f"TX (plain): {frame.hex()}")
            await self._send_raw(frame)

            response = await self._receive_frame()
        logger.debug(f"RX (plain): {response.hex()}")

        decoded = slip_decode(response)
        if not verify_crc(decoded):
            raise AritechError("CRC error", code=ErrorCode.CRC_ERROR)

        return decoded

    async def _call_encrypted(
        self, payload: bytes, key: bytes | None = None, raise_on_error: bool = True
    ) -> bytes | None:
        """Send encrypted message and receive response."""
        if key is None:
            key = self._session_key
        if not key or not self._serial_bytes:
            raise AritechError("No encryption key", code=ErrorCode.PROTOCOL_ERROR)

        encrypted = encrypt_message(payload, key, self._serial_bytes)
        frame = slip_encode(encrypted)

        async with self._with_command_lock():
            use_background_reader = self._monitoring_active and self._reader_task
            try:
                # Create Future BEFORE sending so fast responses aren't lost
                if use_background_reader:
                    self._pending_response = asyncio.get_running_loop().create_future()

                logger.debug(f"TX (enc): {frame.hex()}")
                await self._send_raw(frame)

                if use_background_reader:
                    # Background reader filters COS messages via _handle_unsolicited_frame,
                    # so we only receive command responses here - no loop needed
                    response = await self._receive_frame()
                    logger.debug(f"RX (enc): {response.hex()}")
                else:
                    # Direct reading - unsolicited messages (header 0xC0) can arrive
                    # interleaved with responses, so we must handle them and keep waiting
                    max_unsolicited_reads = 5
                    for _ in range(max_unsolicited_reads):
                        response = await self._receive_frame()
                        logger.debug(f"RX (enc): {response.hex()}")

                        decrypted = decrypt_message(response, key, self._serial_bytes)
                        # Check for unsolicited message (header 0xC0 = request from panel)
                        if (
                            decrypted
                            and len(decrypted) >= 2
                            and decrypted[0] == HEADER_REQUEST
                        ):
                            # Handle unsolicited message and continue waiting for response
                            if decrypted[1] == 0xCA:
                                logger.debug("Received COS during request, handling and waiting for response")
                                await self._handle_cos_inline(decrypted)
                            else:
                                # Non-COS unsolicited message - log and skip
                                logger.warning(
                                    f"Received unsolicited message during request: "
                                    f"msgId=0x{decrypted[1]:02x}, skipping"
                                )
                            continue
                        # Got a response (header 0xA0 or 0xF0), break out
                        break
                    else:
                        # Loop exhausted without getting a real response - raise error
                        raise AritechError(
                            "Too many unsolicited messages received while waiting for response",
                            code=ErrorCode.PROTOCOL_ERROR,
                        )

            except Exception:
                if self._pending_response and not self._pending_response.done():
                    self._pending_response = None
                raise

        decrypted = decrypt_message(response, key, self._serial_bytes)
        if not decrypted:
            # Check for error response
            decoded = slip_decode(response)
            if decoded and decoded[0] == HEADER_ERROR and raise_on_error:
                error_code = decoded[1] if len(decoded) > 1 else 0
                raise AritechError(
                    f"Panel error: 0x{error_code:02x}",
                    code=ErrorCode.PANEL_ERROR,
                    panel_error=error_code,
                )
            return None

        # Check for error in decrypted response
        if raise_on_error:
            err = check_response_error(decrypted)
            if err is not None:
                raise AritechError(
                    f"Panel error: 0x{err:02x}",
                    code=ErrorCode.PANEL_ERROR,
                    panel_error=err,
                )

        return decrypted

    async def call_encrypted(
        self, payload: bytes, key: bytes | None = None, raise_on_error: bool = True
    ) -> bytes | None:
        """
        Public method to send encrypted message and receive response.

        Used by AritechMonitor for COS handling. This delegates to the internal
        method which handles pausing the background reader.
        """
        return await self._call_encrypted(payload, key, raise_on_error)

    # ========================================================================
    # Generic name fetching helper
    # ========================================================================

    async def _get_names(
        self,
        msg_name: str,
        response_name: str,
        entity_name: str,
        *,
        max_count: int | None = None,
        valid_numbers: list[int] | None = None,
    ) -> list[NamedItem]:
        """
        Generic helper for fetching entity names from the panel.

        Handles pagination in batches (16 for x500, 4 for x700).

        Args:
            msg_name: Message name for the request (e.g., 'getAreaNames')
            response_name: Response message name (e.g., 'areaNames')
            entity_name: Entity type name for logging (e.g., 'Area')
            max_count: Maximum entity count (stops pagination)
            valid_numbers: Only include these entity numbers

        Returns:
            List of NamedItem objects
        """
        logger.debug(f"Querying {entity_name} names...")

        results: list[NamedItem] = []

        # Use extended format parameters if applicable
        # x700 panels and x500 panels with protocol 4.4+ use "Ext" format for areas and zones
        # (30-byte names, 4 per page). Outputs and triggers use the standard format.
        supports_extended = self.is_x700_panel or (
            self._protocol_version and self._protocol_version >= 4004
        )
        has_extended_format = supports_extended and msg_name in (
            "getAreaNames",
            "getZoneNames",
        )

        if has_extended_format:
            name_length = EXTENDED_NAME_LENGTH
            names_per_page = EXTENDED_NAMES_PER_PAGE
            actual_msg_name = msg_name + "Extended"
            logger.debug(
                f"Using extended format: {actual_msg_name}, "
                f"{name_length}-byte names, {names_per_page} per page"
            )
        else:
            name_length = NAME_LENGTH
            names_per_page = NAMES_PER_PAGE
            actual_msg_name = msg_name

        # Determine which pages to request
        pages_to_request: list[int] = []
        if valid_numbers:
            # Only request pages containing valid numbers
            page_set: set[int] = set()
            for num in valid_numbers:
                page_start = ((num - 1) // names_per_page) * names_per_page + 1
                page_set.add(page_start)
            pages_to_request = sorted(page_set)
        elif max_count:
            # Request pages up to max_count
            pages_to_request = list(range(1, max_count + 1, names_per_page))
        else:
            # Request pages until empty (output/trigger style)
            pages_to_request = list(range(1, 257, names_per_page))

        for start_index in pages_to_request:
            payload = construct_message(actual_msg_name, {"index": start_index})
            response = await self._call_encrypted(payload, self._session_key)

            if not response:
                logger.debug(f"No response for {entity_name} page at {start_index}")
                if not max_count and not valid_numbers:
                    break  # Stop pagination on no response
                continue

            if response[0] == HEADER_RESPONSE and is_message_type(
                response, response_name, 1
            ):
                found_any = False

                for i in range(names_per_page):
                    offset = NAMES_START_OFFSET + i * name_length
                    if offset + name_length > len(response):
                        break

                    entity_num = start_index + i
                    if max_count and entity_num > max_count:
                        break

                    name_bytes = response[offset : offset + name_length]
                    name = (
                        name_bytes.decode("ascii", errors="ignore")
                        .rstrip("\x00")
                        .strip()
                    )

                    if name:
                        # Filter by valid_numbers if provided
                        if not valid_numbers or entity_num in valid_numbers:
                            results.append(NamedItem(number=entity_num, name=name))
                            found_any = True

                # Stop pagination if no entities found and not using valid_numbers/max_count
                if not found_any and not valid_numbers and not max_count:
                    logger.debug(
                        f"No {entity_name}s found at index {start_index}, stopping"
                    )
                    break
            else:
                logger.debug(f"Unexpected response format for {entity_name} page")
                if not max_count and not valid_numbers:
                    break

        logger.debug(f"Found {len(results)} {entity_name}s")
        return results

    # ========================================================================
    # Control session helper
    # ========================================================================

    @asynccontextmanager
    async def _with_control_session(
        self,
        create_msg_name: str,
        create_props: dict[str, Any],
        entity_type: str,
        entity_id: int,
    ) -> AsyncIterator[int]:
        """
        Async context manager for control session operations.

        Creates a control session, yields the session ID, and ensures
        cleanup (destroyControlSession) runs even on failure.

        Uses a lock to serialize all control operations, preventing conflicts when:
        1. The same entity can only have one active control session
        2. Requests don't have unique IDs, so responses must be sequential

        Args:
            create_msg_name: Message name for creating the session
            create_props: Properties for the create message
            entity_type: Entity type for error messages (e.g., 'zone')
            entity_id: Entity ID for error messages

        Yields:
            The session ID for use in action commands

        Raises:
            AritechError: If session creation fails
        """
        async with self._with_command_lock():
            create_payload = construct_message(create_msg_name, create_props)
            response = await self._call_encrypted(create_payload, self._session_key)

            cc = parse_create_cc_response(response)
            if not cc:
                raise AritechError(
                    f"Failed to create control context for {entity_type} {entity_id}",
                    code=ErrorCode.CREATE_CC_FAILED,
                )

            session_id = cc["sessionId"]
            try:
                yield session_id
            finally:
                await self._call_encrypted(
                    construct_message("destroyControlSession", {"sessionId": session_id}),
                    self._session_key,
                    raise_on_error=False,
                )

    # ========================================================================
    # Area operations
    # ========================================================================

    async def get_area_names(self) -> list[NamedItem]:
        """Get area names from the panel."""
        return await self._get_names(
            "getAreaNames",
            "areaNames",
            "Area",
            max_count=self.max_area_count,
        )

    async def get_area_states(
        self, area_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get area states."""
        if area_numbers is None:
            area_numbers = list(range(1, self.max_area_count + 1))

        if not area_numbers:
            return []

        # Use batch request for efficiency
        payload = build_batch_stat_request("AREA", area_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "areaStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = AreaState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def get_valid_areas(self) -> list[int]:
        """Get list of valid/configured area numbers. Uses cached value if available.

        x700 panels don't support getValidAreas - use all areas 1-N based on panel model.
        """
        # Return cached value if available
        if self._valid_area_numbers is not None:
            logger.debug(f"Using cached valid areas: {self._valid_area_numbers}")
            return self._valid_area_numbers

        logger.debug("Querying valid area numbers...")

        # x700 panels don't support getValidAreas command - use all areas based on model
        if self.is_x700_panel:
            max_areas = self.max_area_count
            valid_areas = list(range(1, max_areas + 1))
            logger.debug(f"x700 panel: using all {max_areas} areas: {valid_areas}")
            self._valid_area_numbers = valid_areas
            return valid_areas

        payload = construct_message("getValidAreas", {})
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 3:
            return list(range(1, self.max_area_count + 1))

        if response[0] == HEADER_RESPONSE and is_message_type(
            response, "validAreas", 1
        ):
            # Parse bitmask - skip a0 1b 02 (header + msgId + typeId)
            bitset = response[3:]
            valid: list[int] = []
            for byte_idx, byte in enumerate(bitset):
                for bit in range(8):
                    if byte & (1 << bit):
                        valid.append(byte_idx * 8 + bit + 1)
            self._valid_area_numbers = valid
            return valid

        return list(range(1, self.max_area_count + 1))

    # ========================================================================
    # Zone operations
    # ========================================================================

    async def get_zone_names(self) -> list[NamedItem]:
        """Get zone names from the panel."""
        # First, get the list of valid zones from the panel
        valid_zone_numbers = await self.get_valid_zone_numbers()

        return await self._get_names(
            "getZoneNames",
            "zoneNames",
            "Zone",
            valid_numbers=valid_zone_numbers,
        )

    async def get_valid_zone_numbers(self) -> list[int] | None:
        """
        Get list of valid/configured zone numbers from the panel.

        This method also populates the zone-to-areas mapping (self._zone_areas),
        which maps each zone number to the list of areas it belongs to.

        Returns:
            List of valid zone numbers, or None if query fails
        """
        logger.debug("Querying valid zone numbers...")

        # Get valid areas first (from cache or query)
        if self._valid_area_numbers is None:
            self._valid_area_numbers = await self.get_valid_areas()

        valid_areas = self._valid_area_numbers
        if not valid_areas:
            logger.debug("No valid areas found")
            return None

        # Build batch request - one getZonesAssignedToAreas per area
        requests: list[bytes] = []
        for i, area_num in enumerate(valid_areas):
            msg = build_get_valid_zones_message([area_num])
            # Strip header for batch
            without_header = msg[1:]
            # Separator is the message length (0x0c = 12 bytes for getZonesAssignedToAreas)
            separator = len(without_header)
            # Add separator between requests (not after last one)
            if i < len(valid_areas) - 1:
                requests.append(without_header + bytes([separator]))
            else:
                requests.append(without_header)

        # Send batch request
        batch_msg = construct_message("batch", {})
        length_byte = bytes([0x0C])  # getZonesAssignedToAreas messages are 12 bytes
        payload = batch_msg + length_byte + b"".join(requests)

        logger.debug(f"Zone batch payload ({len(payload)} bytes)")
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            logger.debug("No valid batch response for zones")
            return await self._get_valid_zone_numbers_individual(valid_areas)

        # Response format: a0 [ee ee 20] [response1] [20] [response2] [20] ... [responseN]
        # 0x20 is the msgId for zonesAssignedToAreas
        if response[1] != 0xEE or response[2] != 0xEE or response[3] != 0x20:
            logger.debug(f"Unexpected response format: {response[:4].hex()}, falling back")
            return await self._get_valid_zone_numbers_individual(valid_areas)

        # Reset zone-to-areas mapping
        self._zone_areas = {}
        valid_zones_set: set[int] = set()

        # Each zone response is 32 bytes: 20 0a [30 bytes bitset]
        # Plus 0x20 separator between responses (not after last)
        ZONE_RESPONSE_LEN = 32
        offset = 4  # Skip a0 ee ee 20 header

        for i, area_num in enumerate(valid_areas):
            is_last = i == len(valid_areas) - 1
            response_len = ZONE_RESPONSE_LEN if is_last else ZONE_RESPONSE_LEN + 1

            if offset + ZONE_RESPONSE_LEN > len(response):
                logger.debug(f"Not enough data at offset {offset} for area {area_num}")
                break

            zone_response = response[offset : offset + ZONE_RESPONSE_LEN]
            offset += response_len

            # Parse: 20 0a [bitset...]
            if zone_response[0] != 0x20:
                logger.debug(
                    f"Unexpected zone response format for area {area_num}: {zone_response[:4].hex()}"
                )
                continue

            bitset_start = 2  # Skip 20 0a
            bitset = zone_response[bitset_start:]

            for byte_idx, byte_val in enumerate(bitset):
                for bit in range(8):
                    if byte_val & (1 << bit):
                        zone_num = byte_idx * 8 + bit + 1
                        valid_zones_set.add(zone_num)

                        # Add this area to zone's area list
                        if zone_num not in self._zone_areas:
                            self._zone_areas[zone_num] = []
                        self._zone_areas[zone_num].append(area_num)

        valid_zones = sorted(valid_zones_set)
        logger.debug(f"Found {len(valid_zones)} valid zones")
        logger.debug(f"Zone-to-areas mapping: {len(self._zone_areas)} entries")
        return valid_zones

    async def _get_valid_zone_numbers_individual(
        self, valid_areas: list[int]
    ) -> list[int] | None:
        """
        Fallback: query zones for each area individually (slower but more compatible).

        Args:
            valid_areas: List of valid area numbers

        Returns:
            List of valid zone numbers
        """
        logger.debug("Using individual zone queries (fallback)")

        self._zone_areas = {}
        valid_zones_set: set[int] = set()

        for area_num in valid_areas:
            payload = build_get_valid_zones_message([area_num])
            response = await self._call_encrypted(payload, self._session_key)

            if not response:
                logger.debug(f"No response for area {area_num}")
                continue

            if response[0] == HEADER_RESPONSE and is_message_type(
                response, "zonesAssignedToAreas", 1
            ):
                bitset_start = 3  # Skip a0 20 0a
                bitset = response[bitset_start:]

                for byte_idx, byte_val in enumerate(bitset):
                    for bit in range(8):
                        if byte_val & (1 << bit):
                            zone_num = byte_idx * 8 + bit + 1
                            valid_zones_set.add(zone_num)

                            if zone_num not in self._zone_areas:
                                self._zone_areas[zone_num] = []
                            self._zone_areas[zone_num].append(area_num)

        valid_zones = sorted(valid_zones_set)
        logger.debug(f"Found {len(valid_zones)} valid zones")
        return valid_zones

    def get_zone_areas(self, zone_num: int) -> list[int] | None:
        """
        Get the areas a zone belongs to.

        Args:
            zone_num: Zone number

        Returns:
            List of area numbers, or None if unknown
        """
        return self._zone_areas.get(zone_num)

    async def _get_zone_area_props(self, zone_num: int) -> dict[str, bool]:
        """
        Build area props dict for createZoneControlSession based on zone's assigned areas.

        Args:
            zone_num: Zone number

        Returns:
            Dictionary with area.N: True for each area the zone belongs to
        """
        # If zone-to-areas mapping is empty, populate it first
        if not self._zone_areas:
            logger.debug("Zone-to-areas mapping empty, querying...")
            await self.get_valid_zone_numbers()

        areas = self.get_zone_areas(zone_num)
        if areas:
            props = {f"area.{area_num}": True for area_num in areas}
            logger.debug(f"Zone {zone_num} is in areas: {areas}")
            return props

        # Fallback to all valid areas if zone mapping unknown
        if self._valid_area_numbers:
            props = {f"area.{area_num}": True for area_num in self._valid_area_numbers}
            logger.debug(
                f"Zone {zone_num} area unknown, using all valid areas: {self._valid_area_numbers}"
            )
            return props

        # Last resort fallback
        logger.debug(f"Zone {zone_num} area unknown, falling back to area 1")
        return {"area.1": True}

    async def get_zone_states(
        self, zone_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get zone states using batch request."""
        if zone_numbers is None:
            zone_numbers = list(range(1, min(24, self.max_zone_count) + 1))

        if not zone_numbers:
            return []

        payload = build_batch_stat_request("ZONE", zone_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            logger.debug("No valid batch response, falling back to individual queries")
            return await self._get_zone_states_individual(zone_numbers)

        messages = split_batch_response(response, "zoneStatus")

        if not messages:
            logger.debug("No messages parsed from batch, falling back to individual queries")
            return await self._get_zone_states_individual(zone_numbers)

        results: list[StateResult] = []

        for msg in messages:
            state = ZoneState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def _get_zone_states_individual(
        self, zone_numbers: list[int]
    ) -> list[StateResult]:
        """
        Get zone states individually (fallback when batch fails).

        Args:
            zone_numbers: List of zone numbers to query

        Returns:
            List of zone state results
        """
        logger.debug("Using individual zone state queries")
        results: list[StateResult] = []

        for zone_num in zone_numbers:
            # Build individual getZoneStatus request
            payload = bytes([0xC0]) + build_get_stat_request("ZONE", zone_num, False)
            response = await self._call_encrypted(payload, self._session_key)

            if response and len(response) >= 7 and response[4] == zone_num:
                state = ZoneState.from_bytes(response)
                results.append(
                    StateResult(
                        number=zone_num,
                        state=state,
                        raw_hex=response.hex(),
                    )
                )

        return results

    async def inhibit_zone(self, zone_num: int) -> None:
        """Inhibit a zone."""
        logger.debug(f"Inhibiting zone {zone_num}...")

        area_props = await self._get_zone_area_props(zone_num)
        async with self._with_control_session(
            "createZoneControlSession", area_props, "zone", zone_num
        ) as session_id:
            payload = construct_message(
                "inhibitZone", {"sessionId": session_id, "objectId": zone_num}
            )
            response = await self._call_encrypted(
                payload, self._session_key, raise_on_error=False
            )

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to inhibit zone {zone_num}",
                    code=ErrorCode.ZONE_INHIBIT_FAILED,
                )

            logger.debug(f"Zone {zone_num} inhibited")

    async def uninhibit_zone(self, zone_num: int) -> None:
        """Uninhibit a zone."""
        logger.debug(f"Uninhibiting zone {zone_num}...")

        area_props = await self._get_zone_area_props(zone_num)
        async with self._with_control_session(
            "createZoneControlSession", area_props, "zone", zone_num
        ) as session_id:
            payload = construct_message(
                "uninhibitZone", {"sessionId": session_id, "objectId": zone_num}
            )
            response = await self._call_encrypted(
                payload, self._session_key, raise_on_error=False
            )

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to uninhibit zone {zone_num}",
                    code=ErrorCode.ZONE_UNINHIBIT_FAILED,
                )

            logger.debug(f"Zone {zone_num} uninhibited")

    # ========================================================================
    # Output operations
    # ========================================================================

    async def get_output_names(self) -> list[NamedItem]:
        """Get output names from the panel."""
        return await self._get_names("getOutputNames", "outputNames", "Output")

    async def get_output_states(
        self, output_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get output states."""
        if output_numbers is None:
            output_numbers = list(range(1, 9))

        if not output_numbers:
            return []

        payload = build_batch_stat_request("OUTPUT", output_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "outputStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = OutputState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def force_activate_output(self, output_num: int) -> None:
        """
        Force activate an output (override to ON state).

        This sets the output to active and marks it as overridden.
        Use cancel_force_output() to remove the override and return to normal state.
        """
        logger.debug(f"Force activating output {output_num}...")

        async with self._with_control_session(
            "createOutputControlSession", {"area.1": True}, "output", output_num
        ) as session_id:
            payload = construct_message(
                "forceActivateOutput", {"sessionId": session_id, "objectId": output_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to force activate output {output_num}",
                    code=ErrorCode.OUTPUT_ACTIVATE_FAILED,
                )

            logger.debug(f"Output {output_num} force activated")

    async def force_deactivate_output(self, output_num: int) -> None:
        """
        Force deactivate an output (override to OFF state).

        This sets the output to inactive and marks it as overridden.
        Use cancel_force_output() to remove the override and return to normal state.
        """
        logger.debug(f"Force deactivating output {output_num}...")

        async with self._with_control_session(
            "createOutputControlSession", {"area.1": True}, "output", output_num
        ) as session_id:
            payload = construct_message(
                "forceDeactivateOutput", {"sessionId": session_id, "objectId": output_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to force deactivate output {output_num}",
                    code=ErrorCode.OUTPUT_DEACTIVATE_FAILED,
                )

            logger.debug(f"Output {output_num} force deactivated")

    async def cancel_force_output(self, output_num: int) -> None:
        """
        Cancel force status on an output (remove override).

        This removes the override flag and returns the output to its normal
        programmed state.
        """
        logger.debug(f"Canceling force on output {output_num}...")

        async with self._with_control_session(
            "createOutputControlSession", {"area.1": True}, "output", output_num
        ) as session_id:
            payload = construct_message(
                "cancelForceOutput", {"sessionId": session_id, "objectId": output_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to cancel force on output {output_num}",
                    code=ErrorCode.OUTPUT_CANCEL_FORCE_FAILED,
                )

            logger.debug(f"Output {output_num} force canceled")

    # ========================================================================
    # Trigger operations
    # ========================================================================

    async def get_trigger_names(self) -> list[NamedItem]:
        """Get trigger names from the panel."""
        return await self._get_names("getTriggerNames", "triggerNames", "Trigger")

    async def get_trigger_states(
        self, trigger_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get trigger states."""
        if trigger_numbers is None:
            trigger_numbers = list(range(1, 9))

        if not trigger_numbers:
            return []

        payload = build_batch_stat_request("TRIGGER", trigger_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "triggerStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = TriggerState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def activate_trigger(self, trigger_num: int) -> None:
        """Activate a trigger."""
        logger.debug(f"Activating trigger {trigger_num}...")

        async with self._with_control_session(
            "createTriggerControlSession", {}, "trigger", trigger_num
        ) as session_id:
            payload = construct_message(
                "activateTrigger", {"sessionId": session_id, "objectId": trigger_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to activate trigger {trigger_num}",
                    code=ErrorCode.TRIGGER_ACTIVATE_FAILED,
                )

            logger.debug(f"Trigger {trigger_num} activated")

    async def deactivate_trigger(self, trigger_num: int) -> None:
        """Deactivate a trigger."""
        logger.debug(f"Deactivating trigger {trigger_num}...")

        async with self._with_control_session(
            "createTriggerControlSession", {}, "trigger", trigger_num
        ) as session_id:
            payload = construct_message(
                "deactivateTrigger", {"sessionId": session_id, "objectId": trigger_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            if parse_return_bool(response) is not True:
                raise AritechError(
                    f"Failed to deactivate trigger {trigger_num}",
                    code=ErrorCode.TRIGGER_DEACTIVATE_FAILED,
                )

            logger.debug(f"Trigger {trigger_num} deactivated")

    # ========================================================================
    # Door methods
    # ========================================================================

    async def get_door_names(self) -> list[NamedItem]:
        """Get door names from the panel."""
        return await self._get_names("getDoorNames", "doorNames", "Door")

    async def get_valid_door_numbers(self) -> list[int]:
        """Get valid door numbers from the panel."""
        logger.debug("Querying valid door numbers...")

        payload = construct_message("getValidDoors", {})
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        # Parse bitmask response - doors are in bytes starting at offset 2
        valid_doors: list[int] = []
        for byte_idx in range(2, len(response)):
            byte_val = response[byte_idx]
            for bit in range(8):
                if byte_val & (1 << bit):
                    door_num = (byte_idx - 2) * 8 + bit + 1
                    valid_doors.append(door_num)

        logger.debug(f"Found {len(valid_doors)} valid doors: {valid_doors}")
        return valid_doors

    async def get_door_states(
        self, door_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get door states."""
        if door_numbers is None:
            door_numbers = list(range(1, 9))

        if not door_numbers:
            return []

        payload = build_batch_stat_request("DOOR", door_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "doorStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = DoorState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    # ========================================================================
    # FILTER METHODS
    # ========================================================================

    async def get_filter_names(self) -> list[NamedItem]:
        """Get filter names from the panel."""
        return await self._get_names("getFilterNames", "filterNames", "Filter")

    async def get_filter_states(
        self, filter_numbers: list[int] | None = None
    ) -> list[StateResult]:
        """Get filter states.

        Filters are read-only entities with a simple on/off (active/inactive) state.

        Args:
            filter_numbers: List of filter numbers to query. Defaults to 1-64.

        Returns:
            List of StateResult objects with FilterState.
        """
        if filter_numbers is None:
            filter_numbers = list(range(1, 65))

        if not filter_numbers:
            return []

        payload = build_batch_stat_request("FILTER", filter_numbers)
        response = await self._call_encrypted(payload, self._session_key)

        if not response or len(response) < 4:
            return []

        messages = split_batch_response(response, "filterStatus")
        results: list[StateResult] = []

        for msg in messages:
            state = FilterState.from_bytes(msg["bytes"])
            results.append(
                StateResult(
                    number=msg["objectId"],
                    state=state,
                    raw_hex=msg["bytes"].hex(),
                )
            )

        return results

    async def lock_door(self, door_num: int) -> dict[str, Any]:
        """Lock a door."""
        logger.debug(f"Locking door {door_num}...")

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "lockDoor", {"sessionId": session_id, "objectId": door_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            # Door commands return a0000100 for success (boolean 0x00 = no error)
            # Error responses have 0xF0 header which check_response_error will throw on
            check_response_error(response)
            logger.debug(f"Door {door_num} locked")

        return {"skipped": False}

    async def unlock_door(self, door_num: int) -> dict[str, Any]:
        """Unlock a door indefinitely."""
        logger.debug(f"Unlocking door {door_num}...")

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "unlockDoor", {"sessionId": session_id, "objectId": door_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            check_response_error(response)
            logger.debug(f"Door {door_num} unlocked")

        return {"skipped": False}

    async def unlock_door_standard_time(self, door_num: int) -> dict[str, Any]:
        """Unlock a door for the door's configured standard time."""
        logger.debug(f"Unlocking door {door_num} (standard time)...")

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "unlockDoorStandardTime", {"sessionId": session_id, "objectId": door_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            check_response_error(response)
            logger.debug(f"Door {door_num} unlocked (standard time)")

        return {"skipped": False}

    async def unlock_door_time(self, door_num: int, seconds: int) -> dict[str, Any]:
        """Unlock a door for a specified time."""
        logger.debug(f"Unlocking door {door_num} for {seconds}s...")

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "unlockDoorTime",
                {"sessionId": session_id, "objectId": door_num, "timeOpen": seconds},
            )
            response = await self._call_encrypted(payload, self._session_key)

            check_response_error(response)
            logger.debug(f"Door {door_num} unlocked for {seconds}s")

        return {"skipped": False}

    async def disable_door(self, door_num: int) -> dict[str, Any]:
        """Disable a door."""
        logger.debug(f"Disabling door {door_num}...")

        # Check current state first
        states = await self.get_door_states([door_num])
        if states and states[0].state.is_disabled:
            logger.debug(f"Door {door_num} is already disabled, skipping")
            return {"skipped": True, "reason": "already disabled"}

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "disableDoor", {"sessionId": session_id, "objectId": door_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            check_response_error(response)
            logger.debug(f"Door {door_num} disabled")

        return {"skipped": False}

    async def enable_door(self, door_num: int) -> dict[str, Any]:
        """Enable a door."""
        logger.debug(f"Enabling door {door_num}...")

        # Check current state first
        states = await self.get_door_states([door_num])
        if states and not states[0].state.is_disabled:
            logger.debug(f"Door {door_num} is already enabled, skipping")
            return {"skipped": True, "reason": "already enabled"}

        async with self._with_control_session(
            "createDoorControlSession", {}, "door", door_num
        ) as session_id:
            payload = construct_message(
                "enableDoor", {"sessionId": session_id, "objectId": door_num}
            )
            response = await self._call_encrypted(payload, self._session_key)

            check_response_error(response)
            logger.debug(f"Door {door_num} enabled")

        return {"skipped": False}

    # ========================================================================
    # Arm/Disarm operations
    # ========================================================================

    async def arm_area(
        self, areas: int | list[int], set_type: str = "full", force: bool = False
    ) -> None:
        """
        Arm one or more areas.

        Args:
            areas: Area number(s) to arm - single int or list of ints
            set_type: Arm type ('full', 'part1', 'part2')
            force: Force arm despite faults
        """
        async with self._with_command_lock():
            await self._arm_area_impl(areas, set_type, force)

    async def _arm_area_impl(
        self, areas: int | list[int], set_type: str = "full", force: bool = False
    ) -> None:
        """Internal implementation of arm_area (called with lock held)."""
        area_list = areas if isinstance(areas, list) else [areas]
        logger.debug(f"Arming area(s) {area_list} ({set_type}, force={force})...")

        # Map set_type to create message name
        create_messages = {
            "full": "createArmSession",
            "part1": "createPartArmSession",
            "part2": "createPartArm2Session",
        }
        create_msg_name = create_messages.get(set_type.lower(), "createArmSession")

        # Status mappings per set type
        success_statuses = {
            "full": [CC_STATUS["FullSetSetting"], CC_STATUS["FullSetSet"]],
            "part1": [CC_STATUS["PartSetSetting"], CC_STATUS["PartSetSet"]],
            "part2": [CC_STATUS["PartSet2Setting"], CC_STATUS["PartSet2Set"]],
        }
        fault_statuses = {
            "full": CC_STATUS["FullSetFault"],
            "part1": CC_STATUS["PartSetFault"],
            "part2": CC_STATUS["PartSet2Fault"],
        }
        active_statuses = {
            "full": CC_STATUS["FullSetActiveStates"],
            "part1": CC_STATUS["PartSetActiveStates"],
            "part2": CC_STATUS["PartSet2ActiveStates"],
        }
        inhibited_statuses = {
            "full": CC_STATUS["FullSetInhibited"],
            "part1": CC_STATUS["PartSetInhibited"],
            "part2": CC_STATUS["PartSet2Inhibited"],
        }

        # Step 1: Create control context
        area_props = {f"area.{area_num}": True for area_num in area_list}
        create_payload = construct_message(create_msg_name, area_props)
        logger.debug(f"Step 1: Sending {create_msg_name}")
        response = await self._call_encrypted(create_payload, self._session_key)

        cc = parse_create_cc_response(response)
        if not cc:
            raise AritechError(
                f"Failed to create control context for area(s) {area_list}",
                code=ErrorCode.CREATE_CC_FAILED,
            )

        session_id = cc["sessionId"]
        logger.debug(f"createArmSession succeeded, sessionId: 0x{session_id:x}")

        try:
            # Step 2: Start arm procedure
            logger.debug("Step 2: Starting arm procedure (armAreas)")
            arm_payload = construct_message("armAreas", {"sessionId": session_id})
            await self._call_encrypted(arm_payload, self._session_key, raise_on_error=False)
            logger.debug("armAreas sent")

            # Step 3: Poll status and handle force scenarios
            forced_once = False
            polls_after_force = 0
            last_status = 0

            for i in range(60):
                if i > 0:
                    await asyncio.sleep(0.3)

                # Read status
                status_payload = construct_message(
                    "getControlSessionStatus", {"sessionId": session_id}
                )
                status_response = await self._call_encrypted(
                    status_payload, self._session_key, raise_on_error=False
                )

                if not status_response or len(status_response) < 5:
                    logger.debug(f"Poll {i + 1}: Invalid response")
                    continue

                # Check if this is actually a controlSessionStatus (msgId 0x20)
                if not is_message_type(status_response, "controlSessionStatus", 1):
                    logger.debug(
                        f"Poll {i + 1}: Got different message (0x{status_response[1]:02x}), retrying..."
                    )
                    continue

                # Parse stateId (16-bit big-endian at bytes 2-3 after header)
                state_id = get_property(
                    "controlSessionStatus", status_response[1:], "stateId"
                )
                last_status = state_id
                logger.debug(f"Poll {i + 1}: Status 0x{state_id:04x}")

                # Check for success (Setting or Set)
                if state_id in success_statuses.get(set_type.lower(), []):
                    logger.debug(f"Arm operation complete - status: 0x{state_id:04x}")
                    return  # Success

                # Handle fault status
                if state_id == fault_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Fault detected, forcing arm...")
                        forced_once = True
                        polls_after_force = 0
                        force_payload = construct_message(
                            "setAreaForced", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            force_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - faults still present after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read fault zones and throw
                    faults = await self._read_arm_issues(session_id, "getFaultZones")
                    raise AritechError(
                        "Arm failed - zone faults detected",
                        code=ErrorCode.ARM_FAULTS,
                        status=state_id,
                        details={"faults": faults},
                    )

                # Handle active states status
                if state_id == active_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Active zones detected, forcing arm...")
                        forced_once = True
                        polls_after_force = 0
                        force_payload = construct_message(
                            "setAreaForced", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            force_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - active zones still present after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read active zones and throw
                    active_zones = await self._read_arm_issues(
                        session_id, "getActiveZones"
                    )
                    raise AritechError(
                        "Arm failed - active zones detected",
                        code=ErrorCode.ARM_ACTIVE_ZONES,
                        status=state_id,
                        details={"activeZones": active_zones},
                    )

                # Handle inhibited status
                if state_id == inhibited_statuses.get(set_type.lower()):
                    if not forced_once and force:
                        logger.debug("Inhibited zones detected, re-sending set command...")
                        forced_once = True
                        polls_after_force = 0
                        # For inhibited, re-send armAreas (not setAreaForced)
                        re_set_payload = construct_message(
                            "armAreas", {"sessionId": session_id}
                        )
                        await self._call_encrypted(
                            re_set_payload, self._session_key, raise_on_error=False
                        )
                        continue
                    if forced_once:
                        polls_after_force += 1
                        if polls_after_force >= 10:
                            raise AritechError(
                                "Force arm failed - inhibited zones still blocking after forcing",
                                code=ErrorCode.FORCE_ARM_FAILED,
                                status=state_id,
                            )
                        continue
                    # Read inhibited zones and throw
                    inhibited_zones = await self._read_arm_issues(
                        session_id, "getInhibitedZones"
                    )
                    raise AritechError(
                        "Arm failed - inhibited zones detected",
                        code=ErrorCode.ARM_INHIBITED,
                        status=state_id,
                        details={"inhibitedZones": inhibited_zones},
                    )

            # If we get here, polling timed out without success or clear failure
            raise AritechError(
                "Arm operation timed out",
                code=ErrorCode.ARM_FAILED,
                status=last_status,
            )

        finally:
            # Step 4: Cleanup - always destroy control context
            logger.debug("Step 4: Cleanup control context...")
            await self._call_encrypted(
                construct_message("destroyControlSession", {"sessionId": session_id}),
                self._session_key,
                raise_on_error=False,
            )
            logger.debug("Cleanup complete")

    async def _read_arm_issues(
        self, session_id: int, message_name: str
    ) -> list[dict[str, Any]]:
        """
        Read fault/active/inhibited zones during arm procedure.

        Args:
            session_id: Control session ID
            message_name: Message to send ('getFaultZones', 'getActiveZones', 'getInhibitedZones')

        Returns:
            List of issue dictionaries with raw data
        """
        issues: list[dict[str, Any]] = []
        next_val = 0

        for i in range(100):  # Safety limit
            payload = construct_message(
                message_name, {"sessionId": session_id, "next": next_val}
            )
            try:
                response = await self._call_encrypted(
                    payload, self._session_key, raise_on_error=False
                )
            except AritechError as err:
                # Panel may return error when no issues to report
                logger.debug(f"{message_name}: {err}")
                break

            if not response or len(response) < 3:
                break

            # Check if response is booleanResponse (end of list)
            if is_message_type(response, "booleanResponse", 1):
                break

            # Parse zone info from response
            if len(response) >= 5:
                issues.append({"raw": response.hex(), "index": i})

            next_val = 1  # Continue reading

        logger.debug(f"Read {len(issues)} {message_name} zones")
        return issues

    async def disarm_area(self, area_num: int) -> None:
        """Disarm an area."""
        async with self._with_command_lock():
            await self._disarm_area_impl(area_num)

    async def _disarm_area_impl(self, area_num: int) -> None:
        """Internal implementation of disarm_area (called with lock held)."""
        logger.debug(f"Disarming area {area_num}...")

        create_payload = construct_message(
            "createDisarmSession", {f"area.{area_num}": True}
        )
        response = await self._call_encrypted(create_payload, self._session_key)

        cc = parse_create_cc_response(response)
        if not cc:
            raise AritechError(
                f"Failed to create control context for area {area_num}",
                code=ErrorCode.CREATE_CC_FAILED,
            )

        session_id = cc["sessionId"]

        try:
            disarm_payload = construct_message(
                "disarmAreas", {"sessionId": session_id}
            )
            await self._call_encrypted(disarm_payload, self._session_key, raise_on_error=False)

            logger.debug(f"Area {area_num} disarmed")
        finally:
            await self._call_encrypted(
                construct_message("destroyControlSession", {"sessionId": session_id}),
                self._session_key,
                raise_on_error=False,
            )

    # ========================================================================
    # Event log operations
    # ========================================================================

    async def read_event_log(
        self, max_events: int = 100
    ) -> AsyncIterator["ParsedEvent"]:
        """
        Read events from the panel event log.

        This is an async generator that yields parsed events.

        Args:
            max_events: Maximum number of events to read (0 for unlimited)

        Yields:
            Parsed event dictionaries
        """
        from .event_parser import parse_event

        logger.debug("Reading event log...")

        # x700 panels and x500 panels with protocol 4.4+ use 60-byte events
        # Older x500 panels use 70-byte events
        is_x700 = self.is_x700_panel
        is_extended_protocol = self._protocol_version and self._protocol_version >= 4004
        event_size = 60 if (is_x700 or is_extended_protocol) else 70

        if is_x700:
            # x700 requires startMonitor first
            start_payload = construct_message("startMonitor", {})
            start_response = await self._call_encrypted(start_payload, self._session_key)
            if start_response:
                logger.debug(f"startMonitor response: {start_response.hex()}")

        # Open the log
        open_payload = construct_message("openLog", {})
        init_response = await self._call_encrypted(open_payload, self._session_key)
        if init_response:
            logger.debug(f"openLog response: {init_response.hex()}")

        event_count = 0
        direction = EVENT_LOG_FIRST
        last_sequence = None
        consecutive_errors = 0
        max_consecutive_errors = 3

        while max_events == 0 or event_count < max_events:
            payload = build_get_event_log_message(direction)

            try:
                response = await self._call_encrypted(payload, self._session_key)

                if not response:
                    logger.debug("No response received")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        logger.debug("Max consecutive errors reached, stopping")
                        break
                    continue

                # Check for logEntry response (msgId 0x0D at byte 1)
                if not is_message_type(response, "logEntry", 1):
                    # Check for ack response (can happen as async COS message)
                    if len(response) > 1 and response[1] == 0x00:
                        logger.debug("Received ack, continuing...")
                        continue
                    logger.debug(
                        f"Unexpected response: {response[:10].hex() if response else 'empty'}"
                    )
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    continue

                # Response payload starts at offset 2 (after header + msgId)
                event_data = response[2:]

                if len(event_data) < event_size:
                    logger.debug(
                        f"Event data too short: {len(event_data)} bytes (expected {event_size})"
                    )
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break
                    continue

                # Parse the event (60 bytes for x700, 70 bytes for x500)
                try:
                    event_buffer = event_data[:event_size]
                    parsed_event = parse_event(event_buffer)

                    # Use parsed sequence for end detection
                    sequence = parsed_event.sequence

                    # Check for end of log - when sequence wraps or stays at 0
                    if last_sequence is not None and last_sequence == 0 and sequence == 0:
                        logger.debug("Reached end of event log (oldest event)")
                        break

                    event_count += 1
                    consecutive_errors = 0
                    last_sequence = sequence

                    yield parsed_event

                except Exception as parse_error:
                    logger.debug(f"Failed to parse event: {parse_error}")
                    logger.debug(f"Raw event data: {event_data[:event_size].hex()}")
                    consecutive_errors += 1
                    if consecutive_errors >= max_consecutive_errors:
                        break

                # After first request, switch to "next" direction
                direction = EVENT_LOG_NEXT

            except Exception as err:
                logger.debug(f"Error reading event: {err}")
                consecutive_errors += 1
                if consecutive_errors >= max_consecutive_errors:
                    logger.debug("Max errors reached, stopping event log read")
                    break
