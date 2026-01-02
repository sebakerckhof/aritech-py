# Aritech Client for Python (Unofficial)

An unofficial, community-developed async Python client to monitor and control KGS (formerly UTC and Carrier) Aritech alarm panels over your local network.

**This project is not affiliated with, endorsed by, or supported by KGS, UTC, Carrier, or any of their subsidiaries.**

## Compatibility

This library supports the ACE 2 ATS version 6 protocol, which works with Advisor Advanced panels:

- **x500 panels**: ATS1500A, ATS2000A, ATS3500A, ATS4500A (PIN-based login, AES-192)
- **x700 (everon) panels**: ATS1500A-IP-MM, ATS3500A-IP-MM, ATS4500A-IP-MM (username/password login, AES-256)

The older version 4 protocol for Master/Classic panels is not supported.

Note that protocol behavior may vary based on panel firmware version. This library has been tested with a limited set of panels. If you encounter issues, please mention your panel model and firmware version when reporting.

## Requirements

- Python 3.11 or higher
- pycryptodome

## Installation

```bash
pip install aritech-client
```

Or install from source:

```bash
cd aritech-py
pip install -e .
```

## Configuration

Create a `config.json` in the current directory or `~/.aritech/config.json` based on your panel type:

**For x500 panels (ATS1500A, ATS2000A, ATS3500A, ATS4500A):**

Copy `config.x500.json.example` to `config.json` and edit with your settings:

```json
{
  "host": "192.168.1.100",
  "port": 3001,
  "pin": "1234",
  "encryptionKey": "your-24-char-encryption-key"
}
```

**For x700 panels (ATS1500A-IP-MM, ATS3500A-IP-MM, ATS4500A-IP-MM):**

Copy `config.x700.json.example` to `config.json` and edit with your settings:

```json
{
  "host": "192.168.1.100",
  "port": 3001,
  "username": "ADMIN",
  "password": "SECRET",
  "encryptionKey": "your-48-char-encryption-key"
}
```

Note: x700 panels use AES-256 (48-char key) while x500 panels use AES-192 (24-char key).

## CLI Usage

```bash
aritech-cli --help
```

Or run directly with Python:

```bash
python -m aritech_client.cli --help
```

For troubleshooting, enable debug logging:

```bash
LOG_LEVEL=debug aritech-cli zones
# or
aritech-cli --debug zones
```

Note: Debug logs may contain sensitive information such as your PIN code.

### Commands

```
Available commands:
  aritech-cli info                         - Show panel description info
  aritech-cli monitor                      - Start monitoring mode (COS events)
  aritech-cli arm [area] [type] [--force]  - Arm area (default: area 1, type full)
                                             Types: full, part1, part2
                                             --force: Force arm despite faults/active zones
  aritech-cli disarm [area]                - Disarm area (default: 1)
  aritech-cli zones                        - Show zone states
  aritech-cli areas                        - Show area states
  aritech-cli outputs                      - Show output names and states
  aritech-cli triggers                     - Show trigger names and states
  aritech-cli inhibit <zone>               - Inhibit a zone
  aritech-cli uninhibit <zone>             - Uninhibit a zone
  aritech-cli activate <output>            - Activate an output
  aritech-cli deactivate <output>          - Deactivate an output
  aritech-cli trigger-activate <trigger>   - Activate a trigger
  aritech-cli trigger-deactivate <trigger> - Deactivate a trigger
  aritech-cli event-log [count]            - Read event log (default: 50 events)

Configuration options (override config.json):
  --host <ip>              - Panel IP address
  --port <port>            - Panel port number
  --encryptionKey <key>    - Encryption key (24-48 chars)
  --config <path>          - Path to config.json

  x500 panels:
  --pin <pin>              - User PIN code

  x700 panels:
  --username <user>        - Login username
  --password <pwd>         - Login password (defaults to username)

Examples:
  aritech-cli --host 192.168.1.100 --pin 1234 --encryptionKey <key> zones
  aritech-cli --host 192.168.1.100 --username ADMIN --password SECRET --encryptionKey <key> zones
  aritech-cli arm 1 full             - Full arm area 1
  aritech-cli arm 1 part1            - Part arm 1 (set 1)
  aritech-cli arm 2 part2            - Part arm 2 (set 2)
  aritech-cli arm 1 full --force     - Force full arm area 1
  aritech-cli outputs                - Show all outputs with states
  aritech-cli activate 1             - Activate output 1
  aritech-cli triggers               - Show all triggers with states
  aritech-cli trigger-activate 1     - Activate trigger 1
  aritech-cli event-log 50           - Read last 50 events from panel log
```

## Library Usage

The library uses asyncio for all communication with the panel:

```python
import asyncio
from aritech_client import AritechClient, AritechConfig

async def main():
    config = AritechConfig(
        host="192.168.1.100",
        port=3001,
        pin="1234",
        encryption_key="your-24-char-encryption-key",
    )

    async with AritechClient(config) as client:
        await client.initialize()

        # Get zone names and states
        zones = await client.get_zone_names()
        states = await client.get_zone_states([z.number for z in zones])

        for zone in zones:
            state = next((s for s in states if s.number == zone.number), None)
            print(f"Zone {zone.number}: {zone.name} - {state.state if state else 'unknown'}")

        # Arm area 1
        await client.arm_area(1, "full")

        # Disarm area 1
        await client.disarm_area(1)

asyncio.run(main())
```

### Monitoring

```python
import asyncio
from aritech_client import AritechClient, AritechConfig
from aritech_client.monitor import AritechMonitor

async def main():
    config = AritechConfig(
        host="192.168.1.100",
        port=3001,
        pin="1234",
        encryption_key="your-24-char-encryption-key",
    )

    async with AritechClient(config) as client:
        await client.initialize()

        monitor = AritechMonitor(client)

        monitor.on_zone_changed(lambda e: print(f"Zone {e.id} changed: {e.new_data}"))
        monitor.on_area_changed(lambda e: print(f"Area {e.id} changed: {e.new_data}"))
        monitor.on_output_changed(lambda e: print(f"Output {e.id} changed: {e.new_data}"))
        monitor.on_trigger_changed(lambda e: print(f"Trigger {e.id} changed: {e.new_data}"))

        await monitor.start()

        # Keep running until interrupted
        try:
            while monitor.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            monitor.stop()

asyncio.run(main())
```

## Features

### Basic
- Connect to panel and retrieve panel description
- Session key exchange
- Login with PIN code (x500 panels)
- Login with username/password (x700 panels)
- Read event log

### Areas
- Read area names
- Read area status (batched or individual)
- Monitor change events for areas
- Arm / Partial arm / Disarm areas

### Zones
- Read zone names
- Read zone status (batched or individual)
- Monitor change events for zones
- Inhibit / uninhibit zones

### Outputs
- Read output names
- Read output states
- Monitor change events for outputs
- Activate / Deactivate outputs

### Triggers
- Read trigger names
- Read trigger states
- Monitor change events for triggers
- Activate / Deactivate triggers

## API Reference

### AritechClient

Main client class for panel communication.

#### Connection
- `connect()` - Establish TCP connection
- `disconnect()` - Close connection
- `initialize()` - Full initialization (description, key exchange, login)

#### Properties
- `panel_name` - Panel name string
- `panel_model` - Panel model string
- `firmware_version` - Firmware version string
- `max_area_count` - Maximum areas for panel model
- `max_zone_count` - Maximum zones for panel model
- `is_connected` - Connection status

#### Panel Info
- `get_description()` - Get panel name, model, firmware version

#### Areas
- `get_area_names()` - Get list of area names
- `get_area_states(area_numbers)` - Get area states
- `arm_area(areas, set_type, force)` - Arm area(s)
- `disarm_area(areas)` - Disarm area(s)

#### Zones
- `get_zone_names()` - Get list of zone names
- `get_zone_states(zone_numbers)` - Get zone states
- `inhibit_zone(zone)` - Inhibit a zone
- `uninhibit_zone(zone)` - Uninhibit a zone

#### Outputs
- `get_output_names()` - Get list of output names
- `get_output_states(output_numbers)` - Get output states
- `activate_output(output)` - Activate an output
- `deactivate_output(output)` - Deactivate an output

#### Triggers
- `get_trigger_names()` - Get list of trigger names
- `get_trigger_states(trigger_numbers)` - Get trigger states
- `activate_trigger(trigger)` - Activate a trigger
- `deactivate_trigger(trigger)` - Deactivate a trigger

#### Events
- `read_event_log(count)` - Async generator yielding parsed events

## Contributing

Pull requests are welcome. We have no plans to implement additional functionality at this time, but contributions are appreciated.

## Disclaimer

This software is provided "as is" without warranty of any kind. Use at your own risk. The authors are not responsible for any damage or security issues that may arise from using this software.

This is an independent project developed through protocol analysis. It is not based on any proprietary source code or documentation.

## Trademarks

ATS, Advisor, and Aritech are trademarks of KGS Fire & Security. All other trademarks are the property of their respective owners. The use of these trademarks does not imply any affiliation with or endorsement by their owners.

## License

MIT
