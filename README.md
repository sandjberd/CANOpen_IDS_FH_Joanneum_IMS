# CANopen IDS Testbed — Red vs. Blue Team on ESP32

A specification-based intrusion detection system (IDS) for CANopen on embedded
hardware. This repository holds the full implementation for the master's thesis
*A Specification-Based Intrusion Detection System for CANopen Networks on
Embedded Hardware* (Sandjar Berdiev, FH JOANNEUM, IMS 2024).

A red node attacks a CANopen bus across seven service categories, a victim node
runs a CANopen slave stack, and a blue node runs the detection engine in
listen-only mode. A SYSWORXX USB-CAN module records all traffic as an
independent ground truth. Attack commands are delivered off the bus over
Wi-Fi/MQTT, so the detector never sees the control channel.

## Repository structure

| Directory        | Role                                                            |
| ---------------- | -------------------------------------------------------------- |
| `red_team_node`  | Attacker firmware (ESP-IDF, C). Turns MQTT commands into CAN frames. |
| `victim_node`    | CANopen slave stack (ESP-IDF, C). Node-ID `0x01`, the primary target. |
| `blue_team_node` | Detection engine (ESP-IDF, C). TWAI in listen-only mode.       |
| `host_listener`  | Host tools (Python): C2 console, SOC alert listener, software victim. |

## Hardware

- 3× ESP32 dev boards (any variant with a TWAI controller: ESP32, ESP32-S3, ESP32-C3)
- 3× SN65HVD230 CAN transceiver modules
- 1× 120 Ω termination resistor at the bus end
- Common GND between all nodes
- Per-node wiring:
  - `GPIO16` → CTX (transceiver TXD)
  - `GPIO17` → CRX (transceiver RXD)
  - `3V3` → VCC
  - `GND` → GND
- Bus: CAN-H and CAN-L of all transceivers connected together, 500 kbit/s

## Topology

```
              ┌──────────────────┐
              │  Victim node     │  (CANopen slave)
              │  Node-ID = 0x01  │
              └────────┬─────────┘
                       │  CAN-H / CAN-L  (500 kbit/s)
   ┌───────────────────┼───────────────────┐
   │                   │                   │
┌──┴──────────┐   ┌────┴───────┐   ┌───────┴────────┐
│ Red ESP32   │   │ Blue ESP32 │   │ SYSWORXX       │
│ (attacker)  │   │ (IDS)      │   │ USB-CAN        │
│ TX          │   │ LISTEN_ONLY│   │ ground-truth   │
└──┬──────────┘   └─────┬──────┘   └───────┬────────┘
   │ Wi-Fi (off-bus)    │ Wi-Fi (SOC)      │ USB
   ▼                    ▼                  ▼
[C2 console]      [SOC listener + broker]  [Host PC capture]
```

## Configuration and credentials

Each firmware project keeps its parameters in `main/config.h`: Wi-Fi SSID and
password, MQTT broker URI, CAN pins, node IDs, COB-ID bases, and the detection
thresholds. **Do not commit real credentials.** Set `WIFI_SSID`,
`WIFI_PASSWORD`, and `MQTT_BROKER_URI` to placeholders and provide the real
values locally before flashing.

The blue node thresholds (in `blue_team_node/main/config.h`) are the values used
in the thesis evaluation, for example `TPDO1_PERIOD_MS = 100`,
`PDO_EARLY_FACTOR_PCT = 50`, `HEARTBEAT_MIN_INTERVAL_MS = 200`,
`EMCY_RATE_THRESHOLD = 3`, `SDO_RATE_THRESHOLD = 10`,
`BUSLOAD_ID_THRESHOLD = 200`, and `BUSLOAD_TOTAL_THRESHOLD = 1500`.

## Build

Requires ESP-IDF v5.x. Flash each node to its own ESP32:

```bash
# Red team (attacker)
cd red_team_node && idf.py set-target esp32 && idf.py build flash monitor

# Blue team (IDS) — on a second ESP32
cd blue_team_node && idf.py set-target esp32 && idf.py build flash monitor

# Victim — on a third ESP32
cd victim_node && idf.py set-target esp32 && idf.py build flash monitor
```

## Host setup

An MQTT broker (e.g. Mosquitto) runs on the host and connects the red and blue
nodes to the host tools. Point every `MQTT_BROKER_URI` in the firmware and the
`BROKER_HOST` in the Python tools at this broker.

```bash
# 1. start the broker
mosquitto -v

# 2. record blue-node alerts
cd host_listener && python3 soc_listener.py

# 3. drive attacks from the interactive console
python3 c2_console.py
```

`c2_console.py` publishes attack commands to `redteam/cmd`. `soc_listener.py`
subscribes to the blue node's alert and heartbeat topics and logs every
detection event. `victim_node.py` is a software CANopen victim used during
development when no hardware victim is attached.

## MQTT topics

| Topic                | Direction        | Purpose                         |
| -------------------- | ---------------- | ------------------------------- |
| `redteam/cmd`        | host → red node  | attack commands                 |
| `redteam/status`     | red node → host  | attack status feedback          |
| `blueteam/alerts`    | blue node → host | detection alerts                |
| `blueteam/traffic`   | blue node → host | periodic traffic summary        |
| `blueteam/heartbeat` | blue node → host | detector liveness               |

## Attack commands (red node)

Published as the payload on `redteam/cmd`. All seven CANopen service categories
are covered.

| Category                | Command         | Effect                                          |
| ----------------------- | --------------- | ----------------------------------------------- |
| NMT state manipulation  | `nmt_preop`     | Force victim into pre-operational               |
|                         | `nmt_stop`      | Force victim into stopped                       |
|                         | `nmt_reset`     | Reset victim node                               |
| SDO abuse               | `sdo_read_ro`   | Unauthorized read of `0x1017`                   |
|                         | `sdo_write_sp`  | Unauthorized write to `0x6001` setpoint         |
|                         | `sdo_write_ro`  | Write to read-only `0x1017` (refused)           |
|                         | `sdo_flood`     | SDO request flood                               |
| PDO injection           | `pdo_spoof`     | Single spoofed TPDO1 (`0x181`)                  |
|                         | `pdo_flood`     | Continuous PDO injection flood                  |
| Heartbeat manipulation  | `hb_spoof`      | Spoof victim heartbeat with a false state       |
|                         | `hb_ghost`      | Ghost-node heartbeat (`0x77E`, node `0x7E`)     |
| EMCY injection          | `emcy_fake`     | Single fake EMCY, generic comm error `0x8100`   |
|                         | `emcy_overvolt` | Single fake EMCY, overvoltage `0x3210`          |
|                         | `emcy_flood`    | Continuous EMCY flood                           |
| LSS abuse               | `lss_switch`    | Switch to config mode, then set a new node-ID   |
|                         | `lss_bitrate`   | Switch to config mode, then set a new bitrate   |
| Bus-level DoS           | `dos_flood`     | High-priority bus saturation flood on `0x000`   |
| Control                 | `stop`          | Stop the current continuous attack              |

## Detection rules (blue node)

Every rule is grounded either in a clause of CiA 301 / CiA 305 or in an observed
runtime property (timing or rate). Alerts are published on `blueteam/alerts`.

| Rule                   | Service   | Fires when                                          | Source  |
| ---------------------- | --------- | --------------------------------------------------- | ------- |
| `R_NMT_CONTROL`        | NMT       | A valid NMT state command is seen on `0x000`        | CiA 301 |
| `R_NMT_BAD_CS`         | NMT       | NMT frame carries an undefined command specifier    | CiA 301 |
| `R7a_SDO_UNKNOWN_NODE` | SDO       | SDO targets a node-ID outside the whitelist         | CiA 301 |
| `R7b_SDO_ABORT`        | SDO       | Server returns an SDO abort (refused access)        | CiA 301 |
| `R7c_SDO_ACCESS`       | SDO       | Unsolicited SDO read or write during operation      | CiA 301 |
| `R8_SDO_FLOOD`         | SDO       | SDO request rate passes the threshold               | CiA 301 |
| `R_PDO_UNKNOWN_NODE`   | PDO       | PDO carries a node-ID outside the whitelist         | CiA 301 |
| `R_PDO_INJECT`         | PDO       | PDO arrives earlier than half its nominal period    | CiA 301 |
| `R6a_GHOST_NODE`       | Heartbeat | Heartbeat from a node-ID outside the whitelist      | CiA 301 |
| `R6b_HEARTBEAT_SPOOF`  | Heartbeat | Two heartbeats for one node arrive too close        | CiA 301 |
| `R6c_HEARTBEAT_STATE`  | Heartbeat | Heartbeat reports an invalid state byte             | CiA 301 |
| `R6_HEARTBEAT_LOST`    | Heartbeat | Expected heartbeat missing past the timeout         | CiA 301 |
| `R1_UNKNOWN_NODE_EMCY` | EMCY      | EMCY from a node-ID outside the whitelist           | CiA 301 |
| `R2_EMCY_FLOOD`        | EMCY      | EMCY rate passes the threshold                      | CiA 301 |
| `R3_EMCY_TIMING`       | EMCY      | Two EMCY frames arrive closer than the minimum      | CiA 301 |
| `R4_BAD_ERROR_CODE`    | EMCY      | Implausible or reserved emergency error code        | CiA 301 |
| `R5_SIGNATURE_MATCH`   | EMCY      | Attacker signature in the manufacturer bytes        | testbed |
| `R_LSS_ABUSE`          | LSS       | Any LSS master frame during operation               | CiA 305 |
| `R_BUS_FLOOD_ID`       | Bus load  | Frames per single COB-ID pass the threshold         | CiA 301 |
| `R_BUS_FLOOD_TOTAL`    | Bus load  | Total frames per second pass the threshold          | CiA 301 |

`R5_SIGNATURE_MATCH` is a testbed aid: the red node tags its EMCY frames with a
fixed marker so the detector can attribute them during experiments. A real
attacker would not include it, so it is not a general detection mechanism.

## Detector modes

The blue node runs in one of two modes, selected with `ids_set_mode()`
(default: Mode B).

- **Mode A** enables only the transport-layer rules, which judge a frame by its
  identifier, its rate, and the bus load. This approximates a plain CAN IDS.
- **Mode B** adds the CANopen-aware rules, which judge a frame by what it means
  in the protocol.

Running each attack in both modes shows what the CANopen-aware rules add. The
SDO stealth access and the heartbeat spoof are caught only in Mode B.

## Related thesis

Berdiev, S. *A Specification-Based Intrusion Detection System for CANopen
Networks on Embedded Hardware.* Master's thesis, FH JOANNEUM, Master's Degree
Programme IT and Mobile Security, 2026.