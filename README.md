# CANopen Security Lab - Red vs Blue Team Node by Berdiev Sandjar IMS 24

ESP-IDF implementation for thesis: rogue CANopen node detection.

## Hardware

- 3× ESP32 dev boards (any variant with TWAI: ESP32, ESP32-S3, ESP32-C3)
- 2× SN65HVD230 CAN transceiver modules
- 1× 120Ω termination resistor at bus end
- Common GND between all nodes
- Wiring per node:
  - `GPIO16` → CTX (transceiver TXD)
  - `GPIO17` → CRX (transceiver RXD)
  - `3V3`   → VCC
  - `GND`   → GND
- Bus: CAN-H and CAN-L of all transceivers connected together

## Topology

```
              ┌──────────────────┐
              │  Victim Device   │  (real CANopen node)
              │  Node-ID = 0x01  │
              └────────┬─────────┘
                       │  CAN-H/CAN-L  (500 kbps)
   ┌───────────────────┼───────────────────┐
   │                   │                   │
┌──┴──────────┐    ┌───┴────────┐    ┌─────┴──────┐
│ Red ESP32   │    │ Blue ESP32 │    │ Other      │
│ (attacker)  │    │ (IDS)      │    │ legitimate │
│ Node TX     │    │ LISTEN_ONLY│    │ nodes      │
└──┬──────────┘    └─────┬──────┘    └────────────┘
   │ WiFi (hidden)        │ WiFi (SOC)
   ▼                      ▼
[Attacker laptop]    [Defender host + mosquitto]
   192.168.4.x        192.168.1.10:1883
```

## Build

Requires ESP-IDF v5.x.
S
```bash
# Red team
cd red_team_node
idf.py set-target esp32
idf.py build flash monitor

# Blue team (in another terminal / on second ESP32)
cd blue_team_node
idf.py set-target esp32
idf.py build flash monitor
```

Adjust `main/config.h` in each project for your WiFi SSID, MQTT broker IP, and CAN pins.

## Host setup

```bash
# 1. Install mosquitto broker on the defender host
sudo apt install mosquitto mosquitto-clients

# 2. Run the SOC listener (receives alerts from blue node)
pip install paho-mqtt
python host_listener/soc_listener.py

# 3. (Attacker side) On a machine joined to the attacker's hidden WiFi,
#    run a second mosquitto broker on 192.168.4.1, then:
python host_listener/c2_console.py
```

## Attack scenarios supported

| Command          | Effect                                                 |
|------------------|--------------------------------------------------------|
| `emcy_fake`      | One fake EMCY (generic 0x8100 comm error)             |
| `emcy_overvolt`  | One fake EMCY 0x3210 (DC link overvoltage)            |
| `emcy_flood`     | Continuous EMCY at 100 ms intervals                    |
| `stop`           | Stop any active attack                                 |

## Detection rules implemented

| Rule | Description                                                       | Severity |
|------|-------------------------------------------------------------------|----------|
| R1   | EMCY from non-whitelisted Node-ID                                | critical |
| R2   | EMCY rate exceeds threshold (>3/s default)                       | critical |
| R3   | EMCY inter-arrival too short (<50ms default)                     | warning  |
| R4   | Suspicious / reserved emergency error code                       | warning  |
| R5   | Attacker signature in manufacturer-specific bytes                | critical |
| R6   | Legitimate node's heartbeat missing (possible impersonation)     | critical |

## What to evaluate for thesis

- **Detection rate** per attack type
- **Detection latency** (timestamp of fake EMCY  MQTT alert at host)
- **False positive rate** under benign-only traffic
- **Coverage** of CiA 301 EMCY error code ranges
- Impact of bus load on detection accuracy
