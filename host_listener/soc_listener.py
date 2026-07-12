#!/usr/bin/env python3
import argparse
import csv
import json
import os
import signal
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime

import paho.mqtt.client as mqtt

BROKER_HOST = "10.0.0.99"
BROKER_PORT = 1883
ALERT_TOPIC = "blueteam/alerts"
HEARTBEAT_TOPIC = "blueteam/heartbeat"

RULE_CATEGORY = {
    "R1_UNKNOWN_NODE_EMCY": "EMCY injection",
    "R2_EMCY_FLOOD":        "EMCY injection",
    "R3_EMCY_TIMING":       "EMCY injection",
    "R4_BAD_ERROR_CODE":    "EMCY injection",
    "R5_SIGNATURE_MATCH":   "EMCY injection",
    "R6_HEARTBEAT_LOST":    "Heartbeat manipulation",
    "R6a_GHOST_NODE":       "Heartbeat manipulation",
    "R6b_HEARTBEAT_SPOOF":  "Heartbeat manipulation",
    "R6c_HEARTBEAT_STATE":  "Heartbeat manipulation",
    "R_NMT_CONTROL":        "NMT abuse",
    "R_NMT_BAD_CS":         "NMT abuse",
    "R7a_SDO_UNKNOWN_NODE": "SDO abuse",
    "R7b_SDO_ABORT":        "SDO abuse",
    "R7c_SDO_ACCESS":       "SDO abuse",
    "R8_SDO_FLOOD":         "SDO abuse",
    "R_PDO_UNKNOWN_NODE":   "PDO injection",
    "R_PDO_INJECT":         "PDO injection",
    "R_LSS_ABUSE":          "LSS abuse",
    "R_BUS_FLOOD_ID":       "Bus-level DoS",
    "R_BUS_FLOOD_TOTAL":    "Bus-level DoS",
}

CATEGORY_ORDER = [
    "NMT abuse", "SDO abuse", "PDO injection", "Heartbeat manipulation",
    "EMCY injection", "LSS abuse", "Bus-level DoS", "Uncategorised",
]

COLORS = {
    "info":     "\033[36m",
    "warning":  "\033[33m",
    "critical": "\033[91m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


class Stats:
    def __init__(self):
        self.total = 0
        self.by_category = Counter()
        self.by_rule = Counter()
        self.by_severity = Counter()
        self.first_us = None
        self.last_us = None
        self.start_wall = time.time()

    def update(self, data):
        self.total += 1
        rule = data.get("rule", "?")
        cat = RULE_CATEGORY.get(rule, "Uncategorised")
        self.by_category[cat] += 1
        self.by_rule[rule] += 1
        self.by_severity[data.get("severity", "info")] += 1
        ts = data.get("ts_us")
        if isinstance(ts, int):
            if self.first_us is None:
                self.first_us = ts
            self.last_us = ts

    def summary_lines(self, color=True):
        c = (lambda s, col: f"{col}{s}{RESET}") if color else (lambda s, col: s)
        lines = []
        lines.append("")
        lines.append(c("===== SESSION SUMMARY =====", BOLD))
        wall = time.time() - self.start_wall
        lines.append(f"Duration         : {wall:6.1f} s wall")
        if self.first_us is not None and self.last_us is not None:
            span_ms = (self.last_us - self.first_us) / 1000.0
            lines.append(f"Device alert span: {span_ms:6.1f} ms")
        lines.append(f"Total alerts     : {self.total}")
        lines.append("")
        lines.append(c("By attack category:", BOLD))
        for cat in CATEGORY_ORDER:
            if self.by_category.get(cat):
                lines.append(f"  {cat:24} {self.by_category[cat]:5}")
        lines.append("")
        lines.append(c("By rule:", BOLD))
        for rule, n in self.by_rule.most_common():
            cat = RULE_CATEGORY.get(rule, "Uncategorised")
            lines.append(f"  {rule:24} {n:5}   ({cat})")
        lines.append("")
        lines.append(c("By severity:", BOLD))
        for sev in ("critical", "warning", "info"):
            if self.by_severity.get(sev):
                col = COLORS.get(sev, "") if color else ""
                lines.append(f"  {col}{sev:10}{RESET if color else ''} {self.by_severity[sev]:5}")
        return lines


class Logger:
    def __init__(self, outdir, mode, label):
        os.makedirs(outdir, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = f"{stamp}_mode{mode}_{label}" if label else f"{stamp}_mode{mode}"
        self.jsonl_path = os.path.join(outdir, base + ".jsonl")
        self.csv_path = os.path.join(outdir, base + ".csv")
        self.mode = mode
        self.label = label
        self._jsonl = open(self.jsonl_path, "w", encoding="utf-8")
        self._csv_file = open(self.csv_path, "w", newline="", encoding="utf-8")
        self._csv = csv.writer(self._csv_file)
        self._csv.writerow([
            "wall_iso", "ts_us", "mode", "scenario", "category",
            "rule", "severity", "suspect_node", "suspect_cob", "description",
        ])

    def write(self, data):
        cat = RULE_CATEGORY.get(data.get("rule", "?"), "Uncategorised")
        rec = dict(data)
        rec["mode"] = self.mode
        rec["scenario"] = self.label
        rec["category"] = cat
        rec["wall_iso"] = datetime.now().isoformat(timespec="milliseconds")
        self._jsonl.write(json.dumps(rec) + "\n")
        self._jsonl.flush()
        self._csv.writerow([
            rec["wall_iso"], data.get("ts_us", ""), self.mode, self.label, cat,
            data.get("rule", ""), data.get("severity", ""),
            data.get("suspect_node", ""), data.get("suspect_cob", ""),
            data.get("description", ""),
        ])
        self._csv_file.flush()

    def close(self):
        try:
            self._jsonl.close()
            self._csv_file.close()
        except Exception:
            pass


class SOC:
    def __init__(self, args):
        self.args = args
        self.color = not args.no_color and sys.stdout.isatty()
        self.stats = Stats()
        self.logger = Logger(args.out, args.mode, args.label) if args.out else None

    def _col(self, s, col):
        return f"{col}{s}{RESET}" if self.color else s

    def on_connect(self, client, userdata, flags, rc, properties=None):
        print(f"[SOC] Connected to broker (rc={rc})")
        client.subscribe(ALERT_TOPIC, qos=1)
        client.subscribe(HEARTBEAT_TOPIC, qos=1)
        print(f"[SOC] Subscribed to {ALERT_TOPIC} and {HEARTBEAT_TOPIC}")
        mode = self.args.mode
        label = self.args.label or "(none)"
        print(f"[SOC] Run mode={mode}  scenario={label}  "
              f"logging={'on -> ' + self.logger.csv_path if self.logger else 'off'}")
        print(self._col("Listening for IDS alerts. Ctrl-C to stop and print summary.\n", DIM))

    def on_message(self, client, userdata, msg):
        if msg.topic == HEARTBEAT_TOPIC:
            print(self._col(f"[HB ] Blue node: {msg.payload.decode()}", DIM))
            return
        try:
            data = json.loads(msg.payload.decode())
        except json.JSONDecodeError:
            print(f"[ERR] Bad JSON: {msg.payload!r}")
            return

        self.stats.update(data)
        if self.logger:
            self.logger.write(data)

        sev = data.get("severity", "info")
        rule = data.get("rule", "?")
        cat = RULE_CATEGORY.get(rule, "Uncategorised")
        color = COLORS.get(sev, "") if self.color else ""
        reset = RESET if self.color else ""
        bold = BOLD if self.color else ""
        ts = datetime.now().strftime("%H:%M:%S")

        seen = self.stats.by_rule[rule]
        print(
            f"{color}{bold}[{ts}] [{sev.upper():8}] "
            f"{cat:22} {rule}{reset} "
            f"node={data.get('suspect_node')} cob={data.get('suspect_cob')} "
            f"{self._col('#' + str(seen), DIM)}"
        )
        print(f"         -> {data.get('description')}")

    def run(self):
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        client.on_connect = self.on_connect
        client.on_message = self.on_message

        def handle_sigint(signum, frame):
            self.shutdown(client)
            sys.exit(0)
        signal.signal(signal.SIGINT, handle_sigint)

        print(f"[SOC] Connecting to broker {self.args.host}:{self.args.port}")
        client.connect(self.args.host, self.args.port, 60)
        client.loop_forever()

    def shutdown(self, client):
        try:
            client.disconnect()
        except Exception:
            pass
        for line in self.stats.summary_lines(color=self.color):
            print(line)
        if self.logger:
            print(f"\n[SOC] Log written:\n  {self.logger.jsonl_path}\n  {self.logger.csv_path}")
            self.logger.close()


def parse_args():
    p = argparse.ArgumentParser(description="Blue Team SOC listener")
    p.add_argument("--host", default=BROKER_HOST, help="MQTT broker host")
    p.add_argument("--port", type=int, default=BROKER_PORT, help="MQTT broker port")
    p.add_argument("--mode", choices=["A", "B"], default="B",
                   help="Evaluation mode label recorded in the log "
                        "(A=transport only, B=CANopen aware). Must match the "
                        "mode set on the blue node firmware.")
    p.add_argument("--label", default="",
                   help="Scenario label for this run, e.g. nmt_stop, sdo_stealth")
    p.add_argument("--out", default="",
                   help="Directory to write JSONL+CSV session log. Empty = no log.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors")
    return p.parse_args()


def main():
    SOC(parse_args()).run()


if __name__ == "__main__":
    main()
