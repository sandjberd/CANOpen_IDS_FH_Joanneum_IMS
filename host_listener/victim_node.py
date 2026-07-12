#!/usr/bin/env python3
import argparse
import logging
import sys
import threading
import time
import struct
from enum import IntEnum

import can

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("VICTIM")

NODE_ID = 0x01

COB_NMT       = 0x000
COB_SYNC      = 0x080
COB_EMCY      = 0x080 + NODE_ID
COB_TPDO1     = 0x180 + NODE_ID
COB_TPDO2     = 0x280 + NODE_ID
COB_TSDO      = 0x580 + NODE_ID
COB_RSDO      = 0x600 + NODE_ID
COB_HEARTBEAT = 0x700 + NODE_ID

HEARTBEAT_PERIOD  = 1.000
PDO1_PERIOD       = 0.100
PDO2_PERIOD       = 0.500

SDO_UPLOAD_REQ      = 0x40
SDO_UPLOAD_RESP_4   = 0x43
SDO_UPLOAD_RESP_2   = 0x4B
SDO_UPLOAD_RESP_1   = 0x4F
SDO_DOWNLOAD_REQ_4  = 0x23
SDO_DOWNLOAD_REQ_2  = 0x2B
SDO_DOWNLOAD_REQ_1  = 0x2F
SDO_DOWNLOAD_RESP   = 0x60
SDO_ABORT           = 0x80

SDO_ABORT_NOT_EXIST = 0x06020000
SDO_ABORT_READ_ONLY = 0x06010002

OD_HEARTBEAT_TIME = 0x1017
OD_SENSOR_VALUE   = 0x6000
OD_SETPOINT       = 0x6001


class NMTState(IntEnum):
    INITIALISING    = 0x00
    PRE_OPERATIONAL = 0x7F
    OPERATIONAL     = 0x05
    STOPPED         = 0x04


class NMTCommand(IntEnum):
    START       = 0x01
    STOP        = 0x02
    ENTER_PREOP = 0x80
    RESET_NODE  = 0x81
    RESET_COMM  = 0x82


class ObjectDictionary:
    def __init__(self):
        self.heartbeat_time_ms = int(HEARTBEAT_PERIOD * 1000)
        self.sensor_value      = 0x1234
        self.setpoint          = 0x0064
        self._lock             = threading.Lock()

    def read(self, index, subindex):
        with self._lock:
            if index == OD_HEARTBEAT_TIME and subindex == 0:
                return struct.pack("<H", self.heartbeat_time_ms), 2
            elif index == OD_SENSOR_VALUE and subindex == 0:
                return struct.pack("<H", self.sensor_value), 2
            elif index == OD_SETPOINT and subindex == 0:
                return struct.pack("<H", self.setpoint), 2
            else:
                raise KeyError(f"0x{index:04X}:{subindex}")

    def write(self, index, subindex, data: bytes):
        with self._lock:
            if index == OD_HEARTBEAT_TIME:
                raise PermissionError("read-only")
            elif index == OD_SENSOR_VALUE and subindex == 0:
                self.sensor_value = struct.unpack_from("<H", data)[0]
                log.info(f"[OD ] 0x{index:04X}:{subindex} <- {self.sensor_value}")
            elif index == OD_SETPOINT and subindex == 0:
                self.setpoint = struct.unpack_from("<H", data)[0]
                log.info(f"[OD ] 0x{index:04X}:{subindex} <- {self.setpoint}")
            else:
                raise KeyError(f"0x{index:04X}:{subindex}")


class VictimNode:
    def __init__(self, bus: can.BusABC):
        self.bus   = bus
        self.od    = ObjectDictionary()
        self._nmt  = NMTState.INITIALISING
        self._lock = threading.Lock()

        self._running   = False
        self._threads   = []
        self._start_time = time.monotonic()

        self._tick = 0
        self._adc  = 0

    @property
    def nmt_state(self) -> NMTState:
        with self._lock:
            return self._nmt

    @nmt_state.setter
    def nmt_state(self, state: NMTState):
        with self._lock:
            self._nmt = state
        log.warning(f"[NMT] -> {state.name}  (0x{state:02X})")

    def _send(self, cob_id: int, data: bytes):
        msg = can.Message(
            arbitration_id=cob_id,
            data=data,
            is_extended_id=False,
        )
        try:
            self.bus.send(msg, timeout=0.02)
        except can.CanError as e:
            log.error(f"TX error cob=0x{cob_id:03X}: {e}")

    def boot(self):
        log.info("=" * 50)
        log.info(f" CANopen Victim Node  Node-ID=0x{NODE_ID:02X}")
        log.info("=" * 50)
        log.info(f"  COB Heartbeat : 0x{COB_HEARTBEAT:03X}  period={HEARTBEAT_PERIOD*1000:.0f} ms")
        log.info(f"  COB TPDO1     : 0x{COB_TPDO1:03X}  period={PDO1_PERIOD*1000:.0f} ms")
        log.info(f"  COB TPDO2     : 0x{COB_TPDO2:03X}  period={PDO2_PERIOD*1000:.0f} ms")
        log.info(f"  COB SDO rx    : 0x{COB_RSDO:03X}")
        log.info(f"  COB SDO tx    : 0x{COB_TSDO:03X}")
        log.info("  OD entries:")
        log.info(f"    0x1017:00  Heartbeat time = {HEARTBEAT_PERIOD*1000:.0f} ms  [RO]")
        log.info(f"    0x6000:00  Sensor value   = 0x{self.od.sensor_value:04X}  [RW]")
        log.info(f"    0x6001:00  Setpoint       = 0x{self.od.setpoint:04X}  [RW]")
        log.info("=" * 50)

        self.nmt_state = NMTState.INITIALISING
        time.sleep(0.1)

        self._send(COB_HEARTBEAT, bytes([0x00]))
        log.info("[HB ] Bootup message sent")

        self.nmt_state = NMTState.PRE_OPERATIONAL
        time.sleep(0.5)

        self.nmt_state = NMTState.OPERATIONAL

    def _handle_nmt(self, msg: can.Message):
        if len(msg.data) < 2:
            return
        cmd    = msg.data[0]
        target = msg.data[1]

        if target != 0 and target != NODE_ID:
            return

        log.warning(f"[NMT] cmd=0x{cmd:02X} target=0x{target:02X}")

        try:
            c = NMTCommand(cmd)
        except ValueError:
            log.warning(f"[NMT] Unknown command 0x{cmd:02X}")
            return

        if c == NMTCommand.START:
            self.nmt_state = NMTState.OPERATIONAL
        elif c == NMTCommand.STOP:
            self.nmt_state = NMTState.STOPPED
        elif c == NMTCommand.ENTER_PREOP:
            self.nmt_state = NMTState.PRE_OPERATIONAL
        elif c in (NMTCommand.RESET_NODE, NMTCommand.RESET_COMM):
            self.nmt_state = NMTState.INITIALISING
            time.sleep(0.2)
            self._send(COB_HEARTBEAT, bytes([0x00]))
            self.nmt_state = NMTState.PRE_OPERATIONAL
            time.sleep(0.3)
            self.nmt_state = NMTState.OPERATIONAL

    def _sdo_abort(self, index: int, subindex: int, abort_code: int):
        data = struct.pack("<BBBBBBBB",
            SDO_ABORT,
            index & 0xFF, (index >> 8) & 0xFF,
            subindex,
            abort_code & 0xFF,
            (abort_code >> 8)  & 0xFF,
            (abort_code >> 16) & 0xFF,
            (abort_code >> 24) & 0xFF,
        )
        self._send(COB_TSDO, data)
        log.warning(f"[SDO] Abort 0x{index:04X}:{subindex}  code=0x{abort_code:08X}")

    def _handle_sdo(self, msg: can.Message):
        if len(msg.data) < 4:
            return

        cs       = msg.data[0]
        index    = struct.unpack_from("<H", msg.data, 1)[0]
        subindex = msg.data[3]

        if cs == SDO_UPLOAD_REQ:
            try:
                val_bytes, size = self.od.read(index, subindex)
            except KeyError:
                self._sdo_abort(index, subindex, SDO_ABORT_NOT_EXIST)
                return

            resp = bytearray(8)
            resp[0] = SDO_UPLOAD_RESP_2 if size == 2 else SDO_UPLOAD_RESP_4
            struct.pack_into("<H", resp, 1, index)
            resp[3] = subindex
            resp[4:4+size] = val_bytes
            self._send(COB_TSDO, bytes(resp))

            val = struct.unpack_from("<H", val_bytes)[0]
            log.info(f"[SDO] Read  0x{index:04X}:{subindex} = {val}  (0x{val:04X})")

        elif cs in (SDO_DOWNLOAD_REQ_4, SDO_DOWNLOAD_REQ_2, SDO_DOWNLOAD_REQ_1):
            try:
                self.od.write(index, subindex, msg.data[4:8])
            except PermissionError:
                self._sdo_abort(index, subindex, SDO_ABORT_READ_ONLY)
                return
            except KeyError:
                self._sdo_abort(index, subindex, SDO_ABORT_NOT_EXIST)
                return

            resp = bytearray(8)
            resp[0] = SDO_DOWNLOAD_RESP
            struct.pack_into("<H", resp, 1, index)
            resp[3] = subindex
            self._send(COB_TSDO, bytes(resp))

    def _rx_thread(self):
        log.info("[RX ] Receive thread started")
        while self._running:
            try:
                msg = self.bus.recv(timeout=0.5)
                if msg is None:
                    continue
                if msg.is_extended_id:
                    continue

                cob = msg.arbitration_id

                if cob == COB_NMT:
                    self._handle_nmt(msg)
                elif cob == COB_RSDO:
                    self._handle_sdo(msg)
                elif cob == COB_SYNC:
                    log.debug("[SYNC] received")
                else:
                    log.debug(f"[RX ] 0x{cob:03X}  {msg.data.hex(' ')}")

            except can.CanError as e:
                if self._running:
                    log.error(f"[RX ] CAN error: {e}")

    def _heartbeat_thread(self):
        log.info(f"[HB ] Heartbeat thread started ({HEARTBEAT_PERIOD*1000:.0f} ms)")
        next_tick = time.monotonic()
        while self._running:
            state_byte = bytes([int(self.nmt_state)])
            self._send(COB_HEARTBEAT, state_byte)
            log.debug(f"[HB ] {self.nmt_state.name}")
            next_tick += HEARTBEAT_PERIOD
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()

    def _tpdo1_thread(self):
        log.info(f"[TPDO1] Thread started ({PDO1_PERIOD*1000:.0f} ms)")
        next_tick = time.monotonic()
        while self._running:
            if self.nmt_state == NMTState.OPERATIONAL:
                with self._lock:
                    self._tick = (self._tick + 1) & 0xFFFF
                    self._adc  = (self._adc  + 13) % 1024
                    tick = self._tick
                    adc  = self._adc

                self.od.sensor_value = 100 + (tick % 900)
                flags = 0x0001
                if self.od.sensor_value > 800:
                    flags |= 0x0002

                pdo = struct.pack("<HHHH",
                    self.od.sensor_value,
                    tick,
                    adc,
                    flags,
                )
                self._send(COB_TPDO1, pdo)
                log.debug(f"[TPDO1] sensor={self.od.sensor_value} "
                          f"tick={tick} adc={adc} flags=0x{flags:04X}")

            next_tick += PDO1_PERIOD
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()

    def _tpdo2_thread(self):
        log.info(f"[TPDO2] Thread started ({PDO2_PERIOD*1000:.0f} ms)")
        next_tick = time.monotonic()
        while self._running:
            if self.nmt_state == NMTState.OPERATIONAL:
                uptime_s = int(time.monotonic() - self._start_time) & 0xFFFF
                pdo = struct.pack("<HHBB",
                    self.od.setpoint,
                    uptime_s,
                    NODE_ID,
                    int(self.nmt_state),
                ) + b'\x00\x00'
                self._send(COB_TPDO2, pdo)
                log.debug(f"[TPDO2] setpoint={self.od.setpoint} "
                          f"uptime={uptime_s}s state={self.nmt_state.name}")

            next_tick += PDO2_PERIOD
            sleep = next_tick - time.monotonic()
            if sleep > 0:
                time.sleep(sleep)
            else:
                next_tick = time.monotonic()

    def start(self):
        self._running = True
        self.boot()

        thread_fns = [
            self._rx_thread,
            self._heartbeat_thread,
            self._tpdo1_thread,
            self._tpdo2_thread,
        ]
        for fn in thread_fns:
            t = threading.Thread(target=fn, daemon=True, name=fn.__name__)
            t.start()
            self._threads.append(t)

        log.info("All threads started - node OPERATIONAL")

    def stop(self):
        log.info("Shutting down...")
        self._running = False
        for t in self._threads:
            t.join(timeout=2.0)
        log.info("Stopped")


def list_interfaces():
    print("Available python-can interface types:")
    interfaces = [
        ("ixxat",      "Sysworxx / IXXAT USB-CAN adapter  (Windows/Linux)"),
        ("socketcan",  "Linux SocketCAN  (e.g. can0, vcan0)"),
        ("pcan",       "Peak PCAN USB adapter"),
        ("kvaser",     "Kvaser adapters"),
        ("vector",     "Vector CANalyzer / CANoe hardware"),
        ("slcan",      "Serial-line CAN  (e.g. CANable)"),
        ("virtual",    "Virtual in-process bus  (testing only)"),
    ]
    for name, desc in interfaces:
        print(f"  {name:<14} {desc}")
    print()
    print("Usage examples:")
    print("  python victim_node.py --interface ixxat")
    print("  python victim_node.py --interface socketcan --channel can0")
    print("  python victim_node.py --interface virtual   --channel 0")


def make_bus(interface: str, channel: str, bitrate: int) -> can.BusABC:
    kwargs = dict(bitrate=bitrate)

    if interface == "ixxat":
        kwargs["channel"] = int(channel) if channel else 0
        log.info(f"Opening IXXAT/Sysworxx channel {kwargs['channel']} "
                 f"at {bitrate} bps")

    elif interface == "socketcan":
        kwargs["channel"] = channel or "can0"
        log.info(f"Opening SocketCAN channel {kwargs['channel']}")

    elif interface == "virtual":
        kwargs["channel"] = channel or "0"
        kwargs.pop("bitrate", None)
        log.info("Opening virtual CAN bus (testing only)")

    else:
        kwargs["channel"] = channel
        log.info(f"Opening {interface} channel {channel} at {bitrate} bps")

    return can.Bus(interface=interface, **kwargs)


def main():
    parser = argparse.ArgumentParser(
        description="CANopen Victim Node (Node-ID=0x01) - PC / Sysworxx"
    )
    parser.add_argument(
        "--interface", "-i",
        default="ixxat",
        help="python-can interface type (default: ixxat for Sysworxx)",
    )
    parser.add_argument(
        "--channel", "-c",
        default="0",
        help="CAN channel / device index (default: 0)",
    )
    parser.add_argument(
        "--bitrate", "-b",
        type=int,
        default=500000,
        help="CAN bitrate in bps (default: 500000)",
    )
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List available interface types and exit",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable DEBUG logging (shows every PDO and heartbeat)",
    )
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        bus = make_bus(args.interface, args.channel, args.bitrate)
    except Exception as e:
        log.error(f"Failed to open CAN bus: {e}")
        log.error("Run with --list to see available interfaces.")
        sys.exit(1)

    node = VictimNode(bus)
    try:
        node.start()
        log.info("Press Ctrl+C to stop")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    finally:
        node.stop()
        bus.shutdown()


if __name__ == "__main__":
    main()
