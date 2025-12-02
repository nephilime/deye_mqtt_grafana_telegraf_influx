#!/usr/bin/env python3
import asyncio
import time
import logging
import base64
from typing import Any, Dict, Optional
from struct import unpack_from, calcsize
from urllib import request, error as urlerror

from bleak import BleakClient, BleakError

# ==============================
#  LOGGING SETUP + VERBOSE LEVEL
# ==============================

VERBOSE_LEVEL_NUM = 15  # Between INFO (20) and DEBUG (10)
logging.addLevelName(VERBOSE_LEVEL_NUM, "VERBOSE")


def verbose(self, message, *args, **kws):
    """Custom verbose log level for large dumps."""
    if self.isEnabledFor(VERBOSE_LEVEL_NUM):
        self._log(VERBOSE_LEVEL_NUM, message, args, **kws)


logging.Logger.verbose = verbose  # type: ignore[attr-defined]

# Default log level: INFO. Use VERBOSE_LEVEL_NUM or DEBUG for more details.
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("jk_bms")

# ==============================
#  GLOBAL SETTINGS
# ==============================

# Your JK-BMS MAC address
BMS_ADDRESS = "C8:47:80:1A:13:A7"

# UART characteristic (FFE1)
UART_CHAR_UUID = "0000ffe1-0000-1000-8000-00805f9b34fb"

# JK commands
COMMAND_CELL_INFO = 0x96
COMMAND_DEVICE_INFO = 0x97

# JK02 protocol constants
FRAME_VERSION_JK04 = 0x01
FRAME_VERSION_JK02 = 0x02
FRAME_VERSION_JK02_32S = 0x03
PROTOCOL_VERSION_JK02 = 0x02

protocol_version = PROTOCOL_VERSION_JK02

# Frame sizes for JK02
MIN_RESPONSE_SIZE = 300
MAX_RESPONSE_SIZE = 320

# Reconnect / timeout settings
NO_DATA_TIMEOUT = 60.0       # seconds without CELL_INFO => reconnect
RECONNECT_DELAY = 10.0       # delay before reconnect attempt

# ==============================
#  INFLUX SETTINGS (EDIT HERE)
# ==============================

# Enable/disable Influx export
INFLUX_ENABLED = True

# InfluxDB v1 example:
#   "http://localhost:8086/write?db=jkbms"
INFLUX_WRITE_URL: Optional[str] = "http://127.0.0.1:8086/write?db=influx"

# Export interval (seconds)
INFLUX_EXPORT_INTERVAL = 30.0

# Token (for InfluxDB v2 if needed, otherwise keep None)
INFLUX_AUTH_TOKEN: Optional[str] = None

# Username/password for basic auth (InfluxDB 1.x or 2.x with basic auth)
INFLUX_USERNAME: Optional[str] = "admin"      # <-- change to your user
INFLUX_PASSWORD: Optional[str] = "admin"   # <-- change to your password

# ==============================
#  TRANSLATION TABLES
# ==============================

TRANSLATE_DEVICE_INFO = [
    [["device_info", "hw_rev"], 22, "8s"],
    [["device_info", "sw_rev"], 30, "8s"],
    [["device_info", "uptime"], 38, "<L"],
    [["device_info", "vendor_id"], 6, "16s"],
    [["device_info", "manufacturing_date"], 78, "8s"],
]

TRANSLATE_SETTINGS = [
    [["settings", "cell_uvp"], 10, "<L", 0.001],
    [["settings", "cell_uvpr"], 14, "<L", 0.001],
    [["settings", "cell_ovp"], 18, "<L", 0.001],
    [["settings", "cell_ovpr"], 22, "<L", 0.001],
    [["settings", "balance_trigger_voltage"], 26, "<L", 0.001],
    [["settings", "power_off_voltage"], 46, "<L", 0.001],
    [["settings", "max_charge_current"], 50, "<L", 0.001],
    [["settings", "max_discharge_current"], 62, "<L", 0.001],
    [["settings", "max_balance_current"], 72, "<L", 0.001],
    [["settings", "cell_count"], 114, "<L"],
    [["settings", "charging_switch"], 118, "4?"],
    [["settings", "discharging_switch"], 122, "4?"],
    [["settings", "balancing_switch"], 126, "4?"],
]

TRANSLATE_CELL_INFO = [
    # 16 cell voltages (mV → V)
    [["cell_info", "voltages", 16], 6, "<H", 0.001],

    # average & delta cell voltage
    [["cell_info", "average_cell_voltage"], 74, "<H", 0.001],
    [["cell_info", "delta_cell_voltage"], 188, "<H", 0.001],

    # 16 cell internal resistances (mΩ → Ω)
    [["cell_info", "resistances", 16], 80, "<H", 0.001],

    # warning bitmask (16-bit)
    [["cell_info", "warnings_bitmask16"], 136, "<H"],

    # pack total voltage
    [["cell_info", "total_voltage"], 234, "<H", 0.01],

    # pack current (signed, mA → A)
    [["cell_info", "current"], 158, "<l", 0.001],

    # temperatures (0.1 °C)
    [["cell_info", "temperature_mos"], 144, "<H", 0.1],
    [["cell_info", "temperature_sensor_1"], 162, "<H", 0.1],
    [["cell_info", "temperature_sensor_2"], 164, "<H", 0.1],

    # balancing current (mA → A)
    [["cell_info", "balancing_current"], 170, "<H", 0.001],

    # SOC + capacities
    [["cell_info", "battery_soc"], 173, "B"],
    [["cell_info", "capacity_remain"], 174, "<L", 0.001],
    [["cell_info", "capacity_nominal"], 178, "<L", 0.001],
    [["cell_info", "cycle_count"], 182, "<L"],
    [["cell_info", "cycle_capacity"], 186, "<L", 0.001],

    # FET / balancing flags
    [["cell_info", "charging_switch_enabled"], 198, "1?"],
    [["cell_info", "discharging_switch_enabled"], 199, "1?"],
    [["cell_info", "balancing_active"], 200, "1?"],
]

# ==============================
#  GLOBAL STATE
# ==============================

frame_buffer = bytearray()
bms_status: Dict[str, Any] = {}
waiting_for_response: str = ""
last_cell_info_ts: float = 0.0
last_influx_export_ts: float = 0.0


# ==============================
#  UTILS
# ==============================

def crc_jk02(arr: bytearray, length: int) -> int:
    """JK02 CRC: sum of bytes, take low byte."""
    crc_val = 0
    for b in arr[:length]:
        crc_val += b
    return crc_val.to_bytes(2, "little")[0]


def translate(fb: bytearray, translation, out_dict: Dict, i: int = 0) -> None:
    """
    Generic translator:
    - translation: [ [path...], offset, format_or_len, (optional) scale ]
    - path: e.g. ["cell_info", "voltages", 16] -> cell_info["voltages"][0..15]
    """
    path = translation[0]
    offset = translation[1]
    fmt_or_len = translation[2]

    if i == len(path) - 1:
        if isinstance(path[i], int):
            keys = range(0, path[i])
        else:
            keys = [path[i]]

        local_offset = 0
        for j in keys:
            if isinstance(fmt_or_len, int):
                val = bytearray(fb[offset + local_offset: offset + local_offset + fmt_or_len])
                local_offset += fmt_or_len
            else:
                val = unpack_from(fmt_or_len, fb, offset + local_offset)[0]
                local_offset += calcsize(fmt_or_len)

            if isinstance(val, bytes):
                val = val.decode("utf-8").rstrip(" \t\n\r\0")
            elif isinstance(val, int) and len(translation) == 4:
                val = val * translation[3]

            out_dict[j] = val
    else:
        key = path[i]
        if key not in out_dict:
            if len(path) == i + 2 and isinstance(path[i + 1], int):
                out_dict[key] = [None] * path[i + 1]
            else:
                out_dict[key] = {}
        translate(fb, translation, out_dict[key], i + 1)


def decode_warnings(fb: bytearray) -> None:
    """Decode warning bits into bms_status['warnings']."""
    global bms_status

    val = unpack_from("<H", fb, 136)[0]  # 16-bit warning mask

    if "cell_info" not in bms_status:
        bms_status["cell_info"] = {}
    if "warnings" not in bms_status:
        bms_status["warnings"] = {}

    bms_status["cell_info"]["error_bitmask_16"] = hex(val)
    bms_status["cell_info"]["error_bitmask_2"] = format(val, "016b")

    w = bms_status["warnings"]
    w["resistance_too_high"] = bool(val & (1 << 0))
    w["cell_count_wrong"] = bool(val & (1 << 2))
    w["charge_overtemp"] = bool(val & (1 << 8))
    w["charge_undertemp"] = bool(val & (1 << 9))
    w["discharge_overtemp"] = bool(val & (1 << 15))
    w["cell_overvoltage"] = bool(val & (1 << 4))
    w["cell_undervoltage"] = bool(val & (1 << 11))
    w["charge_overcurrent"] = bool(val & (1 << 6))
    w["discharge_overcurrent"] = bool(val & (1 << 13))


def decode_device_info_jk02(fb: bytearray) -> None:
    for t in TRANSLATE_DEVICE_INFO:
        translate(fb, t, bms_status)


def decode_cellinfo_jk02(fb: bytearray) -> None:
    global last_cell_info_ts
    for t in TRANSLATE_CELL_INFO:
        translate(fb, t, bms_status)
    decode_warnings(fb)
    last_cell_info_ts = time.time()  # update timestamp when fresh CELL_INFO arrived


def decode_settings_jk02(fb: bytearray) -> None:
    for t in TRANSLATE_SETTINGS:
        translate(fb, t, bms_status)


def _build_influx_line() -> Optional[str]:
    """
    Build a single InfluxDB line protocol record from current bms_status.

    Includes:
      - cell_info (voltages, currents, temps, SOC, capacities, resistances, switches, warnings)
      - device_info (hw/sw rev, uptime, vendor, mfg date)
      - settings (UVP/OVP, currents, switches, cell_count)
    """
    global bms_status

    ci = bms_status.get("cell_info")
    dev = bms_status.get("device_info", {})
    st = bms_status.get("settings", {})
    w  = bms_status.get("warnings", {})

    # We at least need cell_info for basic pack metrics
    if not ci:
        return None

    # measurement and tags
    device_tag = BMS_ADDRESS.replace(":", "_")
    tags = f"device={device_tag}"

    fields: list[str] = []

    def add_float(name: str, value) -> None:
        if value is None:
            return
        try:
            v = float(value)
        except (ValueError, TypeError):
            return
        fields.append(f"{name}={v}")

    def add_bool(name: str, value) -> None:
        if value is None:
            return
        if isinstance(value, bool):
            v = "true" if value else "false"
            fields.append(f"{name}={v}")

    def add_int(name: str, value) -> None:
        if value is None:
            return
        try:
            iv = int(value)
        except (ValueError, TypeError):
            return
        # integer field needs "i" suffix in line protocol
        fields.append(f"{name}={iv}i")

    def add_str(name: str, value) -> None:
        if value is None:
            return
        s = str(value)
        # escape double quotes
        s = s.replace('"', '\\"')
        fields.append(f'{name}="{s}"')

    # ---------- PACK-LEVEL (cell_info) ----------
    add_float("total_voltage", ci.get("total_voltage"))
    add_float("current", ci.get("current"))
    add_float("power", ci.get("power"))
    add_float("avg_cell_voltage", ci.get("average_cell_voltage"))
    add_float("delta_cell_voltage", ci.get("delta_cell_voltage"))
    add_float("capacity_remain", ci.get("capacity_remain"))
    add_float("capacity_nominal", ci.get("capacity_nominal"))
    add_float("cycle_capacity", ci.get("cycle_capacity"))
    add_float("temperature_mos", ci.get("temperature_mos"))
    add_float("temperature_sensor_1", ci.get("temperature_sensor_1"))
    add_float("temperature_sensor_2", ci.get("temperature_sensor_2"))

    soc = ci.get("battery_soc")
    if soc is not None:
        add_int("soc", soc)

    # ---------- CELLS ----------
    volts = ci.get("voltages") or []
    for idx, v in enumerate(volts, start=1):
        add_float(f"cell{idx:02d}_v", v)

    res = ci.get("resistances") or []
    for idx, r in enumerate(res, start=1):
        add_float(f"cell{idx:02d}_r", r)

    # ---------- FET FLAGS (instant state) ----------
    add_bool("charging_switch_enabled", ci.get("charging_switch_enabled"))
    add_bool("discharging_switch_enabled", ci.get("discharging_switch_enabled"))
    add_bool("balancing_active", ci.get("balancing_active"))

    # ---------- WARNINGS MASK + PER-FLAG ----------
    mask16 = ci.get("warnings_bitmask16")
    if isinstance(mask16, int):
        add_int("warnings_mask", mask16)

    # individual warning booleans
    add_bool("warn_resistance_too_high", w.get("resistance_too_high"))
    add_bool("warn_cell_count_wrong", w.get("cell_count_wrong"))
    add_bool("warn_charge_overtemp", w.get("charge_overtemp"))
    add_bool("warn_charge_undertemp", w.get("charge_undertemp"))
    add_bool("warn_discharge_overtemp", w.get("discharge_overtemp"))
    add_bool("warn_cell_overvoltage", w.get("cell_overvoltage"))
    add_bool("warn_cell_undervoltage", w.get("cell_undervoltage"))
    add_bool("warn_charge_overcurrent", w.get("charge_overcurrent"))
    add_bool("warn_discharge_overcurrent", w.get("discharge_overcurrent"))

    # ---------- DEVICE INFO ----------
    if dev:
        add_str("dev_hw_rev", dev.get("hw_rev"))
        add_str("dev_sw_rev", dev.get("sw_rev"))
        add_str("dev_vendor_id", dev.get("vendor_id"))
        add_str("dev_mfg_date", dev.get("manufacturing_date"))
        add_int("dev_uptime", dev.get("uptime"))

    # ---------- SETTINGS ----------
    if st:
        add_float("settings_cell_uvp", st.get("cell_uvp"))
        add_float("settings_cell_uvpr", st.get("cell_uvpr"))
        add_float("settings_cell_ovp", st.get("cell_ovp"))
        add_float("settings_cell_ovpr", st.get("cell_ovpr"))
        add_float("settings_balance_trigger_voltage", st.get("balance_trigger_voltage"))
        add_float("settings_power_off_voltage", st.get("power_off_voltage"))
        add_float("settings_max_charge_current", st.get("max_charge_current"))
        add_float("settings_max_discharge_current", st.get("max_discharge_current"))
        add_float("settings_max_balance_current", st.get("max_balance_current"))
        add_int("settings_cell_count", st.get("cell_count"))
        add_bool("settings_charging_switch", st.get("charging_switch"))
        add_bool("settings_discharging_switch", st.get("discharging_switch"))
        add_bool("settings_balancing_switch", st.get("balancing_switch"))

    if not fields:
        return None

    fields_str = ",".join(fields)
    line = f"jk_bms,{tags} {fields_str}"
    return line


def _send_to_influx(line: str) -> None:
    """Send one line of line protocol to InfluxDB."""
    if not INFLUX_ENABLED or not INFLUX_WRITE_URL:
        return

    data = line.encode("utf-8")
    req = request.Request(INFLUX_WRITE_URL, data=data, method="POST")
    req.add_header("Content-Type", "text/plain; charset=utf-8")

    if INFLUX_AUTH_TOKEN:
        req.add_header("Authorization", f"Token {INFLUX_AUTH_TOKEN}")
    elif INFLUX_USERNAME and INFLUX_PASSWORD:
        userpass = f"{INFLUX_USERNAME}:{INFLUX_PASSWORD}".encode("utf-8")
        b64 = base64.b64encode(userpass).decode("ascii")
        req.add_header("Authorization", f"Basic {b64}")

    try:
        with request.urlopen(req, timeout=5) as resp:
            _ = resp.read()
        log.info("Exported to InfluxDB")
    except urlerror.URLError as exc:
        log.warning("Failed to export to InfluxDB: %s", exc)


async def maybe_export_to_influx() -> None:
    """Export data to InfluxDB at most once per INFLUX_EXPORT_INTERVAL seconds."""
    global last_influx_export_ts

    if not INFLUX_ENABLED or not INFLUX_WRITE_URL:
        return

    now = time.time()
    if now - last_influx_export_ts < INFLUX_EXPORT_INTERVAL:
        return

    line = _build_influx_line()
    if not line:
        return

    last_influx_export_ts = now
    await asyncio.to_thread(_send_to_influx, line)


def decode_frame(frame: bytearray) -> None:
    """Decode complete JK02 frame into global bms_status dict."""
    global bms_status

    if len(frame) < 6:
        return

    info_type = frame[4]

    if info_type == 0x01:
        log.info("STATUS/SETTINGS frame (0x01)")
        if protocol_version == PROTOCOL_VERSION_JK02:
            decode_settings_jk02(frame)
            bms_status["last_update"] = time.time()

    elif info_type == 0x02:
        if protocol_version == PROTOCOL_VERSION_JK02:
            log.info("CELL_INFO frame (0x02)")
            decode_cellinfo_jk02(frame)
            bms_status["last_update"] = time.time()
            try:
                v = bms_status["cell_info"]["total_voltage"]
                c = bms_status["cell_info"]["current"]
                bms_status["cell_info"]["power"] = v * c
            except KeyError:
                pass

    elif info_type == 0x03:
        log.info("DEVICE_INFO frame (0x03)")
        if protocol_version == PROTOCOL_VERSION_JK02:
            decode_device_info_jk02(frame)
            bms_status["last_update"] = time.time()


# ==============================
#  FRAME ASSEMBLY / NOTIFY
# ==============================

def assemble_frame(chunk: bytearray) -> None:
    """Collect chunks into a full 300-byte JK02 frame and decode when CRC matches."""
    global frame_buffer

    if len(frame_buffer) > MAX_RESPONSE_SIZE:
        log.warning("Dropping buffer: exceeded MAX_RESPONSE_SIZE")
        frame_buffer = bytearray()

    if (
        len(chunk) >= 4
        and chunk[0] == 0x55
        and chunk[1] == 0xAA
        and chunk[2] == 0xEB
        and chunk[3] == 0x90
    ):
        frame_buffer = bytearray()

    frame_buffer.extend(chunk)

    if len(frame_buffer) >= MIN_RESPONSE_SIZE:
        calc_crc = crc_jk02(frame_buffer, MIN_RESPONSE_SIZE - 1)
        recv_crc = frame_buffer[MIN_RESPONSE_SIZE - 1]
        log.debug("CRC recv=%02X calc=%02X", recv_crc, calc_crc)
        if calc_crc == recv_crc:
            full_frame = frame_buffer[:MIN_RESPONSE_SIZE]
            hex_str = " ".join(f"{b:02X}" for b in full_frame)
            log.info("Assembled valid frame, length=%d bytes", len(full_frame))
            log.debug("Frame data: %s", hex_str)
            decode_frame(full_frame)
        else:
            log.warning(
                "CRC mismatch: recv=0x%02X calc=0x%02X len=%d",
                recv_crc,
                calc_crc,
                len(frame_buffer),
            )
        frame_buffer = bytearray()


def handle_notification(sender: int, data: bytearray) -> None:
    """Notification callback for FFE1."""
    log.info("Notification from %s: %d bytes", sender, len(data))
    hex_str = " ".join(f"{b:02X}" for b in data)
    log.debug("[NOTIFY %s] %s", sender, hex_str)
    assemble_frame(bytearray(data))


# ==============================
#  COMMAND SENDER
# ==============================

async def write_register(address: int, vals: bytes, length: int, client: BleakClient):
    """JK02 write frame (used here for info requests)."""
    frame = bytearray(20)
    frame[0] = 0xAA
    frame[1] = 0x55
    frame[2] = 0x90
    frame[3] = 0xEB
    frame[4] = address
    frame[5] = length
    frame[6] = vals[0]
    frame[7] = vals[1]
    frame[8] = vals[2]
    frame[9] = vals[3]
    for i in range(10, 19):
        frame[i] = 0x00
    frame[19] = crc_jk02(frame, len(frame) - 1)

    log.info("Send command 0x%02X: %s", address, " ".join(f"{b:02X}" for b in frame))
    await client.write_gatt_char(UART_CHAR_UUID, frame, response=False)


async def request_info(rtype: str, client: BleakClient):
    """Send device_info or cell_info request."""
    if rtype == "cell_info":
        cmd = COMMAND_CELL_INFO
    elif rtype == "device_info":
        cmd = COMMAND_DEVICE_INFO
    else:
        return
    await write_register(cmd, b"\x00\x00\x00\x00", 0x00, client)


# ==============================
#  PRETTY PRINT (VERBOSE)
# ==============================

def pretty_print_status():
    """Dump full status using logger at VERBOSE level."""
    global bms_status

    if not log.isEnabledFor(VERBOSE_LEVEL_NUM):
        return

    if not bms_status:
        log.verbose("No data yet.")
        return

    lines = []
    lines.append("=" * 60)
    lines.append(
        f"Last update: {time.strftime('%H:%M:%S', time.localtime(bms_status.get('last_update', 0)))}"
    )

    dev = bms_status.get("device_info", {})
    if dev:
        lines.append("")
        lines.append("[DEVICE_INFO]")
        lines.append(f"  HW rev        : {dev.get('hw_rev')}")
        lines.append(f"  SW rev        : {dev.get('sw_rev')}")
        lines.append(f"  Uptime        : {dev.get('uptime')} s")
        lines.append(f"  Vendor ID     : {dev.get('vendor_id')}")
        lines.append(f"  Mfg date raw  : {dev.get('manufacturing_date')}")

    st = bms_status.get("settings", {})
    if st:
        lines.append("")
        lines.append("[SETTINGS]")
        lines.append(f"  Cell UVP      : {st.get('cell_uvp')} V")
        lines.append(f"  Cell UVP rel  : {st.get('cell_uvpr')} V")
        lines.append(f"  Cell OVP      : {st.get('cell_ovp')} V")
        lines.append(f"  Cell OVP rel  : {st.get('cell_ovpr')} V")
        lines.append(f"  Balance trig  : {st.get('balance_trigger_voltage')} V")
        lines.append(f"  Power off V   : {st.get('power_off_voltage')} V")
        lines.append(f"  Max I charge  : {st.get('max_charge_current')} A")
        lines.append(f"  Max I discharge: {st.get('max_discharge_current')} A")
        lines.append(f"  Max I balance : {st.get('max_balance_current')} A")
        lines.append(f"  Cell count    : {st.get('cell_count')}")
        lines.append(f"  Charging sw   : {st.get('charging_switch')}")
        lines.append(f"  Dischg sw     : {st.get('discharging_switch')}")
        lines.append(f"  Balancing sw  : {st.get('balancing_switch')}")

    ci = bms_status.get("cell_info", {})
    if ci:
        lines.append("")
        lines.append("[CELL_INFO]")
        vols = ci.get("voltages") or []
        for idx, v in enumerate(vols, start=1):
            lines.append(f"  Cell {idx:02d} : {v:.3f}V")
        res = ci.get("resistances") or []
        for idx, v in enumerate(res, start=1):
            lines.append(f"  Cell {idx:02d}  : {v:.3f}Ω")
        lines.append(f"  Total V        : {ci.get('total_voltage')} V")
        lines.append(f"  Current        : {ci.get('current')} A")
        lines.append(f"  Power          : {ci.get('power', 'n/a')} W")
        lines.append(f"  Avg cell V     : {ci.get('average_cell_voltage')} V")
        lines.append(f"  Delta cell V   : {ci.get('delta_cell_voltage')} V")
        lines.append(f"  Max V cell idx : {ci.get('max_voltage_cell')}")
        lines.append(f"  Min V cell idx : {ci.get('min_voltage_cell')}")
        lines.append(f"  SOC            : {ci.get('battery_soc')} %")
        lines.append(f"  Cap remain     : {ci.get('capacity_remain')} Ah")
        lines.append(f"  Cap nominal    : {ci.get('capacity_nominal')} Ah")
        lines.append(f"  Cycles         : {ci.get('cycle_count')}")
        lines.append(f"  Cycle capacity : {ci.get('cycle_capacity')} Ah")
        lines.append(f"  T sensor 1     : {ci.get('temperature_sensor_1')} °C")
        lines.append(f"  T sensor 2     : {ci.get('temperature_sensor_2')} °C")
        lines.append(f"  T MOS          : {ci.get('temperature_mos')} °C")
        lines.append(f"  Balancing I    : {ci.get('balancing_current')} A")
        lines.append(f"  Chg sw enabled : {ci.get('charging_switch_enabled')}")
        lines.append(f"  Dchg sw enabled: {ci.get('discharging_switch_enabled')}")
        lines.append(f"  Balancing act  : {ci.get('balancing_active')}")

    w = bms_status.get("warnings", {})
    if w:
        lines.append("")
        lines.append("[WARNINGS]")
        lines.append(f"  Raw bitmask 16 : {ci.get('error_bitmask_16')}")
        lines.append(f"  Raw bitmask bin: {ci.get('error_bitmask_2')}")
        for k, v in w.items():
            lines.append(f"  {k}: {v}")

    lines.append("=" * 60)

    log.verbose("\n".join(lines))


# ==============================
#  MAIN RECONNECT LOOP
# ==============================

def _on_disconnected(client: BleakClient):
    """Callback when BLE device disconnects."""
    log.warning("BLE device %s disconnected", client.address)


async def run_forever():
    """Main loop: connect, read, export; reconnect on errors or data timeout."""
    global last_cell_info_ts

    log.info("Influx export: %s", "ENABLED" if INFLUX_ENABLED else "DISABLED")
    if INFLUX_ENABLED:
        log.info("Influx URL: %s", INFLUX_WRITE_URL)
        log.info("Influx interval: %s s", INFLUX_EXPORT_INTERVAL)

    while True:
        client: Optional[BleakClient] = None
        last_cell_info_ts = 0.0

        try:
            log.info("Connecting to %s ...", BMS_ADDRESS)
            client = BleakClient(BMS_ADDRESS, disconnected_callback=_on_disconnected)
            await client.connect()
            log.info("Connected: %s", client.is_connected)

            await client.start_notify(UART_CHAR_UUID, handle_notification)
            log.info("Notifications enabled on FFE1")

            # initial requests
            await request_info("device_info", client)
            await asyncio.sleep(0.3)
            await request_info("cell_info", client)

            # inner read loop (no time limit)
            while True:
                await asyncio.sleep(5)
                pretty_print_status()
                await maybe_export_to_influx()

                # reconnect if we stopped receiving cell info for too long
                if last_cell_info_ts > 0:
                    idle = time.time() - last_cell_info_ts
                    if idle > NO_DATA_TIMEOUT:
                        raise RuntimeError(
                            f"No CELL_INFO data received for {idle:.1f}s, forcing reconnect"
                        )

        except KeyboardInterrupt:
            log.info("KeyboardInterrupt received, shutting down...")
            break
        except (BleakError, RuntimeError) as e:
            log.warning("Connection/data error: %s", e)
            log.info("Will try to reconnect in %.1f seconds...", RECONNECT_DELAY)
        except Exception as e:
            log.error("Unexpected error: %s", e)
            log.info("Will try to reconnect in %.1f seconds...", RECONNECT_DELAY)
        finally:
            if client is not None:
                try:
                    if client.is_connected:
                        try:
                            await client.stop_notify(UART_CHAR_UUID)
                            log.info("Notifications stopped")
                        except Exception as e:
                            log.debug("Error during stop_notify: %s", e)
                        try:
                            await client.disconnect()
                            log.info("BLE client disconnected cleanly")
                        except Exception as e:
                            log.warning("Error during BLE disconnect: %s", e)
                except Exception as e:
                    log.debug("Error checking client.is_connected: %s", e)

        # break out if user interrupted
        if asyncio.current_task() and asyncio.current_task().cancelled():
            break

        # wait before reconnect
        try:
            await asyncio.sleep(RECONNECT_DELAY)
        except KeyboardInterrupt:
            log.info("Interrupted during reconnect sleep, exiting.")
            break


if __name__ == "__main__":
    asyncio.run(run_forever())
