# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Part of the Windows port of the Muse gadget SDK.

"""PC-resident Bluetooth identity translation and state machine.

This module implements the platform-independent logic for `PC-BRIDGE.md`:

1. Name & NetBIOS truncation analysis (`analyze_ble_name`):
   - Evaluates the 17-character `MuseGadgetXXXXXX` name against Windows'
     15-character NetBIOS limit (`MAX_COMPUTERNAME_LENGTH = 15`).
   - Predicts prefix discovery (`MuseGadget` intact) vs suffix validation
     failure (`3855D` != `3855D8` against `homelink-3855d8`).
   - Detects whether the host's current Bluetooth radio name (`POWERSPEC-G757-`)
     proves or strongly indicates NetBIOS truncation.
2. Read-only preflight (`run_preflight`):
   - Produces explicit `GO` / `GO-WITH-RISK` / `NO-GO` verdicts for
     `primary-adapter`, `primary-rename`, and `secondary-dongle`.
3. State machine & immutable backup (`ensure_backup`, `apply`, `continue_pairing`,
   `restore`, `get_status`):
   - Never overwrites an existing `backup.json`.
   - Tracks `idle` -> `renamed-awaiting-reboot` -> `pairing-window` ->
     `paired-restore-pending` -> `restored`.
   - `restore` is idempotent from any state, whether or not pairing occurred.
   - `apply` defaults to `dry_run=True` and touches nothing unless explicitly
     executed.

All Windows-specific calls (Win32 `ctypes` and PowerShell helpers under
`windows/pc_bridge/`) are guarded behind `sys.platform == "win32"` and
injectable probes/runners so this module imports and runs its full test suite
on Linux.
"""

from __future__ import annotations

import enum
import json
import logging
import os
import socket
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from musegadget import config, identity
    from musegadget.identity import BLE_NAME_PREFIX, NODE_ID_PREFIX, Identity
except ImportError:  # loaded with windows/musegadget on sys.path
    import config  # type: ignore[no-redef]
    import identity  # type: ignore[no-redef]
    from identity import BLE_NAME_PREFIX, NODE_ID_PREFIX, Identity  # type: ignore[no-redef]

log = logging.getLogger(__name__)

NETBIOS_MAX_CHARS = 15
BLE_MAX_NAME_BYTES = 248
PC_BRIDGE_SUBDIR = "pc_bridge"
BACKUP_FILE = "backup.json"
STATE_FILE = "state.json"
CONTINUATION_TASK_NAME = "MuseGadgetPcBridgeContinue"

WINDOWS_DIR = Path(__file__).resolve().parent.parent
PS_HELPER_DIR = WINDOWS_DIR / "pc_bridge"
ADAPTER_NAME_PS1 = PS_HELPER_DIR / "adapter-name.ps1"
RENAME_COMPUTER_PS1 = PS_HELPER_DIR / "rename-computer.ps1"
SCHEDULED_TASK_PS1 = PS_HELPER_DIR / "scheduled-task.ps1"


class BridgePhase(str, enum.Enum):
    """Lifecycle states of the PC-resident identity translation machine."""

    IDLE = "idle"
    RENAMED_AWAITING_REBOOT = "renamed-awaiting-reboot"
    PAIRING_WINDOW = "pairing-window"
    PAIRED_RESTORE_PENDING = "paired-restore-pending"
    RESTORED = "restored"


class Verdict(str, enum.Enum):
    """Preflight readiness verdict for a bridge mode."""

    GO = "GO"
    GO_WITH_RISK = "GO-WITH-RISK"
    NO_GO = "NO-GO"


class BridgePreflightError(RuntimeError):
    """Raised when `apply` is blocked by a preflight safety gate."""


@dataclass(frozen=True)
class NameAnalysis:
    """17-character MuseGadget name vs 15-character Windows NetBIOS analysis."""

    expected_name: str
    node_id: str
    char_count: int
    utf8_byte_count: int
    exceeds_netbios_limit: bool
    netbios_truncated_name: str
    expected_suffix: str
    truncated_suffix: str
    node_suffix_upper: str
    prefix_match_if_truncated: bool
    suffix_match_if_truncated: bool
    app_discovery_if_truncated: str
    app_pairing_if_truncated: str
    netbios_truncation_proven: bool
    netbios_truncation_suspected: bool
    truncation_evidence: str


def analyze_ble_name(
    ident: Identity,
    *,
    current_netbios: str | None = None,
    current_dns: str | None = None,
    current_radio_name: str | None = None,
) -> NameAnalysis:
    """Analyze `ident.ble_name` against the 15-byte NetBIOS limit and host names."""
    expected = ident.ble_name
    node_id = ident.node_id
    char_count = len(expected)
    utf8_len = len(expected.encode("utf-8"))
    exceeds = char_count > NETBIOS_MAX_CHARS
    truncated = expected[:NETBIOS_MAX_CHARS]

    expected_suffix = (
        expected[len(BLE_NAME_PREFIX):]
        if expected.startswith(BLE_NAME_PREFIX)
        else expected
    )
    truncated_suffix = (
        truncated[len(BLE_NAME_PREFIX):]
        if truncated.startswith(BLE_NAME_PREFIX)
        else truncated
    )
    node_suffix = (
        node_id[len(NODE_ID_PREFIX):].upper()
        if node_id.startswith(NODE_ID_PREFIX)
        else ident.suffix.upper()
    )

    prefix_ok = truncated.startswith(BLE_NAME_PREFIX)
    suffix_ok = truncated_suffix.upper() == node_suffix

    discovery_pred = (
        "listed-by-prefix (MuseGadget prefix intact)"
        if prefix_ok
        else "not-listed (prefix lost)"
    )
    pairing_pred = (
        "suffix-matches-node-id"
        if suffix_ok
        else (
            f"FAILS-suffix-match (advertised suffix {truncated_suffix!r} "
            f"!= node suffix {node_suffix!r})"
        )
    )

    netbios = (current_netbios or "").strip()
    dns = (current_dns or "").strip()
    radio = (current_radio_name or "").strip()

    proven = False
    suspected = False
    evidence_parts: list[str] = []

    if dns and len(dns) > NETBIOS_MAX_CHARS and radio:
        dns_cut = dns[:NETBIOS_MAX_CHARS]
        if radio.upper() == dns_cut.upper() or (netbios and radio.upper() == netbios.upper()):
            proven = True
            evidence_parts.append(
                f"DNS hostname {dns!r} ({len(dns)} chars) > {NETBIOS_MAX_CHARS} "
                f"while Bluetooth radio name is {radio!r} ({len(radio)} chars), "
                "proving bthport uses the 15-char NetBIOS name."
            )

    if len(radio) == NETBIOS_MAX_CHARS and radio.endswith("-"):
        suspected = True
        evidence_parts.append(
            f"Bluetooth radio name {radio!r} is exactly {NETBIOS_MAX_CHARS} chars "
            "and ends with '-' (illegal at the end of a DNS hostname label per "
            "RFC 952/1123), signature of a 15-char NetBIOS truncation."
        )
    elif len(netbios) == NETBIOS_MAX_CHARS and netbios.endswith("-"):
        suspected = True
        evidence_parts.append(
            f"NetBIOS name {netbios!r} is 15 chars ending with '-', "
            "signature of a truncated longer hostname."
        )

    if not evidence_parts:
        if radio and len(radio) > NETBIOS_MAX_CHARS:
            evidence_parts.append(
                f"Radio name {radio!r} is already {len(radio)} chars (>15); "
                "full 17-char name is supported on this stack."
            )
        else:
            evidence_parts.append(
                "Current names are <=15 chars without trailing '-'; "
                "17-char behavior is UNVERIFIED until tested on hardware."
            )

    return NameAnalysis(
        expected_name=expected,
        node_id=node_id,
        char_count=char_count,
        utf8_byte_count=utf8_len,
        exceeds_netbios_limit=exceeds,
        netbios_truncated_name=truncated,
        expected_suffix=expected_suffix,
        truncated_suffix=truncated_suffix,
        node_suffix_upper=node_suffix,
        prefix_match_if_truncated=prefix_ok,
        suffix_match_if_truncated=suffix_ok,
        app_discovery_if_truncated=discovery_pred,
        app_pairing_if_truncated=pairing_pred,
        netbios_truncation_proven=proven,
        netbios_truncation_suspected=proven or suspected,
        truncation_evidence=" ".join(evidence_parts),
    )


@dataclass(frozen=True)
class HostProbe:
    """Read-only snapshot of the host's naming and Bluetooth adapter state."""

    platform: str
    is_windows: bool
    is_admin: bool
    netbios_name: str
    dns_hostname: str
    radio_present: bool
    radio_name: str
    radio_address: str = ""
    radio_manufacturer: int = 0
    adapter_instance_id: str = ""
    adapter_friendly_name: str = ""
    adapter_reg_path_exists: bool = False
    adapter_reg_local_name_hex: str = ""
    adapter_reg_local_name_text: str = ""
    bumble_available: bool = False
    secondary_hci_transport: str = ""


def _have_bumble() -> bool:
    try:
        import bumble  # noqa: F401
        return True
    except ImportError:
        return False


def _probe_windows_bluetooth_radio() -> tuple[bool, str, str, int]:
    """Read `(present, szName, address, manufacturer)` via `BluetoothApis.dll`."""
    if sys.platform != "win32":
        return False, "", "", 0
    try:
        import ctypes as C
        import ctypes.wintypes as W

        bt = C.WinDLL("BluetoothApis.dll")

        class _FindParams(C.Structure):
            _fields_ = [("dwSize", W.DWORD)]

        class _RadioInfo(C.Structure):
            _fields_ = [
                ("dwSize", W.DWORD),
                ("address", C.c_ulonglong),
                ("szName", W.WCHAR * 248),
                ("ulClassofDevice", W.ULONG),
                ("lmpSubversion", W.USHORT),
                ("manufacturer", W.USHORT),
            ]

        bt.BluetoothFindFirstRadio.restype = W.HANDLE
        bt.BluetoothFindRadioClose.argtypes = [W.HANDLE]
        kernel32 = C.WinDLL("kernel32.dll")
        kernel32.CloseHandle.argtypes = [W.HANDLE]

        params = _FindParams(dwSize=C.sizeof(_FindParams))
        radio_handle = W.HANDLE()
        find_handle = bt.BluetoothFindFirstRadio(C.byref(params), C.byref(radio_handle))
        if not find_handle:
            return False, "", "", 0
        try:
            info = _RadioInfo(dwSize=C.sizeof(_RadioInfo))
            rc = bt.BluetoothGetRadioInfo(radio_handle, C.byref(info))
            if rc != 0:
                return True, "", "", 0
            raw = int(info.address)
            addr_bytes = [(raw >> (8 * i)) & 0xFF for i in range(5, -1, -1)]
            addr_str = ":".join(f"{b:02X}" for b in addr_bytes)
            return True, str(info.szName), addr_str, int(info.manufacturer)
        finally:
            kernel32.CloseHandle(radio_handle)
            bt.BluetoothFindRadioClose(find_handle)
    except Exception as exc:  # noqa: BLE001
        log.debug("BluetoothGetRadioInfo probe failed: %s", exc)
        return False, "", "", 0


def _probe_windows_computer_names() -> tuple[str, str, bool]:
    """Read `(netbios_name, dns_hostname, is_admin)` on Windows."""
    netbios = os.environ.get("COMPUTERNAME") or socket.gethostname()[:NETBIOS_MAX_CHARS]
    dns = socket.gethostname()
    is_admin = False
    if sys.platform != "win32":
        return netbios, dns, is_admin
    try:
        import ctypes as C

        is_admin = bool(C.windll.shell32.IsUserAnAdmin())
        kernel32 = C.WinDLL("kernel32.dll", use_last_error=True)

        def _get_name(fmt: int) -> str:
            size = C.c_uint(260)
            buf = C.create_unicode_buffer(260)
            if kernel32.GetComputerNameExW(fmt, buf, C.byref(size)):
                return str(buf.value)
            return ""

        phys_nb = _get_name(4) or _get_name(0)
        phys_dns = _get_name(5) or _get_name(1)
        if phys_nb:
            netbios = phys_nb
        if phys_dns:
            dns = phys_dns
    except Exception as exc:  # noqa: BLE001
        log.debug("GetComputerNameExW probe failed: %s", exc)
    return netbios, dns, is_admin


def _probe_windows_adapter_ps1() -> dict[str, Any]:
    """Run `adapter-name.ps1 -Action Query` on Windows to read PnP/registry info."""
    if sys.platform != "win32" or not ADAPTER_NAME_PS1.exists():
        return {}
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ADAPTER_NAME_PS1),
                "-Action",
                "Query",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            data = json.loads(proc.stdout.strip().splitlines()[-1])
            if isinstance(data, dict):
                return data
    except Exception as exc:  # noqa: BLE001
        log.debug("adapter-name.ps1 query failed: %s", exc)
    return {}


def probe_host(*, secondary_hci_transport: str = "") -> HostProbe:
    """Collect a read-only `HostProbe` without modifying anything."""
    is_win = sys.platform == "win32"
    netbios, dns, is_admin = _probe_windows_computer_names()
    radio_present, radio_name, radio_addr, radio_mfr = _probe_windows_bluetooth_radio()
    ps_info = _probe_windows_adapter_ps1()

    if not radio_name and is_win:
        radio_name = str(ps_info.get("local_name_text") or netbios)
    if is_win and ps_info.get("is_admin") is not None:
        is_admin = bool(ps_info.get("is_admin"))

    return HostProbe(
        platform=sys.platform,
        is_windows=is_win,
        is_admin=is_admin,
        netbios_name=netbios,
        dns_hostname=dns,
        radio_present=radio_present or bool(ps_info.get("instance_id")),
        radio_name=radio_name,
        radio_address=radio_addr,
        radio_manufacturer=radio_mfr,
        adapter_instance_id=str(ps_info.get("instance_id") or ""),
        adapter_friendly_name=str(ps_info.get("friendly_name") or ""),
        adapter_reg_path_exists=bool(ps_info.get("registry_path_exists")),
        adapter_reg_local_name_hex=str(ps_info.get("local_name_hex") or ""),
        adapter_reg_local_name_text=str(ps_info.get("local_name_text") or ""),
        bumble_available=_have_bumble(),
        secondary_hci_transport=secondary_hci_transport,
    )


@dataclass(frozen=True)
class ModeVerdict:
    """Readiness verdict for one bridge mode."""

    mode: str
    verdict: Verdict
    summary: str
    details: tuple[str, ...] = ()


@dataclass(frozen=True)
class PreflightReport:
    """Full read-only preflight report across all modes."""

    state_dir: str
    device_id: str
    node_id: str
    paired: bool
    name_analysis: NameAnalysis
    host: HostProbe
    verdicts: dict[str, ModeVerdict]
    overall_verdict: Verdict

    def format_report(self) -> str:
        na = self.name_analysis
        h = self.host
        lines = [
            "=== Muse Gadget PC Bridge — Preflight Report (read-only) ===",
            f"State directory:          {self.state_dir}",
            f"Device ID:                {self.device_id}",
            f"Node ID:                  {self.node_id}",
            f"Already paired:           {'yes' if self.paired else 'no'}",
            "",
            "--- BLE Name & 17-Char NetBIOS Analysis ---",
            f"Expected BLE name:        {na.expected_name} ({na.char_count} chars, {na.utf8_byte_count} UTF-8 bytes)",
            f"Exceeds 15-char NetBIOS:  {'yes' if na.exceeds_netbios_limit else 'no'}",
            f"15-char truncated form:   {na.netbios_truncated_name} (suffix {na.truncated_suffix!r} vs expected {na.expected_suffix!r})",
            f"If truncated — discovery: {na.app_discovery_if_truncated}",
            f"If truncated — pairing:   {na.app_pairing_if_truncated}",
            f"Truncation proven:        {'yes' if na.netbios_truncation_proven else 'no'}",
            f"Truncation suspected:     {'yes' if na.netbios_truncation_suspected else 'no'}",
            f"Evidence:                 {na.truncation_evidence}",
            "",
            "--- Host & Adapter Probe ---",
            f"Platform / Admin:         {h.platform} (is_windows={h.is_windows}, is_admin={h.is_admin})",
            f"Current NetBIOS name:     {h.netbios_name or '(unknown)'} ({len(h.netbios_name)} chars)",
            f"Current DNS hostname:     {h.dns_hostname or '(unknown)'} ({len(h.dns_hostname)} chars)",
            f"Current BT radio name:    {h.radio_name or '(unknown)'} ({len(h.radio_name)} chars)",
            f"BT adapter instance:      {h.adapter_instance_id or '(not detected)'}",
            f"BT adapter friendly name: {h.adapter_friendly_name or '(not detected)'}",
            f"Registry Local Name set:  {h.adapter_reg_local_name_text or '(none)'}",
            f"Bumble stack installed:   {'yes' if h.bumble_available else 'no'}",
            "",
            "--- Mode Verdicts ---",
        ]
        for key in ("primary-adapter", "primary-rename", "secondary-dongle"):
            mv = self.verdicts[key]
            lines.append(f"[{mv.verdict.value}] {mv.mode}: {mv.summary}")
            for detail in mv.details:
                lines.append(f"    - {detail}")
        lines.append("")
        lines.append(f"OVERALL VERDICT: {self.overall_verdict.value}")
        return "\n".join(lines)


def run_preflight(
    state_dir: Path | None = None,
    *,
    probe: HostProbe | None = None,
    secondary_hci_transport: str = "",
) -> PreflightReport:
    """Run a strictly read-only preflight check; never writes or mutates state."""
    resolved_dir = state_dir or config.state_dir()
    stored_ident = config.load_json(config.IDENTITY_FILE, resolved_dir) or {}
    mac = stored_ident.get("mac")
    if isinstance(mac, str) and mac:
        ident = Identity(mac)
    else:
        # Read-only fallback if identity.json has not been created yet:
        # do not call load_or_create() because preflight must not write files.
        ident = Identity("fe:35:a9:38:55:d8")

    paired = bool(config.load_json(config.PAIRING_FILE, resolved_dir))
    host = probe or probe_host(secondary_hci_transport=secondary_hci_transport)
    analysis = analyze_ble_name(
        ident,
        current_netbios=host.netbios_name,
        current_dns=host.dns_hostname,
        current_radio_name=host.radio_name,
    )

    verdicts: dict[str, ModeVerdict] = {}

    # 1. Primary Mode Path 1A: Adapter registry Local Name override (no reboot)
    if host.radio_name == analysis.expected_name:
        verdicts["primary-adapter"] = ModeVerdict(
            mode="primary-adapter",
            verdict=Verdict.GO,
            summary=f"Radio already reports full {analysis.char_count}-char {analysis.expected_name}.",
            details=("Open `musegadget_win.py pair` directly and pair from the Muse app.",),
        )
    elif host.is_windows and (host.radio_present or host.adapter_instance_id):
        verdicts["primary-adapter"] = ModeVerdict(
            mode="primary-adapter",
            verdict=Verdict.GO_WITH_RISK,
            summary=(
                "Adapter `Device Parameters\\Local Name` (REG_BINARY) can store "
                f"{analysis.char_count} chars without renaming the PC or rebooting."
            ),
            details=(
                "UNVERIFIED on hardware whether Realtek/bthport.sys honours `Local Name` "
                "across a PnP radio bounce without reverting to NetBIOS.",
                "Safe first step: `apply --mode adapter --execute` tests this and checks "
                "`BluetoothGetRadioInfo.szName` immediately.",
            ),
        )
    else:
        verdicts["primary-adapter"] = ModeVerdict(
            mode="primary-adapter",
            verdict=Verdict.NO_GO,
            summary="No Windows Bluetooth radio adapter detected on this host.",
            details=("Run on the target Windows PC with an active Bluetooth adapter.",),
        )

    # 2. Primary Mode Path 1B: Full Computer Rename (SetComputerNameExW + reboot)
    if not analysis.exceeds_netbios_limit and host.is_windows:
        verdicts["primary-rename"] = ModeVerdict(
            mode="primary-rename",
            verdict=Verdict.GO,
            summary=f"Expected BLE name ({analysis.char_count} chars) fits within the 15-char NetBIOS limit.",
        )
    elif analysis.netbios_truncation_proven:
        verdicts["primary-rename"] = ModeVerdict(
            mode="primary-rename",
            verdict=Verdict.NO_GO,
            summary=(
                f"Host proves NetBIOS truncation: {analysis.expected_name} ({analysis.char_count} chars) "
                f"will truncate to {analysis.netbios_truncated_name} (15 chars) and fail suffix match."
            ),
            details=(
                analysis.truncation_evidence,
                "Use `primary-adapter` or `secondary-dongle` instead.",
            ),
        )
    elif not host.is_windows:
        verdicts["primary-rename"] = ModeVerdict(
            mode="primary-rename",
            verdict=Verdict.NO_GO,
            summary="Not running on Windows; computer rename applies only on the Windows PC.",
            details=(analysis.truncation_evidence,),
        )
    else:
        verdicts["primary-rename"] = ModeVerdict(
            mode="primary-rename",
            verdict=Verdict.GO_WITH_RISK,
            summary=(
                f"{analysis.expected_name} is {analysis.char_count} chars (>15-byte NetBIOS limit); "
                "SetComputerNameExW sets 17-char DNS hostname and 15-char NetBIOS name."
            ),
            details=(
                analysis.truncation_evidence,
                f"If bthport uses NetBIOS, advertised name truncates to {analysis.netbios_truncated_name} "
                f"({analysis.app_pairing_if_truncated}).",
                "Try `primary-adapter` first; if rename is used, verify `BluetoothGetRadioInfo.szName` "
                "after reboot before attempting phone pairing.",
            ),
        )

    # 3. Secondary Mode: Dual-radio Bumble bridge on the PC
    if host.bumble_available and host.secondary_hci_transport:
        verdicts["secondary-dongle"] = ModeVerdict(
            mode="secondary-dongle",
            verdict=Verdict.GO,
            summary=(
                f"Bumble installed and HCI transport {host.secondary_hci_transport!r} configured; "
                f"advertises full 17-char {analysis.expected_name} and relays to built-in radio."
            ),
        )
    elif host.bumble_available:
        verdicts["secondary-dongle"] = ModeVerdict(
            mode="secondary-dongle",
            verdict=Verdict.GO_WITH_RISK,
            summary=(
                "Bumble stack is installed; plug in a dedicated USB BLE dongle (WinUSB via Zadig) "
                "or HCI-UART serial board and pass `--hci-transport` (e.g. `usb:0` or `serial:COM3`)."
            ),
            details=(
                "Keep the built-in Realtek Bluetooth adapter on the Windows driver so "
                "`musegadget_win.py pair` runs alongside the dongle.",
            ),
        )
    else:
        verdicts["secondary-dongle"] = ModeVerdict(
            mode="secondary-dongle",
            verdict=Verdict.NO_GO,
            summary="Python `bumble` package is not installed in this environment.",
            details=("Install with `pip install bumble` and attach a dedicated USB BLE dongle.",),
        )

    all_v = [mv.verdict for mv in verdicts.values()]
    if Verdict.GO in all_v:
        overall = Verdict.GO
    elif Verdict.GO_WITH_RISK in all_v:
        overall = Verdict.GO_WITH_RISK
    else:
        overall = Verdict.NO_GO

    return PreflightReport(
        state_dir=str(resolved_dir),
        device_id=ident.device_id,
        node_id=ident.node_id,
        paired=paired,
        name_analysis=analysis,
        host=host,
        verdicts=verdicts,
        overall_verdict=overall,
    )


# --- Backup and State Machine ------------------------------------------------


@dataclass(frozen=True)
class BridgeBackup:
    """Immutable backup of the PC's original identity before any translation."""

    original_netbios_name: str
    original_dns_hostname: str
    original_radio_name: str
    adapter_instance_id: str = ""
    original_adapter_local_name_hex: str = ""
    created_at: float = 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BridgeBackup":
        return cls(
            original_netbios_name=str(data.get("original_netbios_name") or ""),
            original_dns_hostname=str(data.get("original_dns_hostname") or ""),
            original_radio_name=str(data.get("original_radio_name") or ""),
            adapter_instance_id=str(data.get("adapter_instance_id") or ""),
            original_adapter_local_name_hex=str(data.get("original_adapter_local_name_hex") or ""),
            created_at=float(data.get("created_at") or 0.0),
        )


@dataclass
class BridgeState:
    """Persisted state machine record in `<state_dir>/pc_bridge/state.json`."""

    phase: BridgePhase = BridgePhase.IDLE
    mode: str = "none"
    target_ble_name: str = ""
    continuation_registered: bool = False
    continuation_task_name: str = CONTINUATION_TASK_NAME
    paired: bool = False
    updated_at: float = 0.0
    last_action: str = "init"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["phase"] = self.phase.value
        return out

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "BridgeState":
        raw_phase = str(data.get("phase") or BridgePhase.IDLE.value)
        try:
            phase = BridgePhase(raw_phase)
        except ValueError:
            phase = BridgePhase.IDLE
        return cls(
            phase=phase,
            mode=str(data.get("mode") or "none"),
            target_ble_name=str(data.get("target_ble_name") or ""),
            continuation_registered=bool(data.get("continuation_registered")),
            continuation_task_name=str(data.get("continuation_task_name") or CONTINUATION_TASK_NAME),
            paired=bool(data.get("paired")),
            updated_at=float(data.get("updated_at") or 0.0),
            last_action=str(data.get("last_action") or ""),
            notes=[str(n) for n in (data.get("notes") or [])],
        )


def bridge_dir(state_dir: Path | None = None) -> Path:
    return (state_dir or config.state_dir()) / PC_BRIDGE_SUBDIR


def load_backup(state_dir: Path | None = None) -> BridgeBackup | None:
    raw = config.load_json(BACKUP_FILE, bridge_dir(state_dir))
    return BridgeBackup.from_dict(raw) if raw else None


def ensure_backup(
    state_dir: Path | None = None,
    probe: HostProbe | None = None,
    *,
    clock: Callable[[], float] = time.time,
) -> BridgeBackup:
    """Save the original identity backup if none exists; NEVER overwrite an existing backup."""
    existing = load_backup(state_dir)
    if existing is not None:
        return existing

    h = probe or probe_host()
    backup = BridgeBackup(
        original_netbios_name=h.netbios_name,
        original_dns_hostname=h.dns_hostname or h.netbios_name,
        original_radio_name=h.radio_name or h.netbios_name,
        adapter_instance_id=h.adapter_instance_id,
        original_adapter_local_name_hex=h.adapter_reg_local_name_hex,
        created_at=clock(),
    )
    config.save_json(BACKUP_FILE, asdict(backup), bridge_dir(state_dir))
    return backup


def load_state(state_dir: Path | None = None) -> BridgeState:
    raw = config.load_json(STATE_FILE, bridge_dir(state_dir))
    if not raw:
        return BridgeState()
    return BridgeState.from_dict(raw)


def save_state(state: BridgeState, state_dir: Path | None = None) -> None:
    config.save_json(STATE_FILE, state.to_dict(), bridge_dir(state_dir))


def get_status(
    state_dir: Path | None = None,
    *,
    clock: Callable[[], float] = time.time,
) -> BridgeState:
    """Return the current state machine status, advancing to `paired-restore-pending`
    automatically if `pairing.json` has been written while a translation is active.
    """
    resolved_dir = state_dir or config.state_dir()
    state = load_state(resolved_dir)
    paired_now = bool(config.load_json(config.PAIRING_FILE, resolved_dir))
    changed = False

    if paired_now != state.paired:
        state.paired = paired_now
        changed = True

    if paired_now and state.phase in (
        BridgePhase.RENAMED_AWAITING_REBOOT,
        BridgePhase.PAIRING_WINDOW,
    ):
        state.phase = BridgePhase.PAIRED_RESTORE_PENDING
        state.last_action = "pairing_detected"
        state.updated_at = clock()
        state.notes.append("pairing.json detected; ready to restore original identity.")
        changed = True

    if changed and (bridge_dir(resolved_dir) / STATE_FILE).exists():
        save_state(state, resolved_dir)

    return state


@dataclass(frozen=True)
class CommandSpec:
    """One PowerShell / process operation in an apply or restore sequence."""

    step: str
    description: str
    argv: tuple[str, ...]


@dataclass(frozen=True)
class ActionResult:
    """Result of `apply`, `continue_pairing`, or `restore`."""

    dry_run: bool
    state: BridgeState
    backup: BridgeBackup | None
    commands: tuple[CommandSpec, ...]


CommandRunner = Callable[[CommandSpec], None]


def default_command_runner(spec: CommandSpec) -> None:
    """Execute a `CommandSpec` on Windows; raise RuntimeError on non-zero exit."""
    if sys.platform != "win32":
        raise RuntimeError(
            f"Cannot execute Windows helper step {spec.step!r} on {sys.platform}; "
            "use --dry-run on Linux or pass a simulated runner in tests."
        )
    proc = subprocess.run(
        list(spec.argv),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or f"exit code {proc.returncode}").strip()
        raise RuntimeError(f"Step {spec.step!r} failed: {detail}")


def _build_apply_commands(
    *,
    mode: str,
    target_ble_name: str,
    adapter_instance_id: str,
    state_dir: Path,
    dry_run: bool,
    python_exe: str | None = None,
    script_path: Path | None = None,
) -> list[CommandSpec]:
    whatif = ("-WhatIf",) if dry_run else ()
    py = python_exe or sys.executable
    cli_script = script_path or (WINDOWS_DIR / "musegadget_pc_bridge.py")
    cmds: list[CommandSpec] = []

    if mode == "adapter":
        argv = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(ADAPTER_NAME_PS1),
            "-Action",
            "Set",
            "-NewName",
            target_ble_name,
        ]
        if adapter_instance_id:
            argv.extend(["-InstanceId", adapter_instance_id])
        argv.extend(whatif)
        cmds.append(
            CommandSpec(
                step="translate-adapter-name",
                description=(
                    f"Set Bluetooth adapter registry `Local Name` to {target_ble_name!r} "
                    "and bounce radio."
                ),
                argv=tuple(argv),
            )
        )
    elif mode == "rename":
        argv = [
            "powershell.exe",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(RENAME_COMPUTER_PS1),
            "-Action",
            "Set",
            "-NewName",
            target_ble_name,
            *whatif,
        ]
        cmds.append(
            CommandSpec(
                step="translate-computer-name",
                description=(
                    f"Set physical DNS hostname to {target_ble_name!r} via SetComputerNameExW."
                ),
                argv=tuple(argv),
            )
        )
    else:
        raise ValueError(f"Unsupported primary translation mode: {mode!r}")

    reg_argv = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCHEDULED_TASK_PS1),
        "-Action",
        "Register",
        "-TaskName",
        CONTINUATION_TASK_NAME,
        "-PythonExe",
        str(py),
        "-ScriptPath",
        str(cli_script),
        "-StateDir",
        str(state_dir),
        *whatif,
    ]
    cmds.append(
        CommandSpec(
            step="register-continuation",
            description=(
                f"Register Scheduled Task {CONTINUATION_TASK_NAME!r} to run "
                "`musegadget_pc_bridge.py continue` after reboot/logon."
            ),
            argv=tuple(reg_argv),
        )
    )
    return cmds


def _build_restore_commands(
    backup: BridgeBackup | None,
    *,
    mode: str,
    dry_run: bool,
) -> list[CommandSpec]:
    whatif = ("-WhatIf",) if dry_run else ()
    cmds: list[CommandSpec] = []

    if backup is not None:
        if mode in ("adapter", "both", "none") or backup.adapter_instance_id or backup.original_adapter_local_name_hex:
            argv = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(ADAPTER_NAME_PS1),
                "-Action",
                "Restore",
            ]
            if backup.adapter_instance_id:
                argv.extend(["-InstanceId", backup.adapter_instance_id])
            if backup.original_adapter_local_name_hex:
                argv.extend(["-OriginalLocalNameHex", backup.original_adapter_local_name_hex])
            argv.extend(whatif)
            cmds.append(
                CommandSpec(
                    step="restore-adapter-name",
                    description="Restore original Bluetooth adapter registry `Local Name` and bounce radio.",
                    argv=tuple(argv),
                )
            )

        orig_host = backup.original_dns_hostname or backup.original_netbios_name
        if orig_host and mode in ("rename", "both"):
            argv = [
                "powershell.exe",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(RENAME_COMPUTER_PS1),
                "-Action",
                "Restore",
                "-NewName",
                orig_host,
                *whatif,
            ]
            cmds.append(
                CommandSpec(
                    step="restore-computer-name",
                    description=f"Restore computer name to {orig_host!r} via SetComputerNameExW.",
                    argv=tuple(argv),
                )
            )

    unreg_argv = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(SCHEDULED_TASK_PS1),
        "-Action",
        "Unregister",
        "-TaskName",
        CONTINUATION_TASK_NAME,
        *whatif,
    ]
    cmds.append(
        CommandSpec(
            step="unregister-continuation",
            description=f"Unregister Scheduled Task {CONTINUATION_TASK_NAME!r}.",
            argv=tuple(unreg_argv),
        )
    )
    return cmds


def apply_translation(
    state_dir: Path | None = None,
    *,
    mode: str = "adapter",
    dry_run: bool = True,
    allow_truncation_risk: bool = False,
    require_reboot: bool | None = None,
    probe: HostProbe | None = None,
    runner: CommandRunner | None = None,
    clock: Callable[[], float] = time.time,
) -> ActionResult:
    """Plan or execute the primary-mode Bluetooth identity translation.

    Defaults to `dry_run=True`, which never creates or mutates any files and
    never runs external commands.
    """
    if mode not in ("adapter", "rename"):
        raise ValueError(f"mode must be 'adapter' or 'rename', got {mode!r}")

    resolved_dir = state_dir or config.state_dir()
    host = probe or probe_host()

    stored_ident = config.load_json(config.IDENTITY_FILE, resolved_dir) or {}
    mac = stored_ident.get("mac")
    if isinstance(mac, str) and mac:
        ident = Identity(mac)
    elif dry_run:
        ident = Identity("fe:35:a9:38:55:d8")
    else:
        ident = identity.load_or_create(resolved_dir)

    analysis = analyze_ble_name(
        ident,
        current_netbios=host.netbios_name,
        current_dns=host.dns_hostname,
        current_radio_name=host.radio_name,
    )

    if mode == "rename" and analysis.exceeds_netbios_limit:
        if analysis.netbios_truncation_proven and not allow_truncation_risk:
            raise BridgePreflightError(
                f"Refusing computer rename to {analysis.expected_name!r} ({analysis.char_count} chars): "
                f"host proves 15-char NetBIOS truncation ({analysis.netbios_truncated_name!r}), which "
                f"fails Muse app suffix validation ({analysis.truncated_suffix!r} != {analysis.expected_suffix!r}). "
                "Use `--mode adapter` or `secondary-run`, or pass `--allow-truncation-risk` to override."
            )
        if analysis.netbios_truncation_suspected and not allow_truncation_risk:
            raise BridgePreflightError(
                f"Refusing computer rename to {analysis.expected_name!r} ({analysis.char_count} chars): "
                f"current radio/NetBIOS name ({host.radio_name or host.netbios_name!r}) indicates 15-char "
                f"NetBIOS truncation ({analysis.netbios_truncated_name!r}). "
                "Try `--mode adapter` or `secondary-run` first, or pass `--allow-truncation-risk`."
            )

    existing_backup = load_backup(resolved_dir)
    preview_backup = existing_backup or BridgeBackup(
        original_netbios_name=host.netbios_name,
        original_dns_hostname=host.dns_hostname or host.netbios_name,
        original_radio_name=host.radio_name or host.netbios_name,
        adapter_instance_id=host.adapter_instance_id,
        original_adapter_local_name_hex=host.adapter_reg_local_name_hex,
        created_at=clock(),
    )

    commands = _build_apply_commands(
        mode=mode,
        target_ble_name=ident.ble_name,
        adapter_instance_id=preview_backup.adapter_instance_id or host.adapter_instance_id,
        state_dir=resolved_dir,
        dry_run=dry_run,
    )

    needs_reboot = (mode == "rename") if require_reboot is None else require_reboot
    next_phase = (
        BridgePhase.RENAMED_AWAITING_REBOOT
        if needs_reboot
        else BridgePhase.PAIRING_WINDOW
    )

    if dry_run:
        current_state = load_state(resolved_dir)
        return ActionResult(
            dry_run=True,
            state=current_state,
            backup=existing_backup,
            commands=tuple(commands),
        )

    backup = ensure_backup(resolved_dir, host, clock=clock)
    exec_runner = runner or default_command_runner
    for cmd in commands:
        exec_runner(cmd)

    paired_now = bool(config.load_json(config.PAIRING_FILE, resolved_dir))
    state = BridgeState(
        phase=BridgePhase.PAIRED_RESTORE_PENDING if paired_now else next_phase,
        mode=mode,
        target_ble_name=ident.ble_name,
        continuation_registered=True,
        continuation_task_name=CONTINUATION_TASK_NAME,
        paired=paired_now,
        updated_at=clock(),
        last_action=f"apply:{mode}",
        notes=[
            f"Translated identity to {ident.ble_name} via mode={mode}; "
            f"original backup preserved ({backup.original_radio_name or backup.original_netbios_name})."
        ],
    )
    save_state(state, resolved_dir)
    return ActionResult(
        dry_run=False,
        state=state,
        backup=backup,
        commands=tuple(commands),
    )


def restore_identity(
    state_dir: Path | None = None,
    *,
    dry_run: bool = False,
    runner: CommandRunner | None = None,
    clock: Callable[[], float] = time.time,
) -> ActionResult:
    """Idempotently restore the original computer/Bluetooth name from `backup.json`
    and remove the continuation task, from ANY state and regardless of whether
    pairing succeeded.
    """
    resolved_dir = state_dir or config.state_dir()
    backup = load_backup(resolved_dir)
    prior_state = load_state(resolved_dir)

    restore_mode = prior_state.mode if prior_state.mode in ("adapter", "rename") else "both"
    commands = _build_restore_commands(backup, mode=restore_mode, dry_run=dry_run)

    if dry_run:
        return ActionResult(
            dry_run=True,
            state=prior_state,
            backup=backup,
            commands=tuple(commands),
        )

    exec_runner = runner or default_command_runner
    for cmd in commands:
        exec_runner(cmd)

    paired_now = bool(config.load_json(config.PAIRING_FILE, resolved_dir))
    restored_target = (
        (backup.original_radio_name or backup.original_dns_hostname or backup.original_netbios_name)
        if backup
        else "(no backup file)"
    )
    new_state = BridgeState(
        phase=BridgePhase.RESTORED,
        mode=prior_state.mode,
        target_ble_name=prior_state.target_ble_name,
        continuation_registered=False,
        continuation_task_name=CONTINUATION_TASK_NAME,
        paired=paired_now,
        updated_at=clock(),
        last_action="restore",
        notes=[
            *prior_state.notes,
            f"Restored original identity ({restored_target}) and removed continuation task.",
        ],
    )
    save_state(new_state, resolved_dir)
    return ActionResult(
        dry_run=False,
        state=new_state,
        backup=backup,
        commands=tuple(commands),
    )


def continue_pairing(
    state_dir: Path | None = None,
    *,
    dry_run: bool = False,
    run_pair_fn: Callable[[Path], bool] | None = None,
    auto_restore: bool = True,
    runner: CommandRunner | None = None,
    clock: Callable[[], float] = time.time,
) -> ActionResult:
    """Post-reboot / post-apply continuation step:

    1. Transitions `state.json` into `pairing-window`.
    2. Invokes `run_pair_fn(state_dir)` (default: runs `musegadget_win.py pair`)
       or detects an existing `pairing.json`.
    3. When `pairing.json` exists, transitions to `paired-restore-pending`.
    4. If `auto_restore=True`, immediately restores the original name and removes
       the continuation task (`restored`).
    """
    resolved_dir = state_dir or config.state_dir()
    prior_state = load_state(resolved_dir)
    backup = load_backup(resolved_dir)

    if dry_run:
        restore_cmds = _build_restore_commands(
            backup,
            mode=prior_state.mode if prior_state.mode in ("adapter", "rename") else "both",
            dry_run=True,
        )
        return ActionResult(
            dry_run=True,
            state=prior_state,
            backup=backup,
            commands=tuple(restore_cmds),
        )

    prior_state.phase = BridgePhase.PAIRING_WINDOW
    prior_state.last_action = "continue:pairing-window"
    prior_state.updated_at = clock()
    prior_state.notes.append("Entered pairing window.")
    save_state(prior_state, resolved_dir)

    if not config.load_json(config.PAIRING_FILE, resolved_dir):
        if run_pair_fn is not None:
            run_pair_fn(resolved_dir)
        else:
            _default_run_pair_window(resolved_dir)

    paired_now = bool(config.load_json(config.PAIRING_FILE, resolved_dir))
    prior_state.paired = paired_now
    if paired_now:
        prior_state.phase = BridgePhase.PAIRED_RESTORE_PENDING
        prior_state.last_action = "continue:paired-restore-pending"
        prior_state.updated_at = clock()
        prior_state.notes.append("pairing.json detected; restore pending.")
        save_state(prior_state, resolved_dir)

    if auto_restore:
        return restore_identity(
            resolved_dir,
            dry_run=False,
            runner=runner,
            clock=clock,
        )

    return ActionResult(
        dry_run=False,
        state=prior_state,
        backup=backup,
        commands=(),
    )


def _default_run_pair_window(state_dir: Path) -> bool:
    """Run `musegadget_win.py pair` with `MUSEGADGET_STATE_DIR=state_dir`."""
    env = dict(os.environ)
    env[config.STATE_DIR_ENV] = str(state_dir)
    win_entry = WINDOWS_DIR / "musegadget_win.py"
    subprocess.run(
        [sys.executable, str(win_entry), "pair"],
        env=env,
        check=False,
    )
    return bool(config.load_json(config.PAIRING_FILE, state_dir))
