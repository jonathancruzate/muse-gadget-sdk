#!/usr/bin/env python3
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

"""PC-resident Muse Gadget Bluetooth identity bridge CLI.

Subcommands:
  preflight      Read-only check of identity, 17-char vs 15-char NetBIOS risk,
                 current computer/Bluetooth names, adapter info, and per-mode
                 GO / GO-WITH-RISK / NO-GO verdicts. Changes nothing.
  apply          Translate PC Bluetooth identity for the pairing window
                 (DEFAULT: --dry-run; pass --execute to apply). Never overwrites
                 an existing backup.
  continue       Post-reboot/apply continuation: open `musegadget_win.py pair`,
                 watch for `pairing.json`, and restore original identity.
  restore        Standalone, idempotent restore of the original name from backup
                 and removal of the continuation task, from any state.
  status         Show current state-machine phase (`idle`,
                 `renamed-awaiting-reboot`, `pairing-window`,
                 `paired-restore-pending`, `restored`) and backup summary.
  secondary-run  Run the secondary-mode dual-radio Bumble bridge on the PC
                 using a dedicated USB BLE dongle (`--hci-transport usb:0`) or
                 HCI-UART serial board (`--hci-transport serial:COM3,1000000`).
"""

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

os.environ.setdefault(
    "MUSEGADGET_STATE_DIR", str(Path.home() / "musegadget" / "state")
)

from musegadget import config, identity  # noqa: E402
from musegadget.ble_bridge import BridgeConfig  # noqa: E402
from musegadget.pc_bridge import (  # noqa: E402
    BridgePreflightError,
    apply_translation,
    continue_pairing,
    get_status,
    load_backup,
    restore_identity,
    run_preflight,
)
from musegadget.pc_bridge_bumble import build_bumble_bridge  # noqa: E402


def _resolve_state_dir(args: argparse.Namespace) -> Path:
    explicit = getattr(args, "sub_state_dir", None) or getattr(args, "state_dir", None)
    if explicit:
        return Path(explicit)
    return config.state_dir()


def cmd_preflight(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    report = run_preflight(
        state_dir,
        secondary_hci_transport=args.hci_transport or "",
    )
    if args.json:
        payload = dataclasses.asdict(report)
        payload["overall_verdict"] = report.overall_verdict.value
        for k, v in payload["verdicts"].items():
            v["verdict"] = report.verdicts[k].verdict.value
        print(json.dumps(payload, indent=2))
    else:
        print(report.format_report())
    return 0


def cmd_apply(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    dry_run = not bool(args.execute)
    try:
        result = apply_translation(
            state_dir,
            mode=args.mode,
            dry_run=dry_run,
            allow_truncation_risk=args.allow_truncation_risk,
        )
    except BridgePreflightError as exc:
        print(f"PREFLIGHT GATE BLOCKED APPLY: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"apply failed: {exc}", file=sys.stderr)
        return 1

    mode_banner = "DRY-RUN (no changes made)" if result.dry_run else "EXECUTED"
    print(f"=== Muse Gadget PC Bridge — Apply ({mode_banner}, mode={args.mode}) ===")
    print(f"State directory: {state_dir}")
    if result.backup is not None:
        print(
            f"Existing backup: preserved (netbios={result.backup.original_netbios_name!r}, "
            f"dns={result.backup.original_dns_hostname!r}, "
            f"radio={result.backup.original_radio_name!r})"
        )
    else:
        print("Backup step:     would write <state_dir>/pc_bridge/backup.json (never overwrites existing)")

    print("Planned / executed steps:")
    for i, cmd in enumerate(result.commands, 1):
        print(f"  {i}. [{cmd.step}] {cmd.description}")
        print(f"     cmd: {' '.join(cmd.argv)}")
    print(
        "  3. [post-reboot-continuation] Run `musegadget_pc_bridge.py continue --execute` "
        "-> opens `musegadget_win.py pair`, watches for `pairing.json`, then runs `restore`."
    )
    if not result.dry_run:
        print(f"Current phase:   {result.state.phase.value}")
    return 0


def cmd_continue(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    dry_run = not bool(args.execute)
    result = continue_pairing(
        state_dir,
        dry_run=dry_run,
        auto_restore=not args.no_auto_restore,
    )
    banner = "DRY-RUN" if result.dry_run else "EXECUTED"
    print(f"=== Muse Gadget PC Bridge — Continue ({banner}) ===")
    print(f"Phase:  {result.state.phase.value}")
    print(f"Paired: {'yes' if result.state.paired else 'no'}")
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    try:
        result = restore_identity(
            state_dir,
            dry_run=bool(args.dry_run),
        )
    except Exception as exc:  # noqa: BLE001
        print(f"restore failed: {exc}", file=sys.stderr)
        return 1

    banner = "DRY-RUN (no changes made)" if result.dry_run else "EXECUTED"
    print(f"=== Muse Gadget PC Bridge — Restore ({banner}) ===")
    if result.backup is not None:
        print(
            f"Restoring from backup: netbios={result.backup.original_netbios_name!r}, "
            f"dns={result.backup.original_dns_hostname!r}, "
            f"radio={result.backup.original_radio_name!r}"
        )
    else:
        print("No backup.json present; unregistering continuation task only.")
    for i, cmd in enumerate(result.commands, 1):
        print(f"  {i}. [{cmd.step}] {cmd.description}")
        print(f"     cmd: {' '.join(cmd.argv)}")
    print(f"Phase: {result.state.phase.value}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    state = get_status(state_dir)
    backup = load_backup(state_dir)
    if args.json:
        payload = state.to_dict()
        payload["backup"] = dataclasses.asdict(backup) if backup else None
        print(json.dumps(payload, indent=2))
        return 0

    print("=== Muse Gadget PC Bridge — Status ===")
    print(f"State directory:         {state_dir}")
    print(f"Phase:                   {state.phase.value}")
    print(f"Mode:                    {state.mode}")
    print(f"Target BLE name:         {state.target_ble_name or '(not set)'}")
    print(f"Continuation registered: {'yes' if state.continuation_registered else 'no'}")
    print(f"Paired (pairing.json):   {'yes' if state.paired else 'no'}")
    if backup is not None:
        print(
            f"Backup on disk:          yes (netbios={backup.original_netbios_name!r}, "
            f"dns={backup.original_dns_hostname!r}, radio={backup.original_radio_name!r})"
        )
    else:
        print("Backup on disk:          no")
    return 0


def cmd_secondary_run(args: argparse.Namespace) -> int:
    state_dir = _resolve_state_dir(args)
    stored_ident = config.load_json(config.IDENTITY_FILE, state_dir) or {}
    mac = stored_ident.get("mac")
    if isinstance(mac, str) and mac:
        ident = identity.Identity(mac)
    elif args.dry_run:
        ident = identity.Identity("fe:35:a9:38:55:d8")
    else:
        ident = identity.load_or_create(state_dir)

    target_names = tuple(args.target_name or ["POWERSPEC-G757-"])
    bridge_cfg = BridgeConfig.for_identity(
        ident,
        target_names=target_names,
        target_address=args.target_address,
    )
    if args.dry_run:
        print("=== Muse Gadget PC Bridge — Secondary Mode (DRY-RUN) ===")
        print(f"HCI transport:   {args.hci_transport}")
        print(f"Front BLE name:  {bridge_cfg.front_name} ({len(bridge_cfg.front_name)} chars)")
        print(f"Back PC target:  names={bridge_cfg.target_names}, address={bridge_cfg.target_address}")
        print(f"Service UUID:    {bridge_cfg.service_uuid}")
        return 0

    bridge, driver = build_bumble_bridge(bridge_cfg)
    print(f"Secondary-mode Bumble bridge advertising as {bridge_cfg.front_name} on {args.hci_transport}")
    print(f"Feeding PC WinRT GATT peripheral under { ', '.join(target_names) or args.target_address }")
    try:
        asyncio.run(driver.serve_hci_transport(args.hci_transport))
    except KeyboardInterrupt:
        pass
    stats = bridge.stats
    print(
        f"Bridged {stats.app_to_target_messages} messages phone -> PC, "
        f"{stats.target_to_app_messages} messages PC -> phone."
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="musegadget_pc_bridge",
        description="PC-resident Bluetooth name-translation bridge for Muse Gadget setup.",
    )
    parser.add_argument(
        "--state-dir",
        default=None,
        help="Muse Gadget state directory (defaults to $MUSEGADGET_STATE_DIR or ~/musegadget/state)",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    # preflight
    p_pre = sub.add_parser(
        "preflight",
        help="Read-only preflight check (17-char vs 15-char NetBIOS, adapter info, GO/NO-GO verdicts)",
    )
    p_pre.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_pre.add_argument(
        "--hci-transport",
        default="",
        help="Optional Bumble HCI transport string (e.g. usb:0 or serial:COM3,1000000)",
    )
    p_pre.add_argument("--json", action="store_true", help="Emit JSON output")
    p_pre.set_defaults(fn=cmd_preflight)

    # apply
    p_app = sub.add_parser(
        "apply",
        help="Apply primary-mode Bluetooth identity translation (defaults to --dry-run)",
    )
    p_app.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_app.add_argument(
        "--mode",
        choices=("adapter", "rename"),
        default="adapter",
        help="Primary translation path: 'adapter' (Device Parameters\\Local Name, no reboot) or 'rename' (SetComputerNameExW + reboot)",
    )
    p_app.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Show planned steps without modifying anything (default)",
    )
    p_app.add_argument(
        "--execute",
        "--no-dry-run",
        dest="execute",
        action="store_true",
        default=False,
        help="Actually execute the translation and write backup/state files",
    )
    p_app.add_argument(
        "--allow-truncation-risk",
        action="store_true",
        default=False,
        help="Override the 15-char NetBIOS truncation gate for --mode rename",
    )
    p_app.set_defaults(fn=cmd_apply)

    # continue
    p_cont = sub.add_parser(
        "continue",
        help="Post-reboot continuation: open pair window, watch for pairing.json, then restore",
    )
    p_cont.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_cont.add_argument("--dry-run", action="store_true", default=True, help="Dry-run (default)")
    p_cont.add_argument(
        "--execute",
        "--no-dry-run",
        dest="execute",
        action="store_true",
        default=False,
        help="Execute the continuation workflow",
    )
    p_cont.add_argument(
        "--no-auto-restore",
        action="store_true",
        default=False,
        help="Leave state in paired-restore-pending instead of automatically running restore",
    )
    p_cont.set_defaults(fn=cmd_continue)

    # restore
    p_res = sub.add_parser(
        "restore",
        help="Idempotently restore original identity from backup and remove continuation task",
    )
    p_res.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_res.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Preview restore commands without executing them",
    )
    p_res.set_defaults(fn=cmd_restore)

    # status
    p_stat = sub.add_parser(
        "status",
        help="Show current state-machine phase and backup status",
    )
    p_stat.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_stat.add_argument("--json", action="store_true", help="Emit JSON output")
    p_stat.set_defaults(fn=cmd_status)

    # secondary-run
    p_sec = sub.add_parser(
        "secondary-run",
        help="Run secondary-mode dual-radio Bumble bridge on the PC using a USB/serial BLE dongle",
    )
    p_sec.add_argument("--state-dir", dest="sub_state_dir", default=None, help="State directory override")
    p_sec.add_argument(
        "--hci-transport",
        default="usb:0",
        help="Bumble HCI transport string (e.g. usb:0, usb:0a12:0001, serial:COM3,1000000)",
    )
    p_sec.add_argument(
        "--target-name",
        action="append",
        default=[],
        help="Existing Bluetooth name of the PC's built-in radio (default: POWERSPEC-G757-)",
    )
    p_sec.add_argument(
        "--target-address",
        default=None,
        help="Bluetooth address of the PC's built-in radio, if known",
    )
    p_sec.add_argument("--dry-run", action="store_true", help="Print configuration and exit")
    p_sec.set_defaults(fn=cmd_secondary_run)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # Allow top-level --state-dir before subcommand as well as after subcommand
    if getattr(args, "state_dir", None) is None:
        # Check if top-level parser had --state-dir
        pass
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return int(args.fn(args))


if __name__ == "__main__":
    raise SystemExit(main())
