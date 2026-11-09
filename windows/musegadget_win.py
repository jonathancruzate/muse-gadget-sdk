# Part of the Windows port of the Muse gadget SDK.
#
# Entrypoint that runs the vendored musegadget package on Windows:
#
#   python musegadget_win.py pair [--force]   open Bluetooth setup and pair
#   python musegadget_win.py run              serve the paired device (steady state)
#   python musegadget_win.py info             show identity and pairing state
#
# The vendored package is upstream's Linux build, unmodified except for the
# platform branches in executor.py. Two Linux-only pieces are swapped here,
# in this file, instead of being edited in place:
#
# * ``musegadget.ble_server`` (BlueZ/D-Bus) is replaced in sys.modules by a
#   shim whose BleServer is the WinRT implementation in
#   musegadget/ble_server_windows.py. pair() imports it lazily, by name, so
#   the shim is picked up exactly where the BlueZ server would be.
# * ``musegadget.service.run_service`` (which also opens the Linux local
#   Unix socket) is not used; the Service is run directly, without the
#   local socket. The socket only serves the Linux `send-user-msg`
#   command, which this port does not ship.
#
# State lives in %USERPROFILE%\musegadget\state unless MUSEGADGET_STATE_DIR
# says otherwise; the SDK token is read from that directory's sdk_token
# file (or the MUSEGADGET_SDK_TOKEN environment variable), exactly as
# upstream's config.py defines. The token value is never printed.

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import types
from pathlib import Path

# The state directory must be decided before musegadget.config is imported.
os.environ.setdefault(
    "MUSEGADGET_STATE_DIR", str(Path.home() / "musegadget" / "state"))

from musegadget import config  # noqa: E402
from musegadget.ble_server_windows import BleServerWinRT  # noqa: E402

log = logging.getLogger("musegadget")

# The name this PC registers with Muse once paired (Jonathan's order,
# 2026-11-03: rename the gadget to "PC"). This is the steady-state
# display_name only — the BLE pairing name stays MuseGadget-<suffix>,
# because the Muse app matches it against the node id (identity.py).
DISPLAY_NAME = "PC"


def _install_ble_shim() -> None:
    """Make `from musegadget.ble_server import BleServer` resolve to WinRT."""
    shim = types.ModuleType("musegadget.ble_server")
    shim.BleServer = BleServerWinRT  # type: ignore[attr-defined]
    sys.modules["musegadget.ble_server"] = shim


def cmd_pair(args: argparse.Namespace) -> int:
    from musegadget import pair as pair_mod

    def on_open(window) -> None:
        print()
        print(f"Bluetooth setup is open for {window.timeout_s // 60} minutes.")
        print(f"In the Muse app: Settings > Devices > Developer mode on, "
              f"then Add Device and choose {window.ble_name}.")
        print("Waiting for the Muse app to pair this PC...")

    result = pair_mod.pair(on_open=on_open, force=args.force)
    outcome = result.outcome
    if outcome is pair_mod.PairOutcome.PAIRED:
        print("Paired. This PC is now a Muse device; run "
              "`python musegadget_win.py run` to bring it online.")
        return 0
    if outcome is pair_mod.PairOutcome.ALREADY_PAIRED:
        print("Already paired. Use --force to pair again.")
        return 0
    if outcome is pair_mod.PairOutcome.INVALID_SDK_TOKEN:
        print(f"The SDK token was rejected: {result.sdk_token_problem}")
        print(f"Put a valid token in {config.state_dir() / 'sdk_token'} "
              "and try again.")
        return 2
    print("The setup window closed without pairing. Run pair again when ready.")
    return 2


def cmd_run(_args: argparse.Namespace) -> int:
    from musegadget import identity
    from musegadget.executor import Account, Executor
    from musegadget.service import Service

    if not config.load_json(config.PAIRING_FILE):
        print("Not paired yet. Run `python musegadget_win.py pair` first.")
        return 2
    try:
        sdk_token = config.sdk_token()
    except ValueError:
        sdk_token = None
    service = Service(
        identity=identity.load_or_create(),
        executor=Executor(Account.current()),
        sdk_token=sdk_token,
        display_name=DISPLAY_NAME,
    )

    async def main() -> None:
        await service.run()

    print("Serving this PC as a Muse device. Ctrl+C stops it.")
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    return 0


def cmd_info(_args: argparse.Namespace) -> int:
    from musegadget import identity

    ident = identity.load_or_create()
    paired = bool(config.load_json(config.PAIRING_FILE))
    print(f"state directory: {config.state_dir()}")
    print(f"device id:       {ident.device_id}")
    print(f"node id:         {ident.node_id}")
    print(f"display name:    {DISPLAY_NAME}")
    print(f"Bluetooth name:  {ident.ble_name}")
    print(f"paired:          {'yes' if paired else 'no'}")
    return 0


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    _install_ble_shim()
    parser = argparse.ArgumentParser(
        prog="musegadget_win",
        description="Run this Windows PC as a Muse device (gadget SDK port).")
    sub = parser.add_subparsers(dest="command", required=True)
    pair_parser = sub.add_parser("pair", help="open Bluetooth setup and pair")
    pair_parser.add_argument("--force", action="store_true",
                             help="pair again even if a pairing is saved")
    pair_parser.set_defaults(fn=cmd_pair)
    run_parser = sub.add_parser("run", help="serve the paired device")
    run_parser.set_defaults(fn=cmd_run)
    info_parser = sub.add_parser("info", help="show identity and pairing state")
    info_parser.set_defaults(fn=cmd_info)
    args = parser.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
