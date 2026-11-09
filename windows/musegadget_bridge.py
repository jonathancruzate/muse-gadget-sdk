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

"""Run the Muse Gadget name-translation bridge on a Linux host.

The bridge lets a Windows PC pair as a Muse gadget even though Windows
cannot advertise the ``MuseGadget-XXXXXX`` name the Muse app scans for.
See BRIDGE.md in the project root for the full picture.

Run order for a pairing:

1. On the PC, open its normal pairing window:  ``musegadget_win.py pair``
2. Here, start this bridge (it advertises the PC's MuseGadget name and
   connects to the PC's setup service under the PC's existing name).
3. In the Muse app: Settings > Devices > Developer mode on, then
   Add Device and choose the MuseGadget name shown below.

The bridge host needs the PC's ``identity.json`` (and nothing else) from
the PC's state directory, so the name it advertises is the PC's own:

    scp the PC's state\\identity.json to ./bridge-state/identity.json
    sudo python3 musegadget_bridge.py --state-dir ./bridge-state \
        --target-name POWERSPEC-G757-
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from musegadget import config, identity  # noqa: E402
from musegadget.ble_bridge import BridgeConfig  # noqa: E402
from musegadget.ble_bridge_bluez import build_bridge  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--state-dir", required=True,
        help="directory holding the PC's identity.json (NOT a live state dir)",
    )
    parser.add_argument(
        "--target-name", action="append", default=[],
        help="the PC's existing Bluetooth name (repeatable); "
             "e.g. POWERSPEC-G757-",
    )
    parser.add_argument(
        "--target-address", default=None,
        help="the PC's Bluetooth address, if known (name matching is skipped)",
    )
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    state_dir = Path(args.state_dir)
    if not (state_dir / config.IDENTITY_FILE).exists():
        print(f"no {config.IDENTITY_FILE} in {state_dir} — copy it from the PC's "
              "state directory first; the bridge must advertise the PC's own name.",
              file=sys.stderr)
        return 2
    if not args.target_name and not args.target_address:
        print("give --target-name (the PC's existing Bluetooth name) and/or "
              "--target-address so the bridge knows which device to feed.",
              file=sys.stderr)
        return 2

    ident = identity.load_or_create(state_dir)
    bridge_config = BridgeConfig.for_identity(
        ident,
        target_names=args.target_name,
        target_address=args.target_address,
    )
    bridge, driver = build_bridge(bridge_config)

    print()
    print(f"Bridge advertising as {bridge_config.front_name} "
          f"(node {ident.node_id}).")
    print(f"Feeding the PC advertising as "
          f"{', '.join(args.target_name) or args.target_address}.")
    print("On the PC the pairing window must be open "
          "(musegadget_win.py pair).")
    print("In the Muse app: Settings > Devices > Developer mode on, "
          f"then Add Device and choose {bridge_config.front_name}.")
    print("Ctrl+C stops the bridge; the pairing itself lives on the PC.")
    try:
        driver.run()
    except KeyboardInterrupt:
        pass
    stats = bridge.stats
    print(f"bridged {stats.app_to_target_messages} messages phone -> PC, "
          f"{stats.target_to_app_messages} messages PC -> phone "
          f"({stats.dropped_messages} dropped).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
