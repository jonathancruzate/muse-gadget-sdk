"""Tests for the Windows port pieces of the vendored musegadget package.

The vendored package's own suite (upstream's linux/tests, run against this
copy) covers the protocol: pairing v5, the setup state machine, the Noise
link client. These tests cover only what the port adds:

* the entrypoint's sys.modules shim that swaps the BlueZ peripheral for
  the WinRT one,
* ble_server_windows' import safety and Transport interface,
* the Windows branches in executor.py (the account fallback and the
  threaded child runner), exercised directly so they run on any OS.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

WINDOWS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WINDOWS_DIR))

import musegadget_win  # noqa: E402
from musegadget import executor  # noqa: E402
from musegadget.ble_server_windows import BleServerWinRT  # noqa: E402

try:
    import winrt.windows.devices.bluetooth  # noqa: F401
    HAVE_WINRT = True
except ImportError:
    HAVE_WINRT = False


def test_shim_installs_winrt_server_as_ble_server():
    musegadget_win._install_ble_shim()
    import musegadget.ble_server as ble_server_module

    assert ble_server_module.BleServer is BleServerWinRT
    # pair() imports exactly this name, lazily, so the shim is the server
    # a Windows pairing run constructs.
    from musegadget.ble_server import BleServer

    assert BleServer is BleServerWinRT


def test_ble_server_windows_has_the_transport_interface():
    for method in ("run", "stop", "send_packets", "mtu", "disconnect"):
        assert callable(getattr(BleServerWinRT, method)), method
    if HAVE_WINRT:
        server = BleServerWinRT("MuseGadgetTEST", lambda b: None, lambda: None)
        assert server.mtu() == 163  # the assumed MTU before a session exists
    else:
        # Without the winrt packages, construction fails loudly and clearly,
        # never silently at import time.
        try:
            BleServerWinRT("MuseGadgetTEST", lambda b: None, lambda: None)
        except RuntimeError as exc:
            assert "winrt" in str(exc)
        else:
            raise AssertionError("expected RuntimeError without winrt")


class _StubProbe:
    def __init__(self, radio_name):
        self.radio_name = radio_name


def _bare_server(local_name="MuseGadget-3855D8"):
    """A BleServerWinRT without WinRT: only the fields the name bridge uses."""
    server = object.__new__(BleServerWinRT)
    server._local_name = local_name
    server._name_bridge_active = False
    return server


def _stub_pc_bridge(monkeypatch, *, radio_name="MuseGadget-3855D8", fail=False):
    import types

    calls = []
    stub = types.ModuleType("pc_bridge")

    def apply_translation(**kwargs):
        calls.append(("apply", kwargs))
        if fail:
            raise RuntimeError("stub apply failure")

    def restore_identity(**kwargs):
        calls.append(("restore", kwargs))
        if fail:
            raise RuntimeError("stub restore failure")

    stub.apply_translation = apply_translation
    stub.restore_identity = restore_identity
    stub.probe_host = lambda: _StubProbe(radio_name)
    monkeypatch.setitem(sys.modules, "pc_bridge", stub)
    monkeypatch.setitem(sys.modules, "musegadget.pc_bridge", stub)
    # `from musegadget import pc_bridge` resolves through the package
    # attribute once the real submodule has been imported (test_pc_bridge
    # imports it), so the stub must replace that attribute too.
    import musegadget

    monkeypatch.setattr(musegadget, "pc_bridge", stub, raising=False)
    monkeypatch.delenv("MUSEGADGET_NO_NAME_BRIDGE", raising=False)
    return calls


def test_name_bridge_apply_uses_adapter_mode(monkeypatch):
    calls = _stub_pc_bridge(monkeypatch)
    server = _bare_server()
    server._apply_radio_name()
    assert calls == [("apply", {"mode": "adapter", "dry_run": False})]
    assert server._name_bridge_active is True


def test_name_bridge_apply_failure_is_best_effort(monkeypatch):
    _stub_pc_bridge(monkeypatch, fail=True)
    server = _bare_server()
    server._apply_radio_name()  # must not raise
    assert server._name_bridge_active is False


def test_name_bridge_opt_out_env(monkeypatch):
    calls = _stub_pc_bridge(monkeypatch)
    monkeypatch.setenv("MUSEGADGET_NO_NAME_BRIDGE", "1")
    server = _bare_server()
    server._apply_radio_name()
    assert calls == []
    assert server._name_bridge_active is False


def test_name_bridge_restore_only_when_active(monkeypatch):
    calls = _stub_pc_bridge(monkeypatch)
    server = _bare_server()
    server._restore_radio_name()
    assert calls == []
    server._name_bridge_active = True
    server._restore_radio_name()
    assert calls == [("restore", {})]
    assert server._name_bridge_active is False


def test_name_bridge_restore_failure_is_best_effort(monkeypatch):
    _stub_pc_bridge(monkeypatch, fail=True)
    server = _bare_server()
    server._name_bridge_active = True
    server._restore_radio_name()  # must not raise
    assert server._name_bridge_active is False


def test_account_falls_back_to_current_user_without_pwd(monkeypatch):
    monkeypatch.setattr(executor, "pwd", None)
    account = executor.Account.current()
    assert account.name
    assert account.home == str(Path.home())
    looked_up = executor.Account.lookup("whoever")
    assert looked_up.name == "whoever"
    assert looked_up.home == account.home


def test_run_child_windows_captures_output_and_exit_code():
    stdout, stderr, exit_code, timed_out = executor._run_child_windows(
        [sys.executable, "-c", "import sys; print('hello'); sys.exit(3)"],
        cwd=str(WINDOWS_DIR), timeout_s=30, stdin=None, options={"env": dict(os.environ)},
    )
    assert stdout.strip() == b"hello"
    assert stderr == b""
    assert exit_code == 3
    assert timed_out is False


def test_run_child_windows_feeds_stdin_and_times_out():
    stdout, _stderr, _rc, timed_out = executor._run_child_windows(
        [sys.executable, "-c", "import sys; print(sys.stdin.read().upper(), end='')"],
        cwd=str(WINDOWS_DIR), timeout_s=30, stdin=b"abc", options={"env": dict(os.environ)},
    )
    assert stdout == b"ABC"
    assert timed_out is False

    _out, _err, _rc, timed_out = executor._run_child_windows(
        [sys.executable, "-c", "import time; time.sleep(60)"],
        cwd=str(WINDOWS_DIR), timeout_s=0.5, stdin=None, options={"env": dict(os.environ)},
    )
    assert timed_out is True
