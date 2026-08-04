"""Tests for passive network-interface inspection.

The whole point of this module is what it does *not* do, so most of these
assert absences: no sockets, no DNS, no verdict about being air-gapped.
"""

from __future__ import annotations

import dataclasses
import os

import pytest

from morpheus_crypt.core.netcheck import (
    Interface,
    Kind,
    describe,
    inspect,
)


def _iface(root, name, *, carrier=None, operstate="up", wireless=False,
           physical=True):
    """Build a fake /sys/class/net entry."""
    d = root / name
    d.mkdir(parents=True)
    (d / "operstate").write_text(operstate + "\n")
    if carrier is not None:
        (d / "carrier").write_text(f"{1 if carrier else 0}\n")
    else:
        # A down interface makes the kernel return EINVAL on read. Simulate by
        # creating a directory where a file is expected, so the read raises.
        (d / "carrier").mkdir()
    if wireless:
        (d / "wireless").mkdir()
    if physical:
        (d / "device").mkdir()
    return d


class TestItNeverTouchesTheNetwork:
    """The one property that must never regress.

    A tool that checks connectivity by reaching out would send the packet an
    air-gapped user must not send, and would announce that MORPHEUS is running,
    when, and from what address. The check reads kernel state and nothing else.
    """

    # Checked against the parsed module rather than its text. A substring scan
    # fails both ways: it trips on the docstring promising "no subprocesses",
    # and it would miss `__import__("socket")`.
    FORBIDDEN_IMPORTS = {
        "socket", "ssl", "urllib", "http", "requests", "httpx",
        "subprocess", "ftplib", "smtplib", "telnetlib", "asyncio",
        "xmlrpc", "webbrowser",
    }

    def test_the_module_imports_no_network_machinery(self):
        import ast

        import morpheus_crypt.core.netcheck as mod

        tree = ast.parse(open(mod.__file__, encoding="utf-8").read())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id != "__import__", (
                    "netcheck imports dynamically, which defeats this guard"
                )

        offending = imported & self.FORBIDDEN_IMPORTS
        assert not offending, (
            f"netcheck imports {sorted(offending)}. It must read kernel state "
            f"only: probing the network is the one thing an air-gapped machine "
            f"must not do."
        )

    def test_inspecting_opens_no_sockets(self, tmp_path, monkeypatch):
        import socket

        def explode(*a, **kw):
            raise AssertionError("netcheck opened a socket")

        monkeypatch.setattr(socket, "socket", explode)
        monkeypatch.setattr(socket, "create_connection", explode)
        _iface(tmp_path, "eth0", carrier=True)
        inspect(sysfs_root=tmp_path, platform="linux")


class TestLinkStateReading:
    def test_a_plugged_cable_reports_a_carrier(self, tmp_path):
        _iface(tmp_path, "eth0", carrier=True)
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert [i.name for i in status.live] == ["eth0"]

    def test_an_unplugged_cable_does_not(self, tmp_path):
        _iface(tmp_path, "eth0", carrier=False, operstate="down")
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert status.live == ()

    def test_loopback_never_counts_as_a_way_out(self, tmp_path):
        _iface(tmp_path, "lo", carrier=True, physical=False)
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert status.live == ()
        assert status.by_name("lo").kind is Kind.LOOPBACK

    def test_wireless_is_identified_and_counted(self, tmp_path):
        _iface(tmp_path, "wlan0", carrier=True, wireless=True)
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert status.by_name("wlan0").kind is Kind.WIRELESS
        assert [i.name for i in status.live] == ["wlan0"]

    def test_virtual_interfaces_are_labelled_but_still_counted(self, tmp_path):
        """A bridge or tunnel is a route out, whatever it is made of."""
        _iface(tmp_path, "docker0", carrier=True, physical=False)
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert status.by_name("docker0").kind is Kind.VIRTUAL
        assert [i.name for i in status.live] == ["docker0"]

    def test_an_unreadable_carrier_is_unknown_not_false(self, tmp_path):
        """The kernel returns EINVAL for a down interface.

        Reporting that as "no carrier" would turn an unanswered question into
        a reassuring answer, which is the failure mode this whole feature has
        to avoid.
        """
        _iface(tmp_path, "eth0", carrier=None)
        status = inspect(sysfs_root=tmp_path, platform="linux")
        assert status.by_name("eth0").carrier is None

    def test_interfaces_are_reported_in_a_stable_order(self, tmp_path):
        for name in ("wlan0", "eth0", "lo"):
            _iface(tmp_path, name, carrier=False, physical=name != "lo")
        first = [i.name for i in inspect(sysfs_root=tmp_path, platform="linux").interfaces]
        second = [i.name for i in inspect(sysfs_root=tmp_path, platform="linux").interfaces]
        assert first == second == sorted(first)


class TestUnsupportedPlatformsSaySo:
    """Guessing on macOS or Windows would be worse than declining."""

    @pytest.mark.parametrize("plat", ["darwin", "win32"])
    def test_it_declines_rather_than_guessing(self, tmp_path, plat):
        status = inspect(sysfs_root=tmp_path, platform=plat)
        assert status.supported is False
        assert status.interfaces == ()

    @pytest.mark.parametrize("plat", ["darwin", "win32"])
    def test_the_description_says_what_is_missing(self, tmp_path, plat):
        text = describe(inspect(sysfs_root=tmp_path, platform=plat))
        assert "not supported" in text.lower()
        assert "air-gap" in text.lower()


class TestItReportsObservationsNotAVerdict:
    """No green light that means "you are safe", because it cannot mean that.

    This repo has removed an mlock claim, two clipboard-wipe claims, "no data
    touches the disk" and a recipient-only encryption claim. A traffic light
    implying air-gapped would be the same mistake, and on a machine being used
    to generate a seed a false sense of security is worse than no indicator.
    """

    def test_a_quiet_machine_is_never_called_air_gapped(self, tmp_path):
        _iface(tmp_path, "eth0", carrier=False, operstate="down")
        text = describe(inspect(sysfs_root=tmp_path, platform="linux")).lower()
        assert "cannot tell you" in text
        for overclaim in ("you are air-gapped", "you are safe", "secure",
                          "isolated", "offline and safe"):
            assert overclaim not in text, f"netcheck claimed {overclaim!r}"

    def test_it_names_what_it_cannot_see(self, tmp_path):
        _iface(tmp_path, "eth0", carrier=False, operstate="down")
        text = describe(inspect(sysfs_root=tmp_path, platform="linux")).lower()
        for blind_spot in ("tether", "bluetooth", "already"):
            assert blind_spot in text, (
                f"the caveat does not mention {blind_spot!r}, which is one of "
                f"the ways a 'quiet' machine is still reachable"
            )

    def test_it_states_that_it_sent_nothing(self, tmp_path):
        _iface(tmp_path, "eth0", carrier=True)
        text = describe(inspect(sysfs_root=tmp_path, platform="linux")).lower()
        assert "no packets" in text or "sends nothing" in text


class TestCliSurface:
    @staticmethod
    def _run(argv):
        import contextlib
        import io

        from morpheus_crypt.cli import run_cli

        out, err = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                run_cli(argv)
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue(), err.getvalue()

    def test_check_network_runs_and_says_what_it_did_not_do(self):
        code, out, err = self._run(["--check-network"])
        combined = (out + err).lower()
        assert code in (0, 1, 2)
        assert "morpheus network" in combined or "interface" in combined

    @pytest.mark.skipif(not os.path.isdir("/sys/class/net"),
                        reason="sysfs link state is Linux-only")
    def test_on_linux_the_exit_code_gates_a_script(self):
        code, _, _ = self._run(["--check-network"])
        assert code in (0, 1), (
            "exit 0 when nothing could carry traffic, 1 when something could, "
            "so a setup script can refuse to continue"
        )


class TestInterfaceRecord:
    def test_it_is_immutable(self):
        iface = Interface(name="eth0", kind=Kind.ETHERNET, carrier=True,
                          operstate="up")
        with pytest.raises(dataclasses.FrozenInstanceError):
            iface.name = "eth1"
