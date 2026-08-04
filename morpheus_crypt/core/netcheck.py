"""Passive inspection of network link state, for people setting up air-gapped.

Reads what the kernel already knows and nothing else. It opens no sockets,
resolves no names and runs no subprocesses.

**Why it must stay passive.** The obvious way to answer "am I online" is to try
reaching something. That sends the packet an air-gapped user must not send, and
it announces that MORPHEUS is running, when, and from which address. For a tool
whose users are generating wallet seeds, that is a worse outcome than not
answering at all. So the question is narrowed to one the kernel can answer
locally: is any interface currently in a state where traffic could leave.

**Why it reports observations and not a verdict.** No absence of carrier proves
a machine is air-gapped. This cannot see a phone about to be tethered, a
Bluetooth PAN, a hypervisor's host bridge, someone pushing the cable back in a
minute from now, or — the one that matters most — a machine that was online
thirty seconds ago and already has something resident on it. Air-gapping
frustrates exfiltration over the wire; it does nothing for a box that is
already compromised.

This repository has removed an `mlock` claim, two clipboard-wipe claims, "no
data touches the disk", and a recipient-only encryption claim, in every case
because the software could not back the sentence. A green light meaning "you
are safe" would be the same mistake, and it would be made to someone in the
middle of generating a seed. So the output states what was seen, states plainly
what it cannot see, and leaves the judgement where it belongs.
"""

from __future__ import annotations

import enum
import os
import sys
from dataclasses import dataclass

# Where the Linux kernel publishes per-interface link state. Every file read
# below is plain text, world-readable, and costs nothing.
SYSFS_NET = "/sys/class/net"


class Kind(enum.Enum):
    """What sort of interface this is, as far as sysfs reveals."""

    ETHERNET = "ethernet"
    WIRELESS = "wireless"
    LOOPBACK = "loopback"
    VIRTUAL = "virtual"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.value


@dataclass(frozen=True)
class Interface:
    """One interface, as the kernel currently describes it.

    `carrier` is deliberately tri-state. The kernel returns EINVAL when the
    interface is administratively down, and reporting that as "no carrier"
    would convert an unanswered question into a reassuring answer, which is the
    exact failure this module exists to avoid.
    """

    name: str
    kind: Kind
    carrier: bool | None
    operstate: str

    @property
    def could_carry_traffic(self) -> bool:
        """True when this interface is a live route off the machine."""
        return self.kind is not Kind.LOOPBACK and self.carrier is True


@dataclass(frozen=True)
class NetworkStatus:
    """The whole observation, including whether one was possible at all."""

    supported: bool
    platform: str
    interfaces: tuple[Interface, ...]

    @property
    def live(self) -> tuple[Interface, ...]:
        return tuple(i for i in self.interfaces if i.could_carry_traffic)

    def by_name(self, name: str) -> Interface:
        for iface in self.interfaces:
            if iface.name == name:
                return iface
        raise KeyError(name)


def _read(path: str) -> str | None:
    """Read a sysfs value, or None if the kernel refuses to answer.

    A down interface makes `carrier` return EINVAL, which is not an error
    condition so much as "ask me later".
    """
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except (OSError, ValueError):
        return None


def _classify(root: str, name: str) -> Kind:
    if name == "lo":
        return Kind.LOOPBACK
    if os.path.isdir(os.path.join(root, name, "wireless")) or os.path.exists(
        os.path.join(root, name, "phy80211")
    ):
        return Kind.WIRELESS
    # Real hardware has a `device` link back into the bus tree. Bridges, veths,
    # tunnels and taps do not. They still carry traffic, so they are labelled
    # rather than excluded.
    if not os.path.exists(os.path.join(root, name, "device")):
        return Kind.VIRTUAL
    return Kind.ETHERNET


def inspect(sysfs_root: str | os.PathLike[str] = SYSFS_NET,
            platform: str | None = None) -> NetworkStatus:
    """Read current link state. Sends nothing, opens no sockets.

    `platform` and `sysfs_root` are injectable so the behaviour can be tested
    on machines that have no sysfs, which includes the macOS leg of CI.
    """
    platform = sys.platform if platform is None else platform
    root = os.fspath(sysfs_root)

    if not platform.startswith("linux") or not os.path.isdir(root):
        return NetworkStatus(supported=False, platform=platform, interfaces=())

    found: list[Interface] = []
    for name in sorted(os.listdir(root)):
        carrier_raw = _read(os.path.join(root, name, "carrier"))
        carrier: bool | None
        if carrier_raw in ("0", "1"):
            carrier = carrier_raw == "1"
        else:
            carrier = None
        found.append(
            Interface(
                name=name,
                kind=_classify(root, name),
                carrier=carrier,
                operstate=_read(os.path.join(root, name, "operstate")) or "unknown",
            )
        )
    return NetworkStatus(supported=True, platform=platform,
                         interfaces=tuple(found))


# Kept as one string so the caveat cannot drift away from the table it
# qualifies. Every clause names something a quiet machine can still be reached
# through, because "no carrier" is the beginning of the question.
_CAVEAT = """\
  This reads link state only. It sends no packets and opens no sockets, which
  is deliberate: probing the network is the one thing an air-gapped machine
  must not do.

  It cannot tell you this machine is air-gapped. It does not see a phone about
  to be tethered, a Bluetooth connection, a virtual machine's host bridge, or
  a cable plugged back in a minute from now. It cannot see whether the machine
  was already online earlier, which is what matters most: an air gap stops
  data leaving over the wire, not something that arrived before the gap."""


def describe(status: NetworkStatus) -> str:
    """Render an observation a person can act on, with no verdict attached."""
    lines = ["MORPHEUS Network Check", "=" * 44]

    if not status.supported:
        lines += [
            f"  Link-state inspection is not supported on {status.platform}.",
            "",
            "  This reads /sys/class/net, which only Linux provides. On other",
            "  systems, disconnect the cable and turn off Wi-Fi by hand.",
            "",
            "  Nothing here can tell you a machine is air-gapped, on any",
            "  platform. See the caveat in the documentation.",
        ]
        return "\n".join(lines)

    if not status.interfaces:
        lines.append("  No network interfaces found.")
    else:
        for iface in status.interfaces:
            if iface.carrier is None:
                state = "unknown"
            elif iface.carrier:
                state = "CARRIER"
            else:
                state = "no carrier"
            lines.append(
                f"  {iface.name:<12} {str(iface.kind):<9} {state:<11} "
                f"{iface.operstate}"
            )

    live = status.live
    lines.append("")
    if live:
        names = ", ".join(i.name for i in live)
        lines.append(
            f"  {len(live)} interface{'s' if len(live) != 1 else ''} could "
            f"currently carry traffic: {names}"
        )
    else:
        lines.append("  No interface currently reports a carrier.")

    lines += ["", _CAVEAT]
    return "\n".join(lines)
