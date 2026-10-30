# SPDX-License-Identifier: Apache-2.0
"""A minimal DHCPv4 client for the lab, run on lab-client as root with the standard library only.

`get IFACE MAC` does a full exchange (DISCOVER, REQUEST) for a chosen hardware address and prints
the address acknowledged. `loop IFACE MAC IP SECONDS` sends an INIT-REBOOT REQUEST for IP every
second and prints one JSON line per try ({"t","result": ack|nak|none,"server"}): the outage a client
sees and any DHCPNAK during a Kea migration.
"""

from __future__ import annotations

import json
import os
import random
import select
import socket
import struct
import sys
import time

COOKIE = b"\x63\x82\x53\x63"
TYPES = {1: "discover", 2: "offer", 3: "request", 5: "ack", 6: "nak"}


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def frame(src_mac: bytes, chaddr: bytes, xid: int, options: bytes) -> bytes:
    bootp = struct.pack(
        "!BBBBIHH4s4s4s4s", 1, 1, 6, 0, xid, 0, 0x8000, b"\0" * 4, b"\0" * 4, b"\0" * 4, b"\0" * 4
    )
    bootp += chaddr + b"\0" * 10 + b"\0" * 192 + COOKIE + options + b"\xff"
    bootp += b"\0" * max(0, 300 - len(bootp))
    udp = struct.pack("!HHHH", 68, 67, 8 + len(bootp), 0) + bootp
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0, b"\0" * 4, b"\xff" * 4)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    return b"\xff" * 6 + src_mac + b"\x08\x00" + ip + udp


def opt(code: int, value: bytes) -> bytes:
    return bytes([code, len(value)]) + value


def parse(packet: bytes, xid: int) -> dict | None:
    if len(packet) < 282 or packet[12:14] != b"\x08\x00" or packet[23] != 17:
        return None
    ihl = (packet[14] & 0x0F) * 4
    udp = 14 + ihl
    if struct.unpack("!H", packet[udp + 2 : udp + 4])[0] != 68:
        return None
    bootp = packet[udp + 8 :]
    if bootp[0] != 2 or struct.unpack("!I", bootp[4:8])[0] != xid or bootp[236:240] != COOKIE:
        return None
    out = {"yiaddr": socket.inet_ntoa(bootp[16:20])}
    i = 240
    while i < len(bootp) and bootp[i] != 255:
        if bootp[i] == 0:
            i += 1
            continue
        code, size = bootp[i], bootp[i + 1]
        value = bootp[i + 2 : i + 2 + size]
        if code == 53:
            out["type"] = TYPES.get(value[0], str(value[0]))
        elif code == 54:
            out["server"] = socket.inet_ntoa(value)
        i += 2 + size
    return out


class Client:
    def __init__(self, iface: str, mac: str) -> None:
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.sock.bind((iface, 0))
        self.src = self.sock.getsockname()[4]
        self.chaddr = bytes.fromhex(mac.replace(":", ""))

    def exchange(self, options: bytes, wait: float, want: tuple[str, ...]) -> dict | None:
        xid = random.getrandbits(32)
        self.sock.send(frame(self.src, self.chaddr, xid, options))
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            ready, _, _ = select.select([self.sock], [], [], left)
            if not ready:
                break
            got = parse(self.sock.recv(4096), xid)
            if got and got.get("type") in want:
                return got
        return None

    def get(self) -> str:
        host = opt(12, b"probe-" + self.chaddr[-2:].hex().encode())
        for _ in range(10):
            offer = self.exchange(opt(53, b"\x01") + host, 3.0, ("offer",))
            if offer is None:
                continue
            ip = socket.inet_aton(offer["yiaddr"])
            server = socket.inet_aton(offer["server"])
            ack = self.exchange(opt(53, b"\x03") + opt(50, ip) + opt(54, server) + host, 3.0, ("ack", "nak"))
            if ack and ack["type"] == "ack":
                return ack["yiaddr"]
        raise SystemExit("no lease")

    def reboot(self, ip: str) -> dict | None:
        options = opt(53, b"\x03") + opt(50, socket.inet_aton(ip))
        return self.exchange(options, 1.0, ("ack", "nak"))


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    mode, iface, mac = sys.argv[1:4]
    client = Client(iface, mac)
    if mode == "get":
        print(client.get())
        return
    ip, seconds = sys.argv[4], float(sys.argv[5])
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        started = time.monotonic()
        got = client.reboot(ip)
        line = {"t": round(time.time(), 2), "result": got["type"] if got else "none"}
        if got:
            line["server"] = got.get("server")
            line["yiaddr"] = got.get("yiaddr")
        print(json.dumps(line), flush=True)
        time.sleep(max(0.0, 1.0 - (time.monotonic() - started)))


if __name__ == "__main__":
    main()
