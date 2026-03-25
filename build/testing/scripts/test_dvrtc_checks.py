from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import subprocess
import sys
import unittest
import tempfile
from textwrap import dedent
from unittest import mock


def load_script_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCRIPT_PATH = Path(__file__).with_name("dvrtc-checks.py")
dvrtc_checks = load_script_module("dvrtc_checks", SCRIPT_PATH)
digestleak = load_script_module("digestleak_helper", Path(__file__).with_name("digestleak.py"))
turn_probe = load_script_module("turn_probe_helper", Path(__file__).with_name("turn-probe.py"))


def make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "host": "127.0.0.1",
        "mysql_port": 23306,
        "extension": "1000",
        "username": "1000",
        "password": "1500",
        "timeout": 10.0,
        "requests": 10,
        "collect_seconds": 1.0,
        "min_responses": 1,
        "hash_line": "$sip$*127.0.0.1*127.0.0.1*user*realm*REGISTER*sip*user@127.0.0.1**nonce*cnonce*00000001*auth*MD5*deadbeef",
        "expected_password": "2000",
        "candidates": "2000,password",
        "max_run_time": 8,
        "rtp_host": "",
        "start_port": 35000,
        "end_port": 40000,
        "duration": 6.0,
        "probes": 1,
        "cycle_listen": 0.05,
        "listen": 1.0,
        "payload_type": 0,
        "attempts": 3,
        "kamcmd_addr": "tcp:127.0.0.1:2046",
        "ami_port": 5038,
        "local_port": None,
        "register_only": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class DigestHelpersTest(unittest.TestCase):
    def test_format_uri_host_brackets_ipv6(self) -> None:
        self.assertEqual(dvrtc_checks._format_uri_host("2001:db8::10"), "[2001:db8::10]")
        self.assertEqual(dvrtc_checks._format_hostport("2001:db8::10", 5060), "[2001:db8::10]:5060")

    def test_build_digest_authorization_with_qop(self) -> None:
        challenge = {
            "realm": "asterisk",
            "nonce": "abcdef",
            "qop": "auth,auth-int",
            "opaque": "opaque-token",
        }
        with mock.patch.object(dvrtc_checks.random, "getrandbits", return_value=0x1234):
            header = dvrtc_checks._build_digest_authorization(
                "REGISTER",
                "sip:127.0.0.1",
                "1000",
                "1500",
                challenge,
            )

        cnonce = "0000000000001234"
        ha1 = hashlib.md5(b"1000:asterisk:1500").hexdigest()
        ha2 = hashlib.md5(b"REGISTER:sip:127.0.0.1").hexdigest()
        response = hashlib.md5(
            f"{ha1}:abcdef:00000001:{cnonce}:auth:{ha2}".encode("utf-8")
        ).hexdigest()
        self.assertIn(f'response="{response}"', header)
        self.assertIn(f'cnonce="{cnonce}"', header)
        self.assertIn("qop=auth", header)
        self.assertIn('opaque="opaque-token"', header)

    def test_is_john_sip_hash_recognizes_expected_format(self) -> None:
        self.assertTrue(
            dvrtc_checks._is_john_sip_hash(
                "$sip$*127.0.0.1*127.0.0.1*2000*asterisk*REGISTER*sip*"
                "2000@127.0.0.1*5060;transport=udp*nonce*cnonce*00000001*auth*MD5*deadbeef"
            )
        )
        self.assertFalse(
            dvrtc_checks._is_john_sip_hash(
                "$sip$*2000*asterisk*REGISTER*"
                "sip:2000@127.0.0.1:5060;transport=udp*nonce*cnonce*00000001*auth*deadbeef"
            )
        )


class DigestLeakHelpersTest(unittest.TestCase):
    def test_uri_to_john_parts_extracts_bracketed_ipv6_details(self) -> None:
        scheme, user_host, params, host = digestleak.uri_to_john_parts(
            "sip:2000@[2001:db8::10]:5082;transport=udp"
        )

        self.assertEqual(scheme, "sip")
        self.assertEqual(user_host, "2000@[2001:db8::10]")
        self.assertEqual(params, "5082;transport=udp")
        self.assertEqual(host, "2001:db8::10")

    def test_digest_to_john_hash_uses_normalized_hosts(self) -> None:
        creds = {
            "username": "2000",
            "realm": "attacker.evil",
            "nonce": "nonce-value",
            "uri": "sip:attacker@example.com",
            "response": "response-value",
            "cnonce": "cnonce-value",
            "nc": "00000001",
            "qop": "auth",
        }

        self.assertEqual(
            digestleak.digest_to_john_hash(creds, "203.0.113.10", "192.0.2.10"),
            "$sip$*203.0.113.10*example.com*2000*attacker.evil*BYE*sip*attacker@"
            "example.com**nonce-value*cnonce-value*00000001*auth*MD5*response-value",
        )


class CommandHandlersTest(unittest.TestCase):
    def test_smoke_succeeds_with_expected_services(self) -> None:
        responses = [dvrtc_checks.SipResponse(401, {})]
        with (
            mock.patch.object(dvrtc_checks, "_tcp_connect"),
            mock.patch.object(
                dvrtc_checks,
                "_http_get_text",
                side_effect=[(200, "<html>DVRTC</html>"), (200, "[]")],
            ),
            mock.patch.object(dvrtc_checks, "_probe_register", return_value=responses),
        ):
            self.assertEqual(dvrtc_checks.cmd_smoke(make_args()), 0)

    def test_enum_fails_when_all_responses_show_absent_extension(self) -> None:
        responses = [
            dvrtc_checks.SipResponse(404, {}),
            dvrtc_checks.SipResponse(484, {}),
        ]
        with mock.patch.object(dvrtc_checks, "_probe_options", return_value=responses):
            self.assertEqual(dvrtc_checks.cmd_enum(make_args(extension="2000")), 1)

    def test_weak_cred_requires_successful_authenticated_register(self) -> None:
        responses = [dvrtc_checks.SipResponse(401, {}), dvrtc_checks.SipResponse(200, {})]
        with mock.patch.object(
            dvrtc_checks,
            "_probe_authenticated_register",
            return_value=responses,
        ):
            self.assertEqual(dvrtc_checks.cmd_weak_cred(make_args()), 0)

    def test_offline_crack_accepts_john_sip_hash_and_reports_success(self) -> None:
        args = make_args(
            hash_line=(
                "$sip$*127.0.0.1*127.0.0.1*2000*asterisk*REGISTER*sip*"
                "2000@127.0.0.1*5060;transport=udp*nonce*cnonce*00000001*auth*MD5*deadbeef"
            )
        )
        run_results = [
            subprocess.CompletedProcess(["john", "--list=formats"], 0, "SIP\n", ""),
            subprocess.CompletedProcess(["john", "--format=SIP"], 0, "Loaded 1 password hash\n", ""),
            subprocess.CompletedProcess(["john", "--show"], 0, "2000:2000\n1 password hash cracked, 0 left\n", ""),
        ]
        with mock.patch.object(dvrtc_checks, "_run_capture", side_effect=run_results):
            self.assertEqual(dvrtc_checks.cmd_offline_crack(args), 0)

    def test_offline_crack_rejects_non_john_hash(self) -> None:
        args = make_args(
            hash_line=(
                "$sip$*2000*asterisk*REGISTER*"
                "sip:2000@127.0.0.1:5060;transport=udp*nonce*cnonce*00000001*auth*deadbeef"
            )
        )
        self.assertEqual(dvrtc_checks.cmd_offline_crack(args), 1)

    def test_weak_cred_svcrack_accepts_expected_password(self) -> None:
        args = make_args(
            port=5060,
            extension="1000",
            password_range="1000-2000",
            zeropadding=0,
            reuse_nonce=False,
            expected_password="1500",
        )
        result = subprocess.CompletedProcess(
            ["sipvicious_svcrack"],
            40,
            (
                "+-----------+----------+\n"
                "| Extension | Password |\n"
                "+===========+==========+\n"
                "| 1000      | 1500     |\n"
                "+-----------+----------+\n"
            ),
            "",
        )
        with mock.patch.object(dvrtc_checks, "_run_capture", return_value=result):
            self.assertEqual(dvrtc_checks.cmd_weak_cred_svcrack(args), 0)


class TcpWsHelpersTest(unittest.TestCase):
    def test_recv_tcp_sip_data_reads_until_double_crlf(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.timeout: float | None = None
                self.call_count = 0

            def settimeout(self, t: float) -> None:
                self.timeout = t

            def recv(self, size: int) -> bytes:
                self.call_count += 1
                if self.call_count == 1:
                    return (
                        b"SIP/2.0 401 Unauthorized\r\n"
                        b"WWW-Authenticate: Digest realm=\"test\"\r\n"
                        b"\r\n"
                    )
                return b""

        sock = FakeSocket()
        data = dvrtc_checks._recv_tcp_sip_data(sock, timeout=1.0)
        self.assertIn(b"401", data)
        self.assertEqual(sock.call_count, 1)

    def test_run_kamcmd_returns_stdout(self) -> None:
        result = subprocess.CompletedProcess(["kamcmd"], 0, "some output\n", "")
        with mock.patch("subprocess.run", return_value=result) as mock_run:
            output = dvrtc_checks._run_kamcmd("tcp:127.0.0.1:2046", "ul.dump")
            mock_run.assert_called_once()
            self.assertEqual(output, "some output\n")

    def test_probe_register_ws_brackets_ipv6_host_and_header(self) -> None:
        fake_conn = mock.MagicMock()
        fake_conn.__enter__.return_value = fake_conn
        fake_conn.__exit__.return_value = False
        fake_conn.recv.return_value = "SIP/2.0 401 Unauthorized\r\n\r\n"

        with (
            mock.patch.object(dvrtc_checks, "_local_ip_for_target", return_value="127.0.0.1"),
            mock.patch.object(dvrtc_checks, "_build_register", return_value="REGISTER"),
            mock.patch.object(
                dvrtc_checks,
                "_parse_sip_message",
                return_value=dvrtc_checks.SipResponse(401, {}),
            ),
            mock.patch("websockets.sync.client.connect", return_value=fake_conn) as mock_connect,
        ):
            responses = dvrtc_checks._probe_register_ws(
                "2001:db8::10",
                8000,
                "1000",
                "DVRTC-Transport-WS",
            )

        self.assertEqual([response.code for response in responses], [401])
        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args.args[0], "ws://[2001:db8::10]:8000")
        self.assertEqual(
            mock_connect.call_args.kwargs["additional_headers"],
            {"Host": "[2001:db8::10]:8000"},
        )


class TurnProbeHelpersTest(unittest.TestCase):
    def test_xor_peer_value_round_trips_ipv4_and_ipv6(self) -> None:
        tid = b"123456789012"

        v4 = ipaddress.ip_address("192.0.2.10")
        v4_value = turn_probe.xor_peer_value(v4, 3478, tid)
        self.assertEqual(turn_probe.decode_xor_address(v4_value, tid), ("192.0.2.10", 3478))

        v6 = ipaddress.ip_address("2001:db8::10")
        v6_value = turn_probe.xor_peer_value(v6, 3478, tid)
        self.assertEqual(turn_probe.decode_xor_address(v6_value, tid), ("2001:db8::10", 3478))


class WrapperScriptsTest(unittest.TestCase):
    def _make_fake_python(self, tmpdir: Path) -> tuple[Path, Path]:
        log_file = tmpdir / "python-calls.log"
        fake_python = tmpdir / "python3"
        fake_python.write_text(
            dedent(
                """\
                #!/bin/sh
                set -eu

                log_file="$FAKE_PYTHON_LOG"
                script="$1"
                shift

                {
                    printf 'SCRIPT:%s\\n' "$script"
                    for arg in "$@"; do
                        printf 'ARG:%s\\n' "$arg"
                    done
                    printf '\\n'
                } >>"$log_file"

                case "$script" in
                    */dvrtc-checks.py)
                        if [ "${1:-}" = smoke ]; then
                            printf '[+] Smoke checks passed\\n'
                        fi
                        ;;
                    */digestleak.py)
                        printf 'digestleak demo\\n'
                        printf '%s\\n' '$sip$*203.0.113.10*192.0.2.10*2000*attacker.evil*BYE*sip*attacker@192.0.2.10*5082;transport=udp*nonce*cnonce*00000001*auth*MD5*response'
                        ;;
                esac

                exit 0
                """
            )
        )
        fake_python.chmod(0o755)
        return fake_python, log_file

    def test_smoke_wrapper_forwards_target_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake_python, log_file = self._make_fake_python(tmpdir)
            env = os.environ.copy()
            env["PATH"] = f"{tmpdir}:{env['PATH']}"
            env["FAKE_PYTHON_LOG"] = str(log_file)

            result = subprocess.run(
                ["bash", "build/testing/smoke.sh", "203.0.113.9", "1200", "2444"],
                cwd=Path(__file__).resolve().parents[3],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("[+] Smoke checks passed", result.stdout)
            log = log_file.read_text()
            self.assertIn("SCRIPT:/opt/testing/scripts/dvrtc-checks.py", log)
            self.assertIn("ARG:smoke", log)
            self.assertIn("ARG:--host", log)
            self.assertIn("ARG:203.0.113.9", log)
            self.assertIn("ARG:--extension", log)
            self.assertIn("ARG:1200", log)
            self.assertIn("ARG:--mysql-port", log)
            self.assertIn("ARG:2444", log)

    def test_run_all_wrapper_uses_helper_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            fake_python, log_file = self._make_fake_python(tmpdir)
            env = os.environ.copy()
            env["PATH"] = f"{tmpdir}:{env['PATH']}"
            env["FAKE_PYTHON_LOG"] = str(log_file)

            result = subprocess.run(
                ["bash", "build/testing/run-all.sh", "203.0.113.9", "2444"],
                cwd=Path(__file__).resolve().parents[3],
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )

            self.assertIn("[+] All testing checks passed", result.stdout)
            log = log_file.read_text()
            self.assertIn("SCRIPT:/opt/testing/scripts/dvrtc-checks.py", log)
            self.assertIn("ARG:smoke", log)
            self.assertIn("ARG:--mysql-port", log)
            self.assertIn("ARG:2444", log)
            self.assertIn("SCRIPT:/opt/testing/scripts/digestleak.py", log)
            self.assertIn("SCRIPT:/opt/testing/scripts/turn-probe.py", log)


class NewCommandHandlersTest(unittest.TestCase):
    def test_register_succeeds_with_200_responses(self) -> None:
        responses_ok = [dvrtc_checks.SipResponse(200, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            side_effect=[responses_ok, responses_ok],
        ):
            args = make_args(username="1000", password="1500", timeout=5.0)
            self.assertEqual(dvrtc_checks.cmd_register(args), 0)

    def test_register_fails_without_200(self) -> None:
        responses_fail = [dvrtc_checks.SipResponse(403, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            return_value=responses_fail,
        ):
            args = make_args(username="1000", password="1500", timeout=5.0)
            self.assertEqual(dvrtc_checks.cmd_register(args), 1)

    def test_register_only_skips_unregister(self) -> None:
        responses_ok = [dvrtc_checks.SipResponse(200, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            return_value=responses_ok,
        ) as mock_probe:
            args = make_args(username="1000", password="1500", timeout=5.0, register_only=True)
            self.assertEqual(dvrtc_checks.cmd_register(args), 0)
            mock_probe.assert_called_once()

    def test_register_passes_local_port_to_probe(self) -> None:
        responses_ok = [dvrtc_checks.SipResponse(200, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            side_effect=[responses_ok, responses_ok],
        ) as mock_probe:
            args = make_args(username="1000", password="1500", timeout=5.0, local_port=5070)
            self.assertEqual(dvrtc_checks.cmd_register(args), 0)
            self.assertEqual(mock_probe.call_args_list[0].kwargs["local_port"], 5070)
            self.assertEqual(mock_probe.call_args_list[1].kwargs["local_port"], 5070)

    def test_bad_auth_passes_when_server_rejects(self) -> None:
        responses = [dvrtc_checks.SipResponse(401, {}), dvrtc_checks.SipResponse(403, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            return_value=responses,
        ):
            args = make_args(username="1000", timeout=5.0)
            self.assertEqual(dvrtc_checks.cmd_bad_auth(args), 0)

    def test_bad_auth_fails_when_server_accepts(self) -> None:
        responses = [dvrtc_checks.SipResponse(200, {})]
        with mock.patch.object(
            dvrtc_checks, "_probe_authenticated_register",
            return_value=responses,
        ):
            args = make_args(username="1000", timeout=5.0)
            self.assertEqual(dvrtc_checks.cmd_bad_auth(args), 1)

    def test_callgen_active_passes_with_dialog(self) -> None:
        with mock.patch.object(
            dvrtc_checks, "_ami_command",
            return_value="Channel              Location             State   Application(Data)\nPJSIP/sipcaller1-1  1300@default:1       Up      AppDial\n3 active calls\n",
        ):
            args = make_args(kamcmd_addr="tcp:127.0.0.1:2046")
            self.assertEqual(dvrtc_checks.cmd_callgen_active(args), 0)

    def test_callgen_active_fails_without_dialog(self) -> None:
        with mock.patch.object(
            dvrtc_checks, "_ami_command",
            return_value="0 active calls\n",
        ):
            args = make_args(kamcmd_addr="tcp:127.0.0.1:2046")
            self.assertEqual(dvrtc_checks.cmd_callgen_active(args), 1)

    def test_digestleak_registered_passes(self) -> None:
        with mock.patch.object(
            dvrtc_checks, "_run_kamcmd",
            return_value="AOR: 2000\nContact: sip:2000@127.0.0.1:5082\n",
        ):
            args = make_args(kamcmd_addr="tcp:127.0.0.1:2046")
            self.assertEqual(dvrtc_checks.cmd_digestleak_registered(args), 0)

    def test_digestleak_registered_fails(self) -> None:
        with mock.patch.object(
            dvrtc_checks, "_run_kamcmd",
            return_value="404 AOR not found\n",
        ):
            args = make_args(kamcmd_addr="tcp:127.0.0.1:2046")
            self.assertEqual(dvrtc_checks.cmd_digestleak_registered(args), 1)

    def test_sip_transport_passes_all_transports(self) -> None:
        ok = [dvrtc_checks.SipResponse(401, {})]
        with (
            mock.patch.object(dvrtc_checks, "_probe_register", return_value=ok),
            mock.patch.object(dvrtc_checks, "_probe_register_tcp", return_value=ok),
            mock.patch.object(dvrtc_checks, "_probe_register_ws", return_value=ok),
        ):
            args = make_args(extension="1000")
            self.assertEqual(dvrtc_checks.cmd_sip_transport(args), 0)

    def test_sip_transport_fails_when_transport_down(self) -> None:
        ok = [dvrtc_checks.SipResponse(401, {})]
        with (
            mock.patch.object(dvrtc_checks, "_probe_register", return_value=ok),
            mock.patch.object(
                dvrtc_checks, "_probe_register_tcp", side_effect=OSError("refused"),
            ),
            mock.patch.object(
                dvrtc_checks, "_probe_register_ws", side_effect=Exception("ws failed"),
            ),
        ):
            args = make_args(extension="1000")
            self.assertEqual(dvrtc_checks.cmd_sip_transport(args), 1)

    def test_wss_register_brackets_ipv6_host_and_header(self) -> None:
        fake_conn = mock.MagicMock()
        fake_conn.__enter__.return_value = fake_conn
        fake_conn.__exit__.return_value = False
        fake_conn.recv.side_effect = [
            "SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"asterisk\", nonce=\"abc\"\r\n\r\n",
            "SIP/2.0 200 OK\r\n\r\n",
        ]

        with (
            mock.patch.object(dvrtc_checks, "_local_ip_for_target", return_value="127.0.0.1"),
            mock.patch.object(dvrtc_checks, "_build_register", return_value="REGISTER"),
            mock.patch.object(
                dvrtc_checks,
                "_parse_sip_message",
                side_effect=[
                    dvrtc_checks.SipResponse(401, {}),
                    dvrtc_checks.SipResponse(200, {}),
                ],
            ),
            mock.patch.object(
                dvrtc_checks,
                "_extract_digest_challenge",
                return_value=("Authorization", {"realm": "asterisk", "nonce": "abc"}),
            ),
            mock.patch.object(dvrtc_checks, "_build_digest_authorization", return_value="Digest auth") as mock_auth,
            mock.patch("websockets.sync.client.connect", return_value=fake_conn) as mock_connect,
        ):
            self.assertEqual(dvrtc_checks.cmd_wss_register(make_args(host="2001:db8::10")), 0)

        mock_connect.assert_called_once()
        self.assertEqual(mock_connect.call_args.args[0], "wss://[2001:db8::10]:8443")
        self.assertEqual(
            mock_connect.call_args.kwargs["additional_headers"],
            {"Host": "[2001:db8::10]:8443"},
        )
        mock_auth.assert_called_once_with(
            "REGISTER",
            "sip:[2001:db8::10]",
            "1000",
            "1500",
            {"realm": "asterisk", "nonce": "abc"},
        )


class SipCollectionTest(unittest.TestCase):
    def test_collect_sip_messages_stops_when_predicate_matches(self) -> None:
        class FakeSocket:
            def __init__(self) -> None:
                self.timeout = None
                self.calls = 0

            def settimeout(self, value: float) -> None:
                self.timeout = value

            def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
                self.calls += 1
                if self.calls == 1:
                    return (
                        (
                            b"SIP/2.0 401 Unauthorized\r\n"
                            b"WWW-Authenticate: Digest realm=\"asterisk\", nonce=\"abc\"\r\n"
                            b"\r\n"
                        ),
                        ("127.0.0.1", 5060),
                    )
                raise AssertionError("collector should have stopped after the first matching response")

        fake_socket = FakeSocket()
        responses = dvrtc_checks._collect_sip_messages(
            fake_socket,
            response_window=10.0,
            stop_when=dvrtc_checks._is_digest_challenge_response,
        )

        self.assertEqual(fake_socket.timeout, 0.2)
        self.assertEqual(fake_socket.calls, 1)
        self.assertEqual([response.code for response in responses], [401])


class CommandLineAccessTest(unittest.TestCase):
    def test_each_subcommand_is_available_directly(self) -> None:
        commands = (
            ["smoke", "--help"],
            ["enum", "--help"],
            ["weak-cred", "--help"],
            ["weak-cred-svcrack", "--help"],
            ["sqli", "--help"],
            ["xss", "--help"],
            ["sip-flood", "--help"],
            ["offline-crack", "--help"],
            ["rtp-bleed", "--help"],
            ["register", "--help"],
            ["bad-auth", "--help"],
            ["sip-transport", "--help"],
            ["wss-register", "--help"],
            ["callgen-active", "--help"],
            ["digestleak-registered", "--help"],
            ["voicemail", "--help"],
        )
        for command in commands:
            with self.subTest(command=command[0]):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT_PATH), *command],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, msg=result.stdout)
                self.assertIn("usage:", result.stdout.lower())

    def test_parser_accepts_individual_command_invocations(self) -> None:
        parser = dvrtc_checks.build_parser()
        cases = [
            ("smoke", ["smoke"]),
            ("enum", ["enum"]),
            ("weak-cred", ["weak-cred"]),
            ("weak-cred-svcrack", ["weak-cred-svcrack"]),
            ("sqli", ["sqli"]),
            ("xss", ["xss"]),
            ("sip-flood", ["sip-flood"]),
            ("offline-crack", ["offline-crack", "--hash-line", "$sip$*u*r*m*sip:u@h*n*c*1*auth*r"]),
            ("rtp-bleed", ["rtp-bleed"]),
            ("register", ["register"]),
            ("bad-auth", ["bad-auth"]),
            ("sip-transport", ["sip-transport"]),
            ("wss-register", ["wss-register"]),
            ("callgen-active", ["callgen-active"]),
            ("digestleak-registered", ["digestleak-registered"]),
            ("voicemail", ["voicemail"]),
        ]
        for expected, argv in cases:
            with self.subTest(command=expected):
                parsed = parser.parse_args(argv)
                self.assertEqual(parsed.command, expected)
                self.assertTrue(callable(parsed.func))


if __name__ == "__main__":
    unittest.main()
