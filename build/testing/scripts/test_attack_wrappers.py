from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock


SCRIPTS_DIR = Path(__file__).resolve().parent


def load_script_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


COMMON = load_script_module("dvrtc_attack_common_test_helper", SCRIPTS_DIR / "dvrtc_attack_common.py")


def make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "host": "127.0.0.1",
        "extension": "1000",
        "timeout": 15.0,
        "token": "",
        "payload_template": "",
        "target_did": "9000",
        "query_did": "",
        "expected_early_media_code": 183,
        "injected_extension": "",
        "response_window": 4.0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class AttackCommonHandlerTest(unittest.TestCase):
    def test_sqli_generates_expected_payload_and_token(self) -> None:
        with (
            mock.patch.object(COMMON.random, "randint", return_value=123456),
            mock.patch.object(COMMON, "run_log_injection_check", return_value=0) as helper,
        ):
            self.assertEqual(COMMON.run_sqli_check("127.0.0.1", "1000", 15.0), 0)

        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            "DVRTC_SQLI_123456",
            "leak'), ((SELECT 'DVRTC_SQLI_123456'))-- ",
            "SQLi",
            15.0,
        )

    def test_sqli_accepts_custom_token_and_template(self) -> None:
        with mock.patch.object(COMMON, "run_log_injection_check", return_value=0) as helper:
            self.assertEqual(
                COMMON.run_sqli_check(
                    "127.0.0.1",
                    "1000",
                    15.0,
                    token="FIXED",
                    payload_template="prefix-{token}-suffix",
                ),
                0,
            )

        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            "FIXED",
            "prefix-FIXED-suffix",
            "SQLi",
            15.0,
        )

    def test_xss_generates_expected_payload_and_token(self) -> None:
        with (
            mock.patch.object(COMMON.random, "randint", return_value=654321),
            mock.patch.object(COMMON, "run_log_injection_check", return_value=0) as helper,
        ):
            self.assertEqual(COMMON.run_xss_check("127.0.0.1", "1000", 15.0), 0)

        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            "DVRTC_XSS_654321",
            '<img src=x onerror=alert("DVRTC_XSS_654321")>',
            "XSS",
            15.0,
        )

    def test_freeswitch_lua_sqli_unlocks_hidden_target(self) -> None:
        direct_hidden_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(480, {"reason": 'Q.850;cause=16;text="NORMAL_CLEARING"'}),
        ]
        benign_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(200, {"content-type": "application/sdp"}, "v=0\r\n"),
        ]
        injected_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(183, {"content-type": "application/sdp"}, "v=0\r\n"),
            COMMON.SipResponse(200, {"content-type": "application/sdp"}, "v=0\r\n"),
        ]

        with mock.patch.object(
            COMMON,
            "probe_invite",
            side_effect=[direct_hidden_responses, benign_responses, injected_responses],
        ) as mock_probe:
            self.assertEqual(
                COMMON.run_freeswitch_lua_sqli_check(
                    "127.0.0.1",
                    "2001",
                    target_did="9000",
                    expected_early_media_code=183,
                    response_window=4.0,
                ),
                0,
            )

        self.assertEqual(mock_probe.call_args_list[0].args[1], "9000")
        self.assertEqual(mock_probe.call_args_list[1].args[1], "2001")
        self.assertEqual(mock_probe.call_args_list[1].args[2], COMMON.FREESWITCH_LUA_SQLI_USER_AGENT)
        self.assertEqual(
            mock_probe.call_args_list[2].args[1],
            "2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000",
        )

    def test_freeswitch_lua_sqli_query_did_overrides_target_did(self) -> None:
        direct_hidden_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(480, {"reason": 'Q.850;cause=16;text="NORMAL_CLEARING"'}),
        ]
        benign_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(200, {"content-type": "application/sdp"}, "v=0\r\n"),
        ]
        injected_responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(480, {"reason": 'Q.850;cause=16;text="NORMAL_CLEARING"'}),
        ]

        with mock.patch.object(
            COMMON,
            "probe_invite",
            side_effect=[direct_hidden_responses, benign_responses, injected_responses],
        ) as mock_probe:
            self.assertEqual(
                COMMON.run_freeswitch_lua_sqli_check(
                    "127.0.0.1",
                    "2001",
                    target_did="1200",
                    query_did="9000",
                    response_window=4.0,
                ),
                1,
            )

        self.assertEqual(mock_probe.call_args_list[0].args[1], "9000")
        self.assertEqual(
            mock_probe.call_args_list[2].args[1],
            "2001'/**/AND/**/0/**/UNION/**/SELECT/**/target,scope/**/FROM/**/did_routes/**/WHERE/**/did='9000",
        )


class AttackToolDispatchTest(unittest.TestCase):
    def test_sqli_wrapper_dispatches_to_common_helper(self) -> None:
        module = load_script_module("sqli_tool", SCRIPTS_DIR / "sqli.py")
        with mock.patch.object(module, "run_sqli_check", return_value=0) as helper:
            self.assertEqual(module.cmd_sqli(make_args(payload_template=COMMON.DEFAULT_SQLI_PAYLOAD_TEMPLATE)), 0)
        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            15.0,
            token="",
            payload_template=COMMON.DEFAULT_SQLI_PAYLOAD_TEMPLATE,
        )

    def test_xss_wrapper_dispatches_to_common_helper(self) -> None:
        module = load_script_module("xss_tool", SCRIPTS_DIR / "xss.py")
        with mock.patch.object(module, "run_xss_check", return_value=0) as helper:
            self.assertEqual(module.cmd_xss(make_args(payload_template=COMMON.DEFAULT_XSS_PAYLOAD_TEMPLATE)), 0)
        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            15.0,
            token="",
            payload_template=COMMON.DEFAULT_XSS_PAYLOAD_TEMPLATE,
        )

    def test_freeswitch_wrapper_dispatches_to_common_helper(self) -> None:
        module = load_script_module("freeswitch_lua_sqli_tool", SCRIPTS_DIR / "freeswitch-lua-sqli.py")
        with mock.patch.object(module, "run_freeswitch_lua_sqli_check", return_value=0) as helper:
            self.assertEqual(module.cmd_freeswitch_lua_sqli(make_args()), 0)
        helper.assert_called_once_with(
            "127.0.0.1",
            "1000",
            target_did="9000",
            query_did="",
            injected_extension="",
            expected_early_media_code=183,
            response_window=4.0,
        )


class AttackToolHelpTest(unittest.TestCase):
    def test_each_tool_exposes_help(self) -> None:
        cases = (
            ("sqli.py", "--extension"),
            ("xss.py", "--extension"),
            ("freeswitch-lua-sqli.py", "--target-did"),
        )
        for script_name, expected_flag in cases:
            with self.subTest(script=script_name):
                result = subprocess.run(
                    [sys.executable, str(SCRIPTS_DIR / script_name), "--help"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, msg=result.stdout)
                self.assertIn("usage:", result.stdout.lower())
                self.assertIn(expected_flag, result.stdout)


if __name__ == "__main__":
    unittest.main()
