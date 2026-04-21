from __future__ import annotations

import importlib.util
from pathlib import Path
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


COMMON = load_script_module("dvrtc_attack_common_sqlmap_helper", SCRIPTS_DIR / "dvrtc_attack_common.py")
HARNESS = load_script_module("sip_sqlmap_harness_helper", SCRIPTS_DIR / "sip-sqlmap-harness.py")


class SipSqlmapHarnessTest(unittest.TestCase):
    def test_build_pbx1_payload_wraps_expression_with_error_on_false(self) -> None:
        payload = HARNESS.build_pbx1_payload("1 AND 2=2")
        self.assertIn("seed'),", payload)
        self.assertIn(
            "SELECT IF((1 AND 2=2),'ok',(SELECT 1 UNION SELECT 2))",
            payload,
        )
        self.assertTrue(payload.endswith("('tail"))

    def test_build_pbx2_payload_rewrites_spaces_for_sip_uri(self) -> None:
        payload = HARNESS.build_pbx2_payload("2001", "1 AND EXISTS ( SELECT 1 )")
        self.assertEqual(payload, "2001'/**/AND/**/((1/**/AND/**/EXISTS/**/(/**/SELECT/**/1/**/)))/**/AND/**/'1'='1")

    def test_sip_uri_sql_text_rewrites_not_equals_for_uri_safe_sql(self) -> None:
        self.assertEqual(HARNESS.sip_uri_sql_text("a!=b"), "a/**/IS/**/NOT/**/b")
        self.assertEqual(HARNESS.sip_uri_sql_text("a<>b"), "a/**/IS/**/NOT/**/b")

    def test_evaluate_pbx1_reports_true_on_401(self) -> None:
        responses = [COMMON.SipResponse(401, {})]
        with mock.patch.object(HARNESS, "probe_register", return_value=responses) as probe:
            result = HARNESS.evaluate_pbx1_expression("127.0.0.1", "1")

        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.verdict, HARNESS.SQLMAP_TRUE)
        self.assertIn("codes=[401]", result.sip_detail)
        probe.assert_called_once()

    def test_evaluate_pbx1_reports_false_on_500(self) -> None:
        responses = [COMMON.SipResponse(500, {})]
        with mock.patch.object(HARNESS, "probe_register", return_value=responses):
            result = HARNESS.evaluate_pbx1_expression("127.0.0.1", "1 AND 1=2")

        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.verdict, HARNESS.SQLMAP_FALSE)

    def test_evaluate_pbx1_retries_on_ambiguous_response(self) -> None:
        first = [COMMON.SipResponse(100, {})]
        second = [COMMON.SipResponse(401, {})]
        with (
            mock.patch.object(HARNESS, "probe_register", side_effect=[first, second]) as probe,
            mock.patch.object(HARNESS.time, "sleep"),
        ):
            result = HARNESS.evaluate_pbx1_expression("127.0.0.1", "1", max_attempts=3, retry_delay=0.0)

        self.assertEqual(result.verdict, HARNESS.SQLMAP_TRUE)
        self.assertEqual(probe.call_count, 2)

    def test_evaluate_pbx2_reports_true_for_routable_response(self) -> None:
        responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(200, {"content-type": "application/sdp"}, "v=0\r\n"),
        ]
        with mock.patch.object(HARNESS, "_probe_pbx2_invite", return_value=responses) as probe:
            result = HARNESS.evaluate_pbx2_expression("127.0.0.1", "1")

        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.verdict, HARNESS.SQLMAP_TRUE)
        self.assertIn("classification=routable", result.sip_detail)
        probe.assert_called_once()

    def test_evaluate_pbx2_reports_false_for_invalid_response(self) -> None:
        responses = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(480, {"reason": 'Q.850;cause=16;text="NORMAL_CLEARING"'}),
        ]
        with mock.patch.object(HARNESS, "_probe_pbx2_invite", return_value=responses):
            result = HARNESS.evaluate_pbx2_expression("127.0.0.1", "1 AND 1=2")

        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.verdict, HARNESS.SQLMAP_FALSE)

    def test_evaluate_pbx2_retries_on_server_error_and_succeeds(self) -> None:
        first = [COMMON.SipResponse(100, {}), COMMON.SipResponse(500, {})]
        second = [
            COMMON.SipResponse(100, {}),
            COMMON.SipResponse(200, {"content-type": "application/sdp"}, "v=0\r\n"),
        ]
        with (
            mock.patch.object(HARNESS, "_probe_pbx2_invite", side_effect=[first, second]) as probe,
            mock.patch.object(HARNESS.time, "sleep"),
        ):
            result = HARNESS.evaluate_pbx2_expression("127.0.0.1", "1", max_attempts=3, retry_delay=0.0)

        self.assertEqual(result.verdict, HARNESS.SQLMAP_TRUE)
        self.assertEqual(probe.call_count, 2)

    def test_evaluate_pbx2_reports_false_when_no_response_arrives(self) -> None:
        with (
            mock.patch.object(HARNESS, "_probe_pbx2_invite", return_value=[]),
            mock.patch.object(HARNESS.time, "sleep"),
        ):
            result = HARNESS.evaluate_pbx2_expression("127.0.0.1", "1", max_attempts=1)

        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.verdict, HARNESS.SQLMAP_FALSE)

    def test_stats_tracks_verdicts_and_timing(self) -> None:
        stats = HARNESS.HarnessStats()
        stats.update(HARNESS.SQLMAP_TRUE, 0.1)
        stats.update(HARNESS.SQLMAP_FALSE, 0.2)
        stats.update(HARNESS.SQLMAP_TRUE, 0.3)
        stats.update("ERROR", 0.4)

        d = stats.as_dict()
        self.assertEqual(d["requests"], 4)
        self.assertEqual(d["true"], 2)
        self.assertEqual(d["false"], 1)
        self.assertEqual(d["error"], 1)
        self.assertAlmostEqual(d["total_elapsed_seconds"], 1.0, places=3)
        self.assertAlmostEqual(d["average_seconds"], 0.25, places=3)
        self.assertIn("requests=4", stats.summary_line())

    def test_example_command_uses_mode_specific_dbms(self) -> None:
        pbx1 = HARNESS.HarnessConfig("pbx1", "127.0.0.1", "1000", "q", 12.0, False)
        pbx2 = HARNESS.HarnessConfig("pbx2", "127.0.0.1", "2001", "q", 5.0, False)
        pbx1_command = HARNESS.build_example_command(pbx1, "127.0.0.1", 17771)
        pbx2_command = HARNESS.build_example_command(pbx2, "127.0.0.1", 17771)
        self.assertIn("--dbms=MySQL", pbx1_command)
        self.assertIn("--dbms=SQLite", pbx2_command)
        self.assertNotIn("--not-string", pbx1_command)
        self.assertIn("--tamper=between", pbx2_command)
        self.assertNotIn("dvrtc_sip", pbx2_command)


if __name__ == "__main__":
    unittest.main()
