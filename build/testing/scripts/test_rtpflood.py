from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


def load_script_module(module_name: str, path: Path):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


SCRIPT_PATH = Path(__file__).with_name("rtpflood.py")
rtpflood = load_script_module("rtpflood_helper", SCRIPT_PATH)


def make_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "host": "127.0.0.1",
        "sip_port": 5060,
        "recordings_host": "127.0.0.1",
        "extension": "1200",
        "from_user": "rtpflood",
        "duration": 3.0,
        "packet_rate": 1000,
        "payload_size": 1200,
        "payload_type": 0,
        "min_recording_growth": 1_048_576,
        "recording_settle": 0.0,
        "post_flood_linger": 0.0,
        "response_window": 8.0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class HelpersTest(unittest.TestCase):
    def test_parse_size_bytes_supports_kib_and_mib(self) -> None:
        self.assertEqual(rtpflood._parse_size_bytes("225.2 KiB"), int(225.2 * 1024))
        self.assertEqual(rtpflood._parse_size_bytes("1.5 MiB"), int(1.5 * 1024 * 1024))

    def test_fetch_recordings_parses_index_rows(self) -> None:
        body = (
            '<tr><td class="link"><a href="demo%3Dtest.pcap" title="demo=test.pcap">'
            'demo=test.pcap</a></td><td class="size">2.0 MiB</td><td class="date">2026-Apr-09 18:00</td></tr>'
        )
        with mock.patch.object(rtpflood, "_http_get_text", return_value=(200, body)):
            recordings = rtpflood._fetch_recordings_index("127.0.0.1")

        self.assertEqual(recordings, {"demo=test.pcap": 2 * 1024 * 1024})


class CommandHandlersTest(unittest.TestCase):
    def test_cmd_rtpflood_passes_when_recording_growth_exceeds_threshold(self) -> None:
        fake_call = rtpflood.ActiveCall(
            sip_sock=mock.MagicMock(),
            rtp_sock=mock.MagicMock(),
            local_sip_ip="127.0.0.1",
            local_sip_port=5062,
            dialog=rtpflood.SipDialog("call-id", "from-tag", "branch"),
            from_user="rtpflood",
            from_domain="127.0.0.1",
            to_uri="sip:1200@127.0.0.1",
            to_tag="to-tag",
            request_uri="sip:1200@127.0.0.1:5090;transport=udp",
            route_uris=["sip:127.0.0.1;lr"],
            rtp_host="127.0.0.1",
            rtp_port=35000,
        )
        args = make_args(min_recording_growth=500_000)

        with (
            mock.patch.object(
                rtpflood,
                "_fetch_recordings",
                side_effect=[
                    {"normal.pcap": 225_000},
                    {"normal.pcap": 225_000, "flood.pcap": 2_000_000},
                ],
            ),
            mock.patch.object(rtpflood, "_start_call", return_value=fake_call),
            mock.patch.object(rtpflood, "_send_rtp_flood", return_value=(1000, 1_212_000)),
            mock.patch.object(rtpflood, "_hangup_call"),
            mock.patch.object(rtpflood.time, "sleep"),
        ):
            self.assertEqual(rtpflood.cmd_rtpflood(args), 0)

    def test_cmd_rtpflood_fails_when_growth_stays_below_threshold(self) -> None:
        fake_call = rtpflood.ActiveCall(
            sip_sock=mock.MagicMock(),
            rtp_sock=mock.MagicMock(),
            local_sip_ip="127.0.0.1",
            local_sip_port=5062,
            dialog=rtpflood.SipDialog("call-id", "from-tag", "branch"),
            from_user="rtpflood",
            from_domain="127.0.0.1",
            to_uri="sip:1200@127.0.0.1",
            to_tag="to-tag",
            request_uri="sip:1200@127.0.0.1:5090;transport=udp",
            route_uris=["sip:127.0.0.1;lr"],
            rtp_host="127.0.0.1",
            rtp_port=35000,
        )
        args = make_args(min_recording_growth=2_000_000)

        with (
            mock.patch.object(
                rtpflood,
                "_fetch_recordings",
                side_effect=[
                    {"normal.pcap": 225_000},
                    {"normal.pcap": 225_000, "flood.pcap": 1_000_000},
                ],
            ),
            mock.patch.object(rtpflood, "_start_call", return_value=fake_call),
            mock.patch.object(rtpflood, "_send_rtp_flood", return_value=(1000, 1_212_000)),
            mock.patch.object(rtpflood, "_hangup_call"),
            mock.patch.object(rtpflood.time, "sleep"),
        ):
            self.assertEqual(rtpflood.cmd_rtpflood(args), 1)


if __name__ == "__main__":
    unittest.main()
