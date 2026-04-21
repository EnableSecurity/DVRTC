#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from dvrtc_attack_common import DEFAULT_XSS_PAYLOAD_TEMPLATE, run_xss_check


def cmd_xss(args: argparse.Namespace) -> int:
    return run_xss_check(
        args.host,
        args.extension,
        args.timeout,
        token=args.token,
        payload_template=args.payload_template,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Check SIP->XSS payload path")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--extension", default="1000")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--token", default="", help="Fixed token to embed in the payload and look for in logs")
    parser.add_argument(
        "--payload-template",
        default=DEFAULT_XSS_PAYLOAD_TEMPLATE,
        help="User-Agent payload template; must include '{token}'",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return cmd_xss(args)


if __name__ == "__main__":
    raise SystemExit(main())
