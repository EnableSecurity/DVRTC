#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

from dvrtc_attack_common import (
    FREESWITCH_LUA_SQLI_EXTENSION,
    run_freeswitch_lua_sqli_check,
)


def cmd_freeswitch_lua_sqli(args: argparse.Namespace) -> int:
    return run_freeswitch_lua_sqli_check(
        args.host,
        args.extension,
        target_did=args.target_did,
        query_did=args.query_did,
        injected_extension=args.injected_extension,
        expected_early_media_code=args.expected_early_media_code,
        response_window=args.response_window,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the FreeSWITCH Lua freeswitch.Dbh SQL injection demo"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--extension", default=FREESWITCH_LUA_SQLI_EXTENSION)
    parser.add_argument("--target-did", default="9000")
    parser.add_argument(
        "--query-did",
        default="",
        help="Query the DID mapping for this value instead of querying the mapping for --target-did",
    )
    parser.add_argument("--expected-early-media-code", type=int, default=183)
    parser.add_argument(
        "--injected-extension",
        default="",
        help="Override the injected called SIP URI user part",
    )
    parser.add_argument("--response-window", type=float, default=4.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    return cmd_freeswitch_lua_sqli(args)


if __name__ == "__main__":
    raise SystemExit(main())
