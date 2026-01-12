#!/usr/local/ipcs/peon/venv/bin/python3
# -*- encoding: utf-8 -*-

##############################################################################
## Name: rtproute.py
## Purpose: Implements basic UDP traceroute with RTP payload using scapy
## Date: 2026-01-11
## Author: sszokoly@protonmail.com
## License: MIT
## Version: 0.1
## Source: https://github.com/sszokoly/rtproute
##############################################################################

import socket
from scapy.all import conf, Raw, sr1
from scapy.layers.inet import ICMP, IP, UDP
from scapy.layers.rtp import RTP

"""
RTP Header format (12 bytes):
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|V=2|P|X|  CC   |M|     PT      |       sequence number         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           timestamp                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           synchronization source (SSRC) identifier            |
+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
"""

def make_rtp(
        version: int = 2,              # RTP version (2)
        padding: int = 0,              # Padding flag
        extension: int = 0,            # Extension flag
        numsync: int = 0,              # CSRC count
        marker: int = 0,               # Marker bit
        payload_type: int = 0,         # Payload type 0=G711u, 8=G711a, 18=G729
        sequence: int = 1,             # Sequence number
        timestamp: int = 0,            # Timestamp (Inc 160 for G711/8kHz/20ms)
        sourcesync: int = 0,           # SSRC
        sync=[],                       # CSRC list
        rtp_payload=None               # RTP payload
        
    ):

    rtp_packet = RTP(
        version=version,
        padding=padding,
        extension=extension,
        numsync=numsync,
        marker=marker,
        payload_type=payload_type,
        sequence=sequence,
        timestamp=timestamp,
        sourcesync=sourcesync,
        sync=sync
    )
    rtp_payload = rtp_payload if rtp_payload else b'\x00' * 160
    return rtp_packet / Raw(load=rtp_payload)


def rtproute(host, port=33434, src_addr=None, sport=5060, device=None,
             max_ttl=30, first_ttl=1, max_wait=2, packetlen=172,
             payload_type=0, quiet=False, seqno=1, ssrc=0,
             timestamp=0, inc_seqno=False):
    """
    Custom RTP traceroute with full control over IP/UDP/RTP parameters.
    """
    if device:
        conf.iface = device

    # Resolve hostname if needed
    try:
        target_ip = socket.gethostbyname(host)
    except:
        target_ip = host

    if not quiet:
        print(f"traceroute to {host} ({target_ip}), {max_ttl} hops max, {packetlen} byte packets")

    results = []

    for ttl in range(first_ttl, max_ttl + 1):
        # Build IP layer with source
        ip = IP(dst=target_ip, ttl=ttl)
        if src_addr:
            ip.src = src_addr

        # Calculate RTP payload size
        # IP(20) + UDP(8) + RTP(12) + payload = packetlen
        rtp_payload_size = max(0, packetlen - 20 - 8 - 12)
        rtp_payload = Raw(load=b'\x00' * rtp_payload_size)
        rtp_packet = make_rtp(
            payload_type=payload_type,
            sequence=seqno,
            timestamp=timestamp,
            sourcesync=ssrc,
            rtp_payload=rtp_payload
        )
        l4 = UDP(sport=sport, dport=port) / rtp_packet

        # Build complete packet
        pkt = ip / l4

        # Send and wait for response
        reply = sr1(pkt, timeout=max_wait, verbose=0)

        if reply:
            hop_ip = reply.src
            rtt = (reply.time - pkt.sent_time) * 1000  # Convert to ms

            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(hop_ip)[0]
                output = f"{ttl:2d}  {hostname} ({hop_ip})  {rtt:.3f} ms"
            except:
                output = f"{ttl:2d}  {hop_ip}  {rtt:.3f} ms"

            if not quiet:
                print(output)

            results.append((ttl, hop_ip, rtt))

            # Check if we reached destination
            if reply.src == target_ip or reply.haslayer(ICMP) and reply[ICMP].type == 0:
                break
        else:
            if not quiet:
                print(f"{ttl:2d}  *")
            results.append((ttl, None, None))

        if inc_seqno:
            seqno += 1

    return 0 if results[-1][1] == target_ip else 1, results


if __name__ == '__main__':
    import argparse
    import sys

    sys.argv.extend(['-m', '12', '8.8.8.8'])

    class CustomHelpFormatter(argparse.HelpFormatter):
        def _format_action_invocation(self, action):
            if not action.option_strings:
                # Positional argument
                (metavar,) = self._metavar_formatter(action, action.dest)(1)
                return metavar
            else:
                parts = []
                # if the Optional doesn't take a value, format is: -s, --long
                if action.nargs == 0:
                    parts.extend(action.option_strings)
                # if the Optional takes a value, format is: -s ARGS, --long=ARGS
                else:
                    default = action.dest.upper()
                    args_string = self._format_args(action, default)
                    for option_string in action.option_strings:
                        if option_string.startswith("--"):
                            parts.append("%s=%s" % (option_string, args_string))
                        else:
                            parts.append("%s %s" % (option_string, args_string))
                return ", ".join(parts)

    parser = argparse.ArgumentParser(
        description="UDP/ICMP traceroute",
        add_help=False,
        formatter_class=CustomHelpFormatter,
    )

    # Create custom groups in desired order
    optional = parser.add_argument_group("optional arguments")
    positional = parser.add_argument_group("positional arguments")

    # Add help to optional arguments group
    optional.add_argument(
        "-h", "--help", action="help", help="show this help message and exit"
    )

    # Add all optional arguments to the optional group
    optional.add_argument(
        "-f",
        "--first",
        dest="first_ttl",
        type=int,
        default=1,
        metavar="first_ttl",
        help="Start from the first_ttl (instead from 1)",
    )
    optional.add_argument(
        "-i",
        "--interface",
        dest="device",
        default=None,
        metavar="device",
        help="Specify a network interface to operate with",
    )
    optional.add_argument(
        "--inc-seqno",
        dest="inc_seqno",
        default=False,
        metavar="inc_seqno",
        help="Increment RTP sequence number per ttl",
    )
    optional.add_argument(
        "-m",
        "--max-hops",
        dest="max_ttl",
        type=int,
        default=30,
        metavar="max_ttl",
        help="Set the max number of max_ttl (max TTL to be reached). \
              Default is 30",
    )
    optional.add_argument(
        "--payload-type",
        dest="payload_type",
        type=int,
        default=0,
        metavar="payload_type",
        help="Set the RTP payload type, Default is 0 (G711u)",
    )
    optional.add_argument(
        "-p",
        "--port",
        dest="port",
        type=int,
        default=33434,
        metavar="port",
        help="Set the destination port to use, Default 33434",
    )
    optional.add_argument(
        "-q",
        "--quiet",
        dest="quiet",
        action="store_true",
        default=False,
        help="Do not print responses",
    )
    optional.add_argument(
        "-s",
        "--source",
        dest="src_addr",
        default=None,
        metavar="src_addr",
        help="Use source src_addr for outgoing packets",
    )
    optional.add_argument(
        "--seqno",
        dest="seqno",
        type=int,
        default=1,
        metavar="seqno",
        help="Set the RTP sequence number, Default is 1",
    )
    optional.add_argument(
        "--sport",
        dest="sport",
        type=int,
        default=5060,
        metavar="",
        help="Use source port num for outgoing packets, \
              Default is 5060",
    )
    optional.add_argument(
        "--ssrc",
        dest="ssrc",
        type=int,
        default=0,
        metavar="ssrc",
        help="Set the RTP SSRC, Default is 0",
    )
    optional.add_argument(
        "--timestamp",
        dest="timestamp",
        type=int,
        default=0,
        metavar="ssrc",
        help="Set the RTP timestamp field, Default is 0",
    )
    optional.add_argument(
        "-w",
        "--wait",
        dest="max_wait",
        type=float,
        default=1.0,
        metavar="max_wait",
        help="Wait for a probe no more than this amount of seconds. \
              Default is 1.0 (float)",
    )
    positional.add_argument("host", help="The host to rtproute to")
    positional.add_argument(
        "packetlen",
        nargs="?",
        type=int,
        default=40,
        help=f"The full packet length (default is the length of an IP \
               header plus 40)",
    )
    args = parser.parse_args()
    try:
        rv, _ = rtproute(
            host=args.host,
            port=args.port,
            src_addr=args.src_addr,
            sport=args.sport,
            device=args.device,
            max_ttl=args.max_ttl,
            first_ttl=args.first_ttl,
            max_wait=args.max_wait,
            packetlen=args.packetlen,
            payload_type=args.payload_type,
            seqno=args.seqno,
            ssrc=args.ssrc,
            timestamp=args.timestamp,
            inc_seqno=args.inc_seqno,
            quiet=args.quiet
                
    )
        sys.exit(rv)
    except KeyboardInterrupt:
        print("Application terminated by user")
        sys.exit(2)
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        sys.exit(3)
