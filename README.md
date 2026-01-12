# rtproute
UDP traceroute with RTP payload using scapy

```
UDP traceroute with RTP payload

optional arguments:
  -h, --help            show this help message and exit
  -f first_ttl, --first=first_ttl
                        Start from the first_ttl (instead from 1)
  -i device, --interface=device
                        Specify a network interface to operate with
  --inc-seqno=inc_seqno
                        Increment RTP sequence number per ttl
  -m max_ttl, --max-hops=max_ttl
                        Set the max number of max_ttl (max TTL to be reached). Default is 30
  --payload-type=payload_type
                        Set the RTP payload type, Default is 0 (G711u)
  -p port, --port=port  Set the destination port to use, Default 33434
  -q, --quiet           Do not print responses
  -s src_addr, --source=src_addr
                        Use source src_addr for outgoing packets
  --seqno=seqno         Set the RTP sequence number, Default is 1
  --sport=              Use source port num for outgoing packets, Default is 5060
  --ssrc=ssrc           Set the RTP SSRC, Default is 0
  --timestamp=ssrc      Set the RTP timestamp field, Default is 0
  -w max_wait, --wait=max_wait
                        Wait for a probe no more than this amount of seconds. Default is 1.0 (float)

positional arguments:
  host                  The host to rtproute to
  packetlen             The full packet length (default is the length of an IP header plus 40)
```