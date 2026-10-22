# Phase 1 capture annotations

Capture: core-dns.pcap
Summary: dns-packet-summary.csv

Frame numbers below refer specifically to this capture.

## Root referral: frames 1 and 3

- Resolver: 172.16.2.10
- Root nameserver: 172.16.3.10
- Resolver source port: 34198
- DNS transaction ID: 0x2493
- Query: example.com, type A
- The root response refers the resolver to com.
- The referral includes the nameserver address 172.16.3.20.

## Root priming: frames 2 and 4

- Query name: .
- Query type: NS
- Resolver source port: 55598
- DNS transaction ID: 0xa5ba
- This is a separate root NS priming exchange.

## TLD referral: frames 5 and 6

- Resolver: 172.16.2.10
- TLD nameserver: 172.16.3.20
- Resolver source port: 55174
- DNS transaction ID: 0x7140
- Query: example.com, type A
- The .com response refers the resolver to example.com.
- The referral includes the nameserver address 172.16.3.30.

## Authoritative answer: frames 7 and 8

- Resolver: 172.16.2.10
- Domain nameserver: 172.16.3.30
- Resolver source port: 49952
- DNS transaction ID: 0xa9a8
- Query: example.com, type A
- The answer gives example.com as 172.16.1.20.

## Routing

The resolver route to 172.16.3.10 uses next hop 172.16.2.3.
The capture shows the resolver's DNS queries using source address 172.16.2.10.

## Interpretation note

The CSV lists DNS records from multiple message sections together.
Use dns-packet-details.txt to distinguish the Answer, Authority,
and Additional sections. In particular, identify the final A answer
separately from the nameserver address records.

The client-side dig output and HTTP fetch are separate evidence of
what the client received.
