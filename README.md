[<img src="https://scan.coverity.com/projects/19699/badge.svg">](https://scan.coverity.com/projects/19699/badge.svg)

Meet Junkie the network sniffer!
================================

Junkie is a real-time packet sniffer and analyzer designed to monitor
application performance.  It is modular enough to accomplish many different
tasks.

Compared to previously available tools Junkie lies in between Tcpdump and
Wireshark. Unlike Tcpdump, its purpose is to parse protocols at any depth;
unlike Wireshark, through, Junkie is designed to analyze traffic in real-time
and so cannot parse traffic as exhaustively as Wireshark does.

In addition, Junkie design encompasses extendability and speed:

- plug-in system + high-level extension language that eases the development and
  combination of new functionalities;

- threaded packet capture and analysis for handling of high bandwidth network;

- modular architecture to ease the addition of any protocol layer;

- based on libpcap for portability.

[What can it do](https://github.com/rixed/junkie/blob/master/doc/demo.txt)?

[Is there a longer doc](https://github.com/rixed/junkie/blob/master/doc/doc.txt)?


Supported Protocols
===================

- Ethernet
- ERSPAN
- FCoE
- ARP
- GRE
- GTP
- DHCP
- IPv4, IPv6
- ICMP
- UDP
- TCP
- TLS
- DNS
- HTTP
- CIFS
- FTP
- Mysql
- Netbios
- Postgresql
- TDS, TNS (Oracle)
- RTCP
- RTP
- SDP
- SIP
- Skinny
- MGCP
