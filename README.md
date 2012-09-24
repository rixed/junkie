Meet Junkie the network sniffer!
================================

As the heart of [SecurActive](http://www.securactive.net) network performance
monitoring application lies a real-time packet sniffer and analyzer. Modular
enough to accomplish many different tasks, we believe this tool can be a
helpful companion to the modern network administrator and analyst, and so we
decided to offer it to the public under a liberal license so that the Open
Source community can use it, play with it, and extend it with whatever feature
is deemed appropriate.

Compared to previously available tools junkie lies in between tcpdump and
wireshark. Unlike tcpdump, its purpose is to parse protocols of any depth;
unlike wireshark, through, junkie is designed to analyze traffic in real-time
and so cannot parse traffic as completely as wireshark does.

In addition, junkie's design encompasses extendability and speed:

- plug-in system + high-level extension language that eases the development and
  combination of new functionalities;

- threaded packet capture and analysis for handling of high bandwidth network;

- modular architecture to ease the addition of any protocol layer;

- based on libpcap for portability;

- well tested on professional settings.


Junkie is still being maintained and extended by SecurActive dedicated team
but we believe it can be further extended to fulfill many unforeseen purposes.


Todo
====

Protocol discovery
------------------

- Automatically convert from bro/l7-filter/snort filters to junkie protocol
  discovery

- When we found out a proto for TCP (that we know how to parse), register it
  both ways (using connection tracking hash?)


Netmatch language
-----------------

- a type for signed integers (in a way or another - maybe the few operators
  that really care should exist in two variants?);

- another special form for converting a name to an `ip_addr` (or a regular
  function if we optimize constant away from runtime exec - see below about
  purity);

- a function for matching an ip with a subnet;

- pure functions taking only constants (and thus returning a constant) should
  be precomputed;

- a random function;

- a slice operator to extract a string from another string;

- it should be correct to match with: `(eth) ((ip) (...) or (arp) (...))`.
  in other words, the proto list should be a special form (binding current
  protos) rather than a fixed preamble.

- a list of every valid fields (with a docstrings) for better error messages;

- a higher level language resembling wireshark's, with automatic insertion of
  `set?` predicates;

Nettrack language
-----------------

- A www plugin to display each netgraph state;

Reports
-------

A plugin to use the aforementioned FSM executable rules to build report to
help classify traffic;

Netflow
-------

Using the above report facility, produce netflow statistics (and stream it).

Minor
-----

- writer www plugin must mergecap fractionned pcap files for download;

Parsers for:
------------

- H323

- SCCP

- SMB

- MSSQL

