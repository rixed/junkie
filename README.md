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


Limitations
===========

As a realtime protocol analyzer, Junkie is limited in what protocols it
supports and how deep it inspects packets. Here is a quick overview of the
most blatant limitations:

- Ethernet parser supports Linux cooked capture as a special case (used when
  capturing on "any" interfaces) and 802.1q vlan tags. All other Ethernet
  extensions are ignored.

- ARP parser knows only Ethernet and IP addresses.

- DNS parser supports MDNS, NBNS and LLMNR in the extend where these protocols
  mimic legacy DNS (with the exception that it can unscramble NetBios encoded
  names).

- FTP connection tracking merely look for PASSV or PORT commands in the TCP
  stream without much care for the actual protocol.

- Postgresql parser supports only protocol version 3.0 and Mysql parser
  supports only protocol version 10.  This should cover most of the installed
  base, though.

- TNS parser (for Oracle databases) was roughly reverse engineered from
  various sources, especially the wireshark source code. It should thus not
  be expected to understand all messages in all situations.

- SIP parser implements no proprietary extensions, however prevalent.

- VoIP dialogs are identified by their call-id only, which imply that if
  the sniffer listens to various independent SIP proxys or servers then
  call-id collisions can not be ruled out (this choice was made because
  it proven useful in practice).


Todo
====

Protocol discovery
------------------

Given some signatures, discover some protocols (likely targets: RT(C)P, peer
to peer...).

We could do this with ordinary parsers but it would not be very convenient for
the coder (many boilerplate code involved) nor very convenient for the user
(had to tcp-add-port/udp-add-port many protocols in the right order) nor very
efficient (parent parser, for instance TCP, trying every protocol in turn until
one match). So we instead goes the snort route : run a single process through a
database of descriptions, and return the discovered protocol. If this protocol
had a specific parser then pass it the payload (required for RT(C)P).

We should run this discovery process when some payload remain unparsed at the
end of `proto_parse` call chain, with it's result attached as another
`proto_info` (if there are no better parser for the discovered protocol).

This port independant protocol identification should be feed with rules from guile,
which could be taken from snort, l7 filter or bro signatures, and thus should
be able to understand most of what these signature format offers (such as
regexes, simple header field checks...) + the optional follow-up parser.
A particularity of bro rules is that one can combine several rules but this is
seldom used.

For these filters, one would want to have in `tcp_info` the relavetive sequence
number.


Netmatch language
-----------------

- a type for signed integers (in a way or another - maybe the few operators
  that really care should exist in two variants?);

- a type for byte strings (ideally a special form that build a `char[]` from a
  byte string such as `f1:ab:01:14:00:a7`);

- a special proto 'rest' for the unparsed payload (at this point);

- another special form for converting a name to an `ip_addr` (or a regular
  function if we optimize constant away from runtime exec - see below about
  purity);

- a function for matching an ip with a subnet;

- pure functions taking only constants (and thus returning a constant) should
  be precomputed;

- a random function;

- a slice operator to extract a string from another string;

- binary operators on integers (`&`, `|`, `^`, `!`, `<<` and `>>`)

- it should be correct to match with: `(eth) ((ip) (...) or (arp) (...))`.
  in other words, the proto list should be a special form (binding current
  protos) rather than a fixed preamble.

- a list of every valid fields (with a docstrings) for better error messages;

- a higher level language resembling wireshark's, with automatic insertion of
  `set?` predicates;

Nettrack language
-----------------

- More entry functions than `pass` (start with a `scm-eval` that calls a given
  Guile function);

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

