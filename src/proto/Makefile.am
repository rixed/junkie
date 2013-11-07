AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src -D_GNU_SOURCE -DVARDIR="@VARDIR@"

noinst_LTLIBRARIES = libproto.la

libproto_la_SOURCES = \
	arp.c cap.c cifs.c dns.c dns_tcp.c \
	eth.c ftp.c fuzzing.c fuzzing.h \
	http.c liner.c liner.h httper.c httper.h \
	icmp.c icmpv6.c ip_hdr.h ip.c ip6.c mgcp.c netbios.c \
	port_muxer.c proto.c \
	rtcp.c rtp.c \
	sdp.c sdper.c sdper.h \
	sip.c \
	tcp.c udp.c \
	postgres.c \
	mysql.c \
	tns.c \
	gre.c \
	tls.c \
	pkt_wait_list.c \
	streambuf.c \
	cursor.c \
	cnxtrack.c \
	capfile.c \
	os-detect.c \
	discovery.c \
	hook.c \
	erspan.c \
	ber.c \
	skinny.c \
	dhcp.c \
	fcoe.c \
	tds.c tds_msg.c

libproto_la_LIBADD = ../tools/libjunkietools.la
libproto_la_LDFLAGS = -export-dynamic

.INTERMEDIATE: $(srcdir)/p0f.fp $(srcdir)/fp_2_c.py
$(srcdir)/os-detect.c: $(srcdir)/p0f.fp $(srcdir)/fp_2_c.py
	$(srcdir)/fp_2_c.py < $< > $@

