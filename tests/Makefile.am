##AUTOMAKE_OPTIONS = color-tests
AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src -I $(top_srcdir)/src/proto \
              -D_GNU_SOURCE -DSRCDIR=$(top_srcdir)/tests

check_PROGRAMS = \
	digest_queue_check timeval_check files_check \
	hash_check liner_check ip_addr_check \
	log_check redim_array_check mallocer_check \
	ip_check udp_check tcp_check http_check skinny_check sip_check \
	sdp_check mgcp_check dns_check cnxtrack_check \
	icmp_check rtcp_check flood_check port_range_check \
	arp_check pkt_wait_list_check ip_reassembly_check \
	tcp_reorder_check streambuf_check cli_check \
	postgres_check endianness_check \
	cursor_check mutex_check \
	mysql_check tns_check tls_check tds_check

dist_check_SCRIPTS = \
	postgres.test mysql.test oracle.test tds.test dns.test \
	http-truncation.test \
	pkt_source_stats.scm eth_padding.test \
	pkt_source_dev_id.scm ftp.test gre.test \
	ip.test timeout.scm eth.test cifs.test sip.test \
	writer_check.scm \
	dedup_conf1.test dedup_conf2.test \
	http.test http-chunked.test http-multiline.test \
	tcp.test os-detect.test icmp.test tools-check \
	netmatch_check0.scm netmatch_check1.scm \
	netmatch_check2.scm netmatch_check3.scm \
	netmatch_check4.scm netmatch_check5.scm \
	netmatch_check6.scm netmatch_check7.scm \
	netmatch_check8.scm netmatch_check8.scm \
	sock-check.scm discovery.test tls.test  \
	dhcp.test fcoe.test gtp.test

TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)

AM_TESTS_ENVIRONMENT = \
	export EF_ALLOW_MALLOC_0=1; \
	export GUILE_LOAD_PATH=$(top_srcdir)/guile; \
	export GUILE_LOAD_COMPILED_PATH=$(top_srcdir)/guile; \
	export GUILE_AUTO_COMPILE=0; \
	export GUILE_WARN_DEPRECATED=no; \
	export NETMATCH_CPPFLAGS="$(AM_CPPFLAGS) @GUILE_CFLAGS@ -I$(top_srcdir)/include";

TEST_EXTENSIONS = .test .scm

#LDFLAGS += -lefence

digest_queue_check_SOURCES = digest_queue_check.c
digest_queue_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
timeval_check_SOURCES = timeval_check.c
timeval_check_LDADD = ../src/tools/libjunkietools.la -lm
files_check_SOURCES = files_check.c
files_check_LDADD = ../src/tools/libjunkietools.la -lm
hash_check_SOURCES = hash_check.c
hash_check_LDADD = ../src/tools/libjunkietools.la -lm
liner_check_SOURCES = liner_check.c
liner_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
ip_addr_check_SOURCES = ip_addr_check.c
ip_addr_check_LDADD = ../src/tools/libjunkietools.la -lm
log_check_SOURCES = log_check.c
log_check_LDADD = ../src/tools/libjunkietools.la -lm
redim_array_check_SOURCES = redim_array_check.c
redim_array_check_LDADD = ../src/tools/libjunkietools.la -lm
mallocer_check_SOURCES = mallocer_check.c
mallocer_check_LDADD = ../src/tools/libjunkietools.la -lm
cli_check_SOURCES = cli_check.c
cli_check_LDADD = ../src/tools/libjunkietools.la -lm
mutex_check_SOURCES = mutex_check.c
mutex_check_LDADD = ../src/tools/libjunkietools.la -lm

ip_check_SOURCES = ip_check.c lib.c lib.h
ip_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
udp_check_SOURCES = udp_check.c lib.c lib.h
udp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
tcp_check_SOURCES = tcp_check.c lib.c lib.h
tcp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
http_check_SOURCES = http_check.c lib.c lib.h
http_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
skinny_check_SOURCES = skinny_check.c lib.c lib.h
skinny_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
sip_check_SOURCES = sip_check.c lib.c lib.h
sip_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
sdp_check_SOURCES = sdp_check.c lib.c lib.h
sdp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
mgcp_check_SOURCES = mgcp_check.c lib.c lib.h
mgcp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
dns_check_SOURCES = dns_check.c lib.c lib.h
dns_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
cnxtrack_check_SOURCES = cnxtrack_check.c lib.c lib.h
cnxtrack_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
icmp_check_SOURCES = icmp_check.c lib.c lib.h
icmp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
rtcp_check_SOURCES = rtcp_check.c lib.c lib.h
rtcp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
arp_check_SOURCES = arp_check.c lib.c lib.h
arp_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
flood_check_SOURCES = flood_check.c lib.c lib.h
flood_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
port_range_check_SOURCES = port_range_check.c lib.c lib.h
port_range_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
pkt_wait_list_check_SOURCES = pkt_wait_list_check.c lib.c lib.h ../src/proto/proto.c ../src/proto/hook.c
pkt_wait_list_check_LDADD = ../src/tools/libjunkietools.la -lm
ip_reassembly_check_SOURCES = ip_reassembly_check.c lib.c lib.h
ip_reassembly_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
tcp_reorder_check_SOURCES = tcp_reorder_check.c lib.c lib.h
tcp_reorder_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
streambuf_check_SOURCES = streambuf_check.c lib.c lib.h
streambuf_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
postgres_check_SOURCES = postgres_check.c lib.c lib.h
postgres_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
endianness_check_SOURCES = endianness_check.c
endianness_check_LDADD = ../src/tools/libjunkietools.la -lm
cursor_check_SOURCES = cursor_check.c
cursor_check_LDADD = ../src/tools/libjunkietools.la -lm
tls_check_SOURCES = tls_check.c lib.c lib.h
tls_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm
mysql_check_SOURCES = mysql_check.c lib.c lib.h sql_test.c sql_test.h
mysql_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm $(LTLIBICONV)
tds_check_SOURCES = tds_check.c lib.c lib.h sql_test.c sql_test.h
tds_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm $(LTLIBICONV)
tns_check_SOURCES = tns_check.c lib.c lib.h sql_test.c sql_test.h
tns_check_LDADD = ../src/tools/libjunkietools.la ../src/proto/libproto.la -lm

clean-local:
	rm -f *.log vgcore.* core.* core

EXTRA_DIST = \
	foreach.txt \
	dump_test \
	dedup_conf1.out \
	dedup_conf2.out \
	discovery.out \
	dns.out \
	eth.out \
	eth_padding.out \
	ftp.out \
	gre.out \
	http-chunked.out \
	http-multiline.out \
	http-truncation.out \
	icmp.out \
	ip.out \
	mysql.out \
	oracle.out \
	os-detect.out \
	postgres.out \
	sip.out \
	tcp.out \
	http.out \
	tls.out \
	netmatch_check_lib.scm \
	fcoe.out \
	gtp.out \
	pcap
