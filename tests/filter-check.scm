#!../src/junkie -c
; vim:syntax=scheme expandtab filetype=scheme
; coding: iso-8859-1
!#

(define-module (filter-check))
(use-modules (rnrs base))

(define port-first-expected "(((tcp[0:2] + tcp[2:2]) & 0x1 = 1) or ((udp[0:2] + udp[2:2]) & 0x1 = 1)) or (vlan and (((tcp[0:2] + tcp[2:2]) & 0x1 = 1) or ((udp[0:2] + udp[2:2]) & 0x1 = 1)))")
(define port-second-expected "(((tcp[0:2] + tcp[2:2]) & 0x1 = 0) or ((udp[0:2] + udp[2:2]) & 0x1 = 0)) or (vlan and (((tcp[0:2] + tcp[2:2]) & 0x1 = 0) or ((udp[0:2] + udp[2:2]) & 0x1 = 0)))")
(define port-third-expected "not (tcp or udp) and not (vlan and (tcp or udp))")
(define port-value ((@@ (junkie defs) pcap-filters-for-split) 1))
(assert (string=? port-first-expected (car port-value)))
(assert (string=? port-second-expected (cadr port-value)))
(assert (string=? port-third-expected (caddr port-value)))

(define ip-first-expected "(((ip[14:2] + ip[18:2]) & 0x3 = 3)) or (vlan and (((ip[14:2] + ip[18:2]) & 0x3 = 3)))")
(define ip-second-expected "(((ip[14:2] + ip[18:2]) & 0x3 = 2)) or (vlan and (((ip[14:2] + ip[18:2]) & 0x3 = 2)))")
(define ip-last-expected "not ip and not (vlan and ip)")
(define ip-value ((@@ (junkie defs) pcap-filters-for-split) 2 #:partition-type 'ip))

(assert (string=? ip-first-expected (car ip-value)))
(assert (string=? ip-second-expected (cadr ip-value)))
(assert (string=? ip-last-expected (car (last-pair ip-value))))

(exit 0)
