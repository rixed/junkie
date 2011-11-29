#!../src/junkie -c
; vim:syntax=scheme filetype=scheme expandtab
!#

(display "Testing packet source statistics\n")

(set-log-file "pkt_source_stats.log")
(set-log-level 7)

; We cannot play a pcap and then when it's done read the statistics since the
; statistics would be automatically deleted when the pcap is read in full.
; So we trick this by reading in realtime a special pcap with a final
; packet very far in the future so we have time to read the stats counters.
(define pcap-file "long_and_truncated.pcap")
(open-pcap (string-append "pcap/misc/" pcap-file) #t)

(define (wait-packets n)
  (let ((packets (assoc-ref (iface-stats pcap-file) 'nb-packets)))
    (if (< packets n)
        (begin
          (usleep 10000)
          (wait-packets n)))))

(wait-packets 2) ; wait for all but the last packet

(let ((stats    (iface-stats pcap-file)))
  (assert (eqv? (assoc-ref stats 'nb-packets) 2))
  (assert (eqv? (assoc-ref stats 'nb-duplicates) 0))
  (assert (eqv? (assoc-ref stats 'nb-cap-bytes) (+ 42 42)))
  (assert (eqv? (assoc-ref stats 'nb-wire-bytes) (+ 74 60))))

; (close-iface pcap-file)
; This would not terminate junkie immediately since the sniffer thread is
; currently sleeping until it's time for the 3rd packet.

; good enough
(exit)
