#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing packet source statistics\n")

(use-syntax (ice-9 syncase))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (begin
                               (simple-format #t "Assertion-failed: ~a\n" 'x)
                               (raise SIGABRT))))))

; We cannot play a pcap than when it's done read the statistics, since the
; statistics would be automatically deleted when the pcap is read in full.
; So we trick this by reading in realtime a special pcap with a final
; packet very far in the future so we have time to read the stats counters.
(define pcap-file "long_and_truncated.pcap")
(open-pcap (string-append "pcap/misc/" pcap-file) #t)

(usleep 300000) ; wait for all but the last packet

(let ((stats    (iface-stats pcap-file)))
  (assert (eqv? (assoc-ref stats 'nb-packets) 2))
  (assert (eqv? (assoc-ref stats 'nb-duplicates) 0))
  (assert (eqv? (assoc-ref stats 'nb-cap-bytes) (+ 42 42)))
  (assert (eqv? (assoc-ref stats 'nb-wire-bytes) (+ 74 60))))

(close-iface pcap-file)

; good enough
(exit)
