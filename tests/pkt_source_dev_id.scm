#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing packet source device id uniqueness\n")

(set-log-file "pkt_source_dev_id.log")
(set-log-level 7)

; First a tool
(define (uniq? l)
  (if (null? l) #t
      (let ((hd (car l))
            (l  (cdr l)))
        (if (null? l) #t
            (if (equal? hd (car l)) #f
                (uniq? l))))))
(assert (uniq? '(1 2 3)))
(assert (uniq? '(1)))
(assert (uniq? '()))
(assert (not (uniq? '(1 2 2))))
(assert (not (uniq? '(1 1 2))))

; Same trick used as for pkt_source_stats.scm.
; We open the same pcap several times and expect to have different ids
(define pcap-file "long_and_truncated.pcap")
(let ((pcap (string-append "pcap/misc/" pcap-file)))
  (open-pcap pcap #t)
  (open-pcap pcap #t)
  (open-pcap pcap #t))
(let* ((stats (map iface-stats (iface-names)))
       (ids   (map (lambda (s) (assoc-ref s 'id)) stats)))
  (assert (equal? 3 (length ids)))
  (assert (uniq? (sort ids <))))

; good enough
(exit)
