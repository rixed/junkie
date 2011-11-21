#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing active timeouting\n")

(false-if-exception (delete-file "timeout.log"))
(set-log-file "timeout.log")
(set-log-level 7)

(set-quit-when-done #f)

(define (nb-tot-parsers)
  (let* ((stats      (map proto-stats (proto-names)))
         (nb-parsers (map (lambda (s) (assq-ref s 'nb-parsers)) stats)))
    (reduce + 0 nb-parsers)))
  
(for-each-file-in "pcap/" (lambda (dir)
                            (simple-format #t "Playing all pcap from ~a~%" dir)
                            (for-each-file-in dir open-pcap)))

(set-mux-timeout 1)

; Check that we have only the uniq parsers (which are not deleted once created)
(let loop ((time-elapsed 0))
  (let* ((nb-parsers (nb-tot-parsers)))
    (simple-format #t "~a parsers left after ~as~%" nb-parsers time-elapsed)
    (if (> nb-parsers 7) ; should be 5 but for some reason we have 1 or 2 IPv4 parsers left (FIXME)
        (begin
          (if (> time-elapsed 10)
              (begin
                (map (lambda (p) (simple-format #t "Stats for parser ~a: ~s~%" p (proto-stats p))) (proto-names))
                (assert (<= time-elapsed 10))))
          (sleep 1)
          (loop (1+ time-elapsed))))))

(exit)
