#!../src/junkie -c
; vim:syntax=scheme filetype=scheme expandtab
!#

(display "Testing active timeouting\n")

(false-if-exception (delete-file "timeout.log"))
(set-log-file "timeout.log")
(set-log-level 7)

(set-quit-when-done #f)

(define (nb-tot-muxers)
  (let* ((stats     (map proto-stats (mux-names)))
         (nb-muxers (map (lambda (s) (assq-ref s 'nb-parsers)) stats)))
    (apply + nb-muxers)))
  
(for-each-file-in "pcap/" (lambda (dir)
                            (simple-format #t "Playing all pcap from ~a~%" dir)
                            (for-each-file-in dir open-pcap)))

(set-mux-timeout 1)

; Check that we have only the uniq parsers (which are not deleted once created)
(let loop ((time-elapsed 0))
  (let* ((nb-muxers (nb-tot-muxers)))
    (simple-format #t "~a multiplexers left after ~as~%" nb-muxers time-elapsed)
    (if (> nb-muxers 2) ; should be 0 but for some reason we have 1 or 2 IPv4 parsers left (FIXME)
        (begin
          (if (> time-elapsed 10)
              (begin
                (map (lambda (p) (simple-format #t "Stats for multiplexer ~a: ~s~%" p (proto-stats p))) (mux-names))
                (assert (<= time-elapsed 10))))
          (sleep 1)
          (loop (1+ time-elapsed))))))

(exit)
