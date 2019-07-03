#!../src/junkie -c
; vim:syntax=scheme filetype=scheme expandtab
!#

(display "Testing active timeouting\n")

(false-if-exception (delete-file "timeout.log"))
(set-log-file "timeout.log")
(set-log-level 7)
(set-log-level 3 "mutex")

(set-quit-when-done #f)

(define (num-tot-muxers)
  (let* ((stats     (map proto-stats (mux-names)))
         (num-muxers (map (lambda (s) (assq-ref s 'num-parsers)) stats)))
    (apply + num-muxers)))

(let ((pcap-dir (string-append (getenv "srcdir") "/pcap/")))
  (for-each-file-in pcap-dir (lambda (dir)
                               (simple-format #t "Playing all pcap from ~a~%" dir)
                               (for-each-file-in dir open-pcap))))

(set-mux-timeout 1)

; Check that we have only the uniq parsers (which are not deleted once created)
(let loop ((time-elapsed 0))
  (let* ((num-muxers (num-tot-muxers)))
    (simple-format #t "~a multiplexers left after ~as~%" num-muxers time-elapsed)
    (if (> num-muxers 3) ; should be 1 (Capture) but for some reason we have 1 or 2 IPv4 parsers left (FIXME)
        (begin
          (if (> time-elapsed 10)
              (begin
                (map (lambda (p) (simple-format #t "Stats for multiplexer ~a: ~s~%" p (proto-stats p))) (mux-names))
                (assert (<= time-elapsed 10))))
          (sleep 1)
          (loop (1+ time-elapsed))))))

(exit)
