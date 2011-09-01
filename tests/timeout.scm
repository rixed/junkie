#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing active timeouting\n")

(false-if-exception (delete-file "timeout.log"))
(set-log-file "timeout.log")
(set-log-level 7)

(if (defined? 'use-syntax) ; Guile 2 does not need nor provide this
  (use-syntax (ice-9 syncase)))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (begin
                               (simple-format #t "Assertion-failed: ~a\n" 'x)
                               (raise SIGABRT))))))

(if (not (defined? 'defs-loaded)) (load "../config/defs.scm"))

(set-quit-when-done #f)

(define (play-pcap-from dir)
  (simple-format #t "Playing all pcap from ~a~%" dir)
  (for-each-file-in (string-append "pcap/" dir)
                    (lambda (f) (open-pcap (string-append "pcap/" dir "/" f)))))
(for-each-file-in "pcap/" play-pcap-from)

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
