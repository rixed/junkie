#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing active timeouting\n")

(set-log-file "timeout.log")
(set-log-level 7)

(use-syntax (ice-9 syncase))
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

(simple-format #t "~a parsers left after replay~%" (nb-tot-parsers))

(set-mux-timeout 1)
(usleep 2500000)

; Check that we have only the uniq parsers (which are not deleted once created)
(let* ((nb-parsers (nb-tot-parsers)))
  (simple-format #t "~a parsers left after timeout~%" nb-parsers)
  (assert (<= nb-parsers 6)))

(exit)
