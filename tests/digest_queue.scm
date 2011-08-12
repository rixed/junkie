#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing digest queue interface\n")

(if (defined? 'use-syntax) ; Guile 2 does not need nor provide this
  (use-syntax (ice-9 syncase)))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (begin
                               (simple-format #t "Assertion-failed: ~a\n" 'x)
                               (raise SIGABRT))))))

; ... and on the 325988272th day, god created the initial digest buffer.
(assert (>= 100 (get-nb-digests)))

; we can create a new one, for instance a smaller one.
; notice that this setter is special as it returns a boolean instead of unspecified.
(assert (set-nb-digests 50))

; check we got what we asked for
(assert (= 50 (get-nb-digests)))

; good enough
(exit)

