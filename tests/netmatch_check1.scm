#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Test uint and basic arithmetic

(define (fibo-check n fibo)
  (simple-format #t "Fibo(~a) = ~a~%" n fibo)
  (incr-called)
  (assert (= n 38))
  (assert (= fibo 39088169)))
(export fibo-check)

(test "fibonacci"
      '([(count uint) ; packet counter
         (tmp uint) ; temp used in computation
         (prev-fibo uint)    ; Fibo of n-1
         (fibo uint)]     ; Fibo of n
        [(last-pkt
           (on-entry (apply (check) fibo-check count fibo)))]
        [(root next-pkt
            (match (cap) (do
                           (count := 1)
                           (prev-fibo := 0)
                           (fibo := 1)
                           #t)))
         (next-pkt next-pkt
            (match (cap) (do
                           ; BEWARE: we read from previous bindings and write into new ones!
                           (fibo := (fibo + prev-fibo)) ; new fibo is old fibo + old prev-fibo
                           (prev-fibo := fibo)          ; new prev-fibo is old fibo
                           (count := (count + 1))       ; new count is old count + 1
                           #t)))
         (next-pkt last-pkt
            (match (cap) (count == 38)))]))

(assert (= called 1))

;; good enough!
(exit 0)
