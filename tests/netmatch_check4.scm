#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Test TCP relative sequence numbers

(test "TCP relative sequence numbers"
      '([]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
           (match (tcp) (tcp.rel-seq-num == 1))
           spawn)]))

(assert (= called 23))

;; good enough!
(exit 0)
