#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Test eager evaluation of or

(test "eager eval of or"
      '([]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
            (match (tcp) (or #t #f #f)) ; make certain that ors are composed correctly
            spawn)]))

(assert (>= called 54)) ; although there are only 54 packets we may be called more than that due to the reconstruction of HTTP messages

;; good enough!
(exit 0)
