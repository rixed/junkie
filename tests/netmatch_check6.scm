#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Just test compilation of random

(test "random"
      '([]
        []
        [(root node
            (match (ip) ((random 10) >= (random 50))))]))

;; good enough!
(exit 0)
