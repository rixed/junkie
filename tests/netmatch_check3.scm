#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Test subneting

(test "subnets"
      '([]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
           (match (ip) (in-subnet? ip.src 192.168.10.0/255.255.255.0))
           spawn)]))

(assert (= called 32))

;; good enough!
(exit 0)
