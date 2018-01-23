#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

(test "uint32-at"
      '([ ]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
               (match (tcp)
                      (and
                        ((#(0 0 0 1) @32n 0) == 1)
                        ((#(0 #xfe #xf4 #x00 #x01 0) @32n 1) == #xfef40001)
                        ((#(0 0 #x00 #x01) @16n 2) == #x0001)
                        ((#(0 0 0 1 #x01 #x01) @16n 4) == #x0101)))
                      spawn)]))

(assert (>= called 54))

(exit 0)
