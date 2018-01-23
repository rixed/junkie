#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

(test "index of bytes"
      '([ ]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
            (match (tcp)
                   (and
                       ; Params are (index-of-bytes haystack needle offset max default)
                       ; Normal check
                       ((index-of-bytes #(0 1 2) #(1) 0 4 999) == 1)
                       ((index-of-bytes #(0 1 2) #(1 2) 0 4 999) == 1)
                       ; Check offset
                       ((index-of-bytes #(1 1 2) #(1) 0 4 999) == 0)
                       ((index-of-bytes #(1 1 2) #(1) 1 4 999) == 1)
                       ((index-of-bytes #(1 1 2) #(1 2) 1 4 999) == 1)
                       ((index-of-bytes #(1 1 2) #(1) 2 4 999) == 999)
                       ; Check Max
                       ((index-of-bytes #(0 1 2) #(1) 0 2 999) == 1)
                       ((index-of-bytes #(0 1 2) #(2) 0 1 999) == 999)))
            spawn)]))

(assert (>= called 54))

(exit 0)
