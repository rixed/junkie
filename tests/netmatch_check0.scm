#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(define-module (check))
(use-modules ((junkie netmatch nettrack) :renamer (symbol-prefix-proc 'nt:))
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             (junkie runtime)
             (junkie tools)
             (junkie defs))

(display "Testing netmatch tools\n")

(assert (type:looks-like-subnet? '192.168.10.0/255.255.255.0))
(assert (type:looks-like-bytes? #(1 2 3 4 5)))
(assert (type:looks-like-bytes? #(1)))

;; good enough!
(exit 0)
