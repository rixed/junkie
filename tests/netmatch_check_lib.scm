#!/usr/bin/env ../src/junkie -c
; vim:syntax=scheme expandtab
!#

(define-module (check))
(use-modules ((junkie netmatch nettrack) :renamer (symbol-prefix-proc 'nt:))
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             (junkie runtime)
             (junkie tools)
             (junkie defs))

(define logfile "netmatch_check.log");
(false-if-exception (delete-file logfile))
(set-log-file logfile)
(set-log-level 7)
(set-log-level 3 "mutex")

(set-quit-when-done #f)

;; Run some traffic
(define (play)
  (let ((file (string-append (getenv "srcdir") "/pcap/http/http_multiline.pcap")))
    ; reset dedup
    (reset-digests)
    ; play
    (open-pcap file)
    ; wait completion
    (while (not (null? (iface-names)))
           (usleep 100000))))

(define called 0)
(export called)

(define (test test-name expr)
  (simple-format #t "Running test ~a~%" test-name)
  (slog log-notice "Running test ~a~%" test-name)
  (let ((compiled (nt:compile test-name expr)))
    (set! called 0)
    (nettrack-start compiled)
    (play)
    (nettrack-stop compiled)
    (simple-format #t "Callback was called ~a times~%" called)))
(export test)

(define (incr-called)
  (set! called (1+ called)))
(export incr-called)

