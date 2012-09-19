#!../src/junkie -c
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

(display "Testing netmatch expressions\n")

(define logfile "netmatch_check.log");
(false-if-exception (delete-file logfile))
(set-log-file logfile)
(set-log-level 7)
(set-log-level 3 "mutex")

(set-quit-when-done #f)

(start-repl-server)

;; Run some traffic
(define (play)
  (let ((file "pcap/http/http_multiline.pcap"))
    ; reset dedup
    (reset-digests)
    ; play
    (open-pcap file)
    ; wait completion
    (while (not (null? (iface-names)))
           (usleep 100))))

(define called 0)

(define (test test-name expr)
  (simple-format #t "Running test ~a~%" test-name)
  (slog log-notice "Running test ~a~%" test-name)
  (let ((compiled (nt:compile test-name expr)))
    (set! called 0)
    (nettrack-start compiled)
    (play)
    (nettrack-stop compiled)
    (simple-format #t "Callback was called ~a times~%" called)))

(define (incr-called)
  (set! called (1+ called)))
(export incr-called)

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

; Same as above, but types are infered
(test "fibonacci (type infered)"
      '([(count uint) ; count and fibo must be given since not inferrable in entry expression
         (fibo uint)] ; no other declarations
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

; Test subneting

(test "subnets"
      '([]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
           (match (ip) (in-subnet? ip.src 192.168.10.0/255.255.255.0))
           spawn)]))

(assert (= called 32))

; Test TCP relative sequence numbers

(test "TCP relative sequence numbers"
      '([]
        [(node
           (on-entry (apply (check) incr-called)))]
        [(root node
           (match (tcp) (tcp.rel-seq-num == 1))
           spawn)]))

(assert (= called 23))

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
