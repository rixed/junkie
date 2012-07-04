; vim:syntax=scheme filetype=scheme expandtab
;;; This module contains general purpose functions.

(define-module (junkie defs))

(use-modules (srfi srfi-1)
             (ice-9 regex)
             (ice-9 optargs)
             (ice-9 format)
             (ice-9 threads)
             (junkie runtime)
             (junkie tools))

;; Some definitions the user likely want to use

(define-public log-emerg   0) (define-public log-alert  1) (define-public log-crit 2) (define-public log-err   3) (define-public log-error 3)
(define-public log-warning 4) (define-public log-notice 5) (define-public log-info 6) (define-public log-debug 7)

(define-syntax slog
  (syntax-rules ()
    ((_ lvl fmt ...) (let* ((loc   (current-source-location))
                            (stack (make-stack #t))
                            (msg   ((@ (ice-9 format) format) #f fmt ...))
                            (file  (or (and=> (assq-ref loc 'filename) basename) "<some file>"))
                            (func  (or (and=> (procedure-name (frame-procedure (stack-ref stack 1))) symbol->string) "")))
                       (primitive-log lvl file func msg)))))
(export-syntax slog)

; This one might be usefull to display all help available
(define-public (help)
  (for-each (lambda (l)
              (display "------------------\n")
              (display l)
              (newline))
            (?)))


; Start a server that executes anything (from localhost only)
(define*-public (start-repl-server #:key
                                   (port 29000)
                                   (prompt (lambda () "junkie> "))
                                   (env-or-module (resolve-module '(junkie defs))))
  (letrec ((consume-white-spaces (lambda (port)
                                   (let ((c (peek-char port)))
                                     (cond ((eqv? c #\eot) (begin
                                                             (display "Bye!\r\n")
                                                             (throw 'quit)))
                                           ((char-whitespace? c) (begin
                                                                   (read-char)
                                                                   (consume-white-spaces port))))))))
    (let* ((repl (lambda ()
                   (let ((reader  (lambda (port)
                                    (display (prompt))
                                    (consume-white-spaces port)
                                    (read port)))
                         (evaler  (lambda (expr)
                                    (catch #t
                                           (lambda () (eval expr env-or-module))
                                           (lambda (key . args)
                                             (if (eq? key 'quit) (apply throw 'quit args))
                                             `(error ,key ,args)))))
                         (printer pp))
                     (set-thread-name "J-repl-client")
                     ; Use repl defined in ice-9 boot
                     (repl reader evaler printer)))))
      (make-thread (lambda ()
                     (set-thread-name "J-repl-server")
                     (start-server (inet-aton "127.0.0.1") port repl))))))

; An equivalent of the old fashionned display command line option
(define-public (display-parameters)
  (let ((display-one (lambda (p)
                       (simple-format #t "~a: ~a\n" p (get-parameter-value p)))))
    (for-each display-one (parameter-names))))

; Display the memory consumption due to Guile
(define-public (guile-mem-stats)
  (let* ((stats     (gc-stats))
         (use-bdwgc (assq 'heap-size stats))
         (sum-size (lambda (x s)
                     (let ((a (car x))
                           (b (cdr x)))
                       (+ s (- b a))))))
    (if use-bdwgc
        (assq-ref stats 'heap-size)
        (fold sum-size 0 (assq-ref stats 'cell-heap-segments)))))

; Display the memory consumption and allocation due to the redimentionable arrays
(define-public (array-mem-stats)
  (let* ((tot-used-bytes     0)
         (tot-malloced-bytes 0)
         (stats              (filter-map (lambda (n)
                                           (let* ((s              (array-stats n)))
                                             (if (> (assq-ref s 'nb-malloced) 0)
                                                 (let* ((used-bytes     (* (- (assq-ref s 'nb-used)
                                                                              (assq-ref s 'nb-holes))
                                                                           (assq-ref s 'entry-size)))
                                                        (malloced-bytes (* (assq-ref s 'nb-malloced)
                                                                           (assq-ref s 'entry-size)))
                                                        (compactness    (exact->inexact (/ used-bytes malloced-bytes))))
                                                   (set! tot-used-bytes     (+ tot-used-bytes     used-bytes))
                                                   (set! tot-malloced-bytes (+ tot-malloced-bytes malloced-bytes))
                                                   `(,n . (,@s
                                                            (used-bytes . ,used-bytes)
                                                            (malloced-bytes . ,malloced-bytes)
                                                            (compactness . ,compactness))))
                                                 #f)))
                                         (array-names))))
    `(,@(sort stats
              (lambda (a b)
                (< (assq-ref (cdr a) 'malloced-bytes)
                   (assq-ref (cdr b) 'malloced-bytes))))
       (total . ((used-bytes . ,tot-used-bytes)
                 (malloced-bytes . ,tot-malloced-bytes)
                 (compactness . ,(exact->inexact (if (> tot-malloced-bytes 0)
                                                     (/ tot-used-bytes tot-malloced-bytes)
                                                     1))))))))

; Display malloc statistics
(define-public (mallocer-mem-stats)
  (let* ((size     (lambda (name) (cdr (assoc 'tot-size (mallocer-stats name)))))
         (tot-size (apply + (map size (mallocer-names))))
         (stat-one (lambda (name) (cons name (size name)))))
    (append!
      (map stat-one (mallocer-names))
      (list (cons "total" tot-size)))))

; get the percentage of duplicate frames over the total number (check out if the
; port mirroring is correctly set)
(define-public (duplicate-percentage)
  (let* ((sums     (fold (lambda (iface prev)
                           (let* ((stats     (iface-stats iface))
                                  (packets   (assq-ref stats 'nb-packets))
                                  (dups      (assq-ref stats 'nb-duplicates))
                                  (prev-pkts (car prev))
                                  (prev-dups (cdr prev)))
                             (cons (+ prev-pkts packets) (+ prev-dups dups))))
                         '(0 . 0) (iface-names)))
         (tot-pkts (car sums))
         (tot-dups (cdr sums)))
    (if (> tot-pkts 0)
        (exact->inexact (/ (* 100 tot-dups) tot-pkts))
        -1)))

; get the percentage of dropped packets
(define-public (dropped-percentage)
  (let* ((tot-drop (fold (lambda (iface prevs)
                           (let* ((stats     (iface-stats iface))
                                  (received  (assq-ref stats 'tot-received))
                                  (dropped   (assq-ref stats 'tot-dropped))
                                  (prev-recv (car prevs))
                                  (prev-drop (cdr prevs)))
                             (catch 'wrong-type-arg
                                    (lambda () (cons (+ prev-recv received) (+ prev-drop dropped)))
                                    (lambda (key . args) prevs))))
                         '(0 . 0) (iface-names)))
         (total    (car tot-drop))
         (dropped  (cdr tot-drop)))
    (if (> total 0)
        (exact->inexact (/ (* 100 dropped) total))
        -1)))

; backward compatible function set-ifaces
(define-public (ifaces-matching pattern)
  (let ((ifaces (list-ifaces)))
    (if (list? ifaces)
        (filter
          (lambda (ifname) (string-match pattern ifname))
          (list-ifaces)))))

(define-public (closed-ifaces-matching pattern)
  (let* ((matching (ifaces-matching pattern))
         (opened   (iface-names)))
    (lset-difference equal? matching opened)))

(define*-public (set-ifaces pattern #:key (capfilter "") (bufsize 0) (caplen 0))
  (for-each
    (lambda (ifname) (open-iface ifname #t capfilter caplen bufsize))
    (closed-ifaces-matching pattern)))

; build a list of pcap filter suitable to split traffic through 2^n+1 processes
; n must be >= 1
(define* (pcap-filters-for-split n #:key (capfilter ""))
  (letrec ((mask        (- (ash 1 n) 1))
           (next-filter (lambda (prevs i)
                          (if (> i mask)
                            prevs
                            (let* ((partition   (format #f "ip[11] & 0x~x = ~d" mask i))
                                   (with-user   (if (string-null? capfilter)
                                                    partition
                                                    (format #f "((~a) and (~a))" capfilter partition)))
                                   ; **BEWARE**: Due to a bug in libpcap 'test or (vlan and test)' works as expected
                                   ;             while '(vlan and test) or test' DO NOT!
                                   ;             Also, 'not vlan' does not work as expected.
                                   (vlan-aware  (format #f "(~a) or (vlan and (~a))" with-user with-user)))
                              (next-filter (cons vlan-aware prevs) (1+ i))))))
           (unpartionable (if (string-null? capfilter)
                              "not ip and not (vlan and ip)"
                              ; You'd better not mess with this one, this is not your ordinary logic!
                              (format #f "not ip and (~a) and not (vlan and ip) and (~a)" capfilter capfilter))))
    (next-filter (list unpartionable) 0)))

; Equivalent of set-ifaces for multiple CPUs
(define*-public (open-iface-multiple n ifname #:key (capfilter "") (bufsize 0) (caplen 0) (promisc #t))
  (let* ((filters     (pcap-filters-for-split n #:capfilter capfilter))
         (open-single (lambda (flt) (open-iface ifname promisc flt caplen bufsize))))
    (for-each open-single filters)))

(define*-public (set-ifaces-multiple n pattern #:rest r)
  (make-thread (lambda ()
    (set-thread-name "J-set-ifaces")
    (let loop ()
      (for-each
        (lambda (ifname) (apply open-iface-multiple `(,n ,ifname ,@r)))
        (closed-ifaces-matching pattern))
      (sleep 30)
      (loop)))))

; A simple function to check wether the agentx module is available or not
(define-public have-snmp (false-if-exception (resolve-interface '(agentx tools))))

; Helper function handy for answering SNMP queries : cache a result of some expensive function for some time
(define-public (cached timeout)
  (let* ((hash      (make-hash-table 50)) ; hash from (func . args) into (timestamp . value)
         (ts-of     car)
         (value-of  cdr)
         (mutex     (make-mutex)))
    (lambda func-args
      (with-mutex mutex
                  (let* ((hash-v (hash-ref hash func-args))
                         (now    (current-time)))
                    (if (and hash-v (<= now (+ timeout (ts-of hash-v))))
                        (value-of hash-v)
                        (let ((v (primitive-eval func-args)))
                          (hash-set! hash func-args (cons now v))
                          v)))))))

; Helper functions that comes handy when configuring muxer hashes

(define-public (make-mux-hash-controller coll-avg-min coll-avg-max h-size-min h-size-max)
  (lambda (proto)
    (let* ((stats    (mux-stats proto))
           (h-size   (assq-ref stats 'hash-size))
           (colls    (assq-ref stats 'nb-collisions))
           (lookups  (assq-ref stats 'nb-lookups))
           (coll-avg (if (> lookups 0) (/ colls lookups) -1))
           (resize   (lambda (coll-avg new-h-size)
                       (let ((new-max-children (* new-h-size coll-avg-max 10)))
                         (slog log-info "Collision avg of ~a is ~a. Setting hash size to ~a (and max children to ~a)"
                               proto (exact->inexact coll-avg) new-h-size new-max-children)
                         (set-mux-hash-size proto new-h-size)
                         (set-max-children proto new-max-children)))))
      (if (< coll-avg coll-avg-min) ; then make future hashes smaller
          (if (> h-size h-size-min)
              (resize coll-avg (max h-size-min (round (/ h-size 2))))))
      (if (> coll-avg coll-avg-max) ; then make future hashes bigger
          (if (< h-size h-size-max)
              (resize coll-avg (min h-size-max (* h-size 2))))))))

;; A thread that will limit UDP/TCP muxers to some hash size and collision rates

(define*-public (start-resizer-thread  #:key
                                (min-collision-avg 4)   ; collision average under which we will make hash tables bigger
                                (max-collision-avg 16)  ; collision average above which we will make hash tables smaller
                                (min-hash-size     11)  ; minimal hash table size under which we won't venture
                                (max-hash-size     353) ; maximal etc
                                ; So by default we can happily store 353*16*2=11k different sockets between two given hosts
                                (period            60)) ; how many seconds we wait between two measurments (it's important to wait for the stats to settle)
  (let* ((limiter (make-mux-hash-controller
                    min-collision-avg max-collision-avg min-hash-size max-hash-size))
         (thread  (lambda ()
                    (set-thread-name "J-hash-resizer")
                    (let loop ()
                      (sleep period)
                      (limiter "TCP")
                      (limiter "UDP")
                      ;; Achtung!
                      ;; We use the statistics of the running multiplexers to change the settings of the future multiplexers.
                      ;; So in a situation where the multiplexers are not often recycled we will keep changing settings for
                      ;; multiplexers that are actually unafected by these changes. So we'd better reserve this for short
                      ;; lived multiplexers such as TCP and UDP, and not long lived ones such as IP.
                      ;(limiter "IPv4")
                      ;(limiter "IPv6")
                      (loop)))))
    (make-thread thread)))

; A thread that will periodically report on stdout the number of TCP/UDP simultaneous streams

(define-public (report-cnx period)
  (let ((thread (lambda (period)
                  (set-thread-name "J-report-cnx")
                  (let ((max-tcp 0)
                        (max-udp 0))
                    (let loop ()
                      (let ((cur-tcp (assq-ref (proto-stats "TCP") 'nb-parsers))
                            (cur-udp (assq-ref (proto-stats "UDP") 'nb-parsers)))
                        (if (> cur-tcp max-tcp) (set! max-tcp cur-tcp))
                        (if (> cur-udp max-udp) (set! max-udp cur-udp))
                        (simple-format #t "Current TCP:~a UDP:~a total:~a / Max TCP:~a UDP:~a total:~a~%"
                              cur-tcp cur-udp (+ cur-tcp cur-udp)
                              max-tcp max-udp (+ max-tcp max-udp))
                        (sleep period)
                        (loop)))))))
    (make-thread thread period)))

