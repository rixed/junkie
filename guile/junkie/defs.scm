; vim:syntax=scheme expandtab
;;; This modules contains general purpose functions.

(define-module (junkie defs))

(use-modules (srfi srfi-1)
             (ice-9 regex)
             (ice-9 optargs)
             (ice-9 format)
             (ice-9 threads)
             (junkie runtime))

;; Some definitions the user likely want to use

(define-public log-emerg   0) (define-public log-alert  1) (define-public log-crit 2) (define-public log-err   3)
(define-public log-warning 4) (define-public log-notice 5) (define-public log-info 6) (define-public log-debug 7)

; This one might be usefull to display all help available
(define-public (help)
  (for-each (lambda (l)
              (display "------------------\n")
              (display l)
              (newline))
            (?)))

; A pretty printer
(define-public pp (@ (ice-9 pretty-print) pretty-print))

; Run a server on given port
(define (start-server ip-addr port serve-client)
  (let* ((sock-fd (socket PF_INET SOCK_STREAM 0))
         (serve-socket (lambda (client-cnx)
                         (let* ((client-fd   (car client-cnx))
                                (client-addr (cdr client-cnx))
                                (client-name (hostent:name (gethostbyaddr (sockaddr:addr client-addr)))))
                           (set-current-input-port client-fd)
                           (set-current-output-port client-fd)
                           ; Now spawn a thread for serving client-fd
                           (call-with-new-thread serve-client (lambda (key . args) (close client-fd)))))))
    (setsockopt sock-fd SOL_SOCKET SO_REUSEADDR 1)
    (bind sock-fd AF_INET ip-addr port)
    (listen sock-fd 5)
    (while #t
           (let ((client-cnx (accept sock-fd)))
             (serve-socket client-cnx)))))
                  
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

; Display the memory consumption due to the redimentionable arrays
(define-public (array-mem-stats)
  (let* ((a2size (map (lambda (h)
                        (let* ((stats (array-stats h))
                               (nb-elmts (cdr (assoc 'nb-entries stats)))
                               (elmt-size (cdr (assoc 'entry-size stats)))
                               (size (* nb-elmts elmt-size)))
                          (cons h size)))
                      (array-names)))
         (stat-one (lambda (h) (cons h (cdr (assoc h a2size)))))
         (sum-size (lambda (x s)
                     (let ((h (car x))
                           (a (cdr x)))
                       (+ a s))))
         (tot-size (fold sum-size 0 a2size)))
    (append!
      (map stat-one (array-names))
      (list (cons "total" tot-size)))))

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
                            (let* ((flt         (format #f
                                                        "(ip[11] & 0x~x = ~d) or (vlan and ip[11] & 0x~x = ~d)"
                                                        mask i mask i))
                                   (this-filter (if (not (eqv? capfilter ""))
                                                    (format #f "(~a) and (~a)" capfilter flt)
                                                    flt)))
                              (next-filter (cons this-filter prevs) (1+ i)))))))
    (next-filter (list "not ip and not (vlan and ip)") 0)))

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

; (list-ifaces) will only report the currently mounted network devices.
; So we merely up all devices here. This works because we are the allmighty root.
; First we start by a function that can execute a function per file :
(define-public (for-each-file-in path fun)
  (let ((dir (opendir path)))
    (do ((entry (readdir dir) (readdir dir)))
      ((eof-object? entry))
      (if (not (string-match "^\\.\\.?$" entry))
          (fun entry)))
    (closedir dir)))

(define-public (up-all-ifaces)
  (let* ((up-iface    (lambda (file)
                        (let ((cmd (simple-format #f "/sbin/ifconfig ~a up" file)))
                          (system cmd)))))
    (for-each-file-in "/sys/class/net" up-iface)))

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
                       ;(simple-format #t "Collision avg of ~A is ~A. Setting hash size to ~A\n" proto (exact->inexact coll-avg) new-h-size)
                       (set-mux-hash-size proto new-h-size)
                       (set-max-children proto (* new-h-size coll-avg-max 10)))))
      (if (< coll-avg coll-avg-min) ; then make future hashes smaller
          (if (> h-size h-size-min)
              (resize coll-avg (max h-size-min (round (/ h-size 2))))))
      (if (> coll-avg coll-avg-max) ; then make future hashes bigger
          (if (< h-size h-size-max)
              (resize coll-avg (min h-size-max (* h-size 2))))))))

; Functions to automatically calibrate the deduplication parameters

(define (dichoto f is-good precision last-good last-bad)
  (if (< (abs (- last-good last-bad)) precision)
      last-good
      (let ((middle (/ (+ last-good last-bad) 2)))
        (if (is-good (f middle))
            (dichoto f is-good precision middle last-bad)
            (dichoto f is-good precision last-good middle)))))

; A function to loop over all dup-detection-delays and report number of detected dups

(define-public (best-dedup-delay run-t)
  (let* ((get-dup-ratio     (lambda (how-long dedup-delay)
                              (format #t "Measuring dup ratio for ~8,' dus: " dedup-delay)
                              (set-dup-detection-delay dedup-delay)
                              (reset-deduplication-stats)
                              (sleep how-long)
                              (let* ((stats  (deduplication-stats))
                                     (dups   (assq-ref stats 'dup-found))
                                     (nodups (assq-ref stats 'nodup-found))
                                     (eols   (assq-ref stats 'end-of-list-found))
                                     (sum    (+ dups nodups eols))
                                     (ratio  (if (> sum 0) (/ (* 100 dups) sum) 0)))
                                (format #t "~3,2f%\n" (exact->inexact ratio))
                                ratio)))
         (max-delay         100000)
         (min-delay         1)
         (actual-dups       (get-dup-ratio run-t max-delay))
         (min-detected-dups (* 90/100 actual-dups))
         (is-acceptable     (lambda (ratio) (> ratio min-detected-dups)))
         (best              (dichoto (lambda (d) (get-dup-ratio run-t (round d)))
                                     is-acceptable 500 max-delay min-delay)))
    (round best)))

; And another one to discover the required digests queue length for no more than eol-ratios
; (note: an eol (end-of-list) occurs when the digest queue is too short to find out if a packet
; is a dup)

(define-public (best-nb-digests max-eol-ratio run-t)
  (let* ((get-eol-ratio  (lambda (how-long nbd)
                           (format #t "Measuring eol ratio for ~6d digests: " nbd)
                           (set-nb-digests nbd)
                           (reset-deduplication-stats)
                           (sleep how-long)
                           (let* ((stats  (deduplication-stats))
                                  (dups   (assq-ref stats 'dup-found))
                                  (nodups (assq-ref stats 'nodup-found))
                                  (eols   (assq-ref stats 'end-of-list-found))
                                  (sum    (+ dups nodups eols))
                                  (ratio  (if (> sum 0) (/ (* 100 eols) sum) 0)))
                             (format #t "~3,2f%\n" (exact->inexact ratio))
                             ratio)))
         (max-nb-digests 5000) ; should be enought for any delay! (ie packet rate should be under max-nb-digests*NB_QUEUES/dedup-delay)
         (min-nb-digests 1)
         (is-acceptable  (lambda (ratio) (< ratio max-eol-ratio)))
         (best           (dichoto (lambda (nbd) (get-eol-ratio run-t (round nbd)))
                                  is-acceptable 10 max-nb-digests min-nb-digests)))
    (round best)))

; And then, a function to calibrate deduplication automatically

(define-public (dedup-calibration run-t)
  (set-nb-digests 5000) ; see remark above concerning max-nb-digests
  (let ((best-delay (best-dedup-delay run-t)))
    (format #t "Best dedup delay: ~dus\n" best-delay)
    (set-dup-detection-delay best-delay))
  (let ((best-nbd (best-nb-digests 5 run-t)))  ; arround 5% of list limit hits is acceptable
    (format #t "Best nb-digests: ~d\n" best-nbd)
    (set-nb-digests best-nbd)))

(define-public (auto-calibration)
  (make-thread (lambda ()
                 (set-thread-name "J-autocalibration")
                 (display "Starting autocalibration of deduplication process...\n")
                 (sleep 30) ; wait for all interfaces to show up
                 (dedup-calibration 30) ; each sample period last for 30 seconds
                 (reset-deduplication-stats))))

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
                      (limiter "IPv4")
                      (limiter "IPv6")
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
                        (simple-format #t "Current TCP:~a UDP:~a total:~a / Max TCP:~a UDP:~a total:~a\n"
                                       cur-tcp cur-udp (+ cur-tcp cur-udp)
                                       max-tcp max-udp (+ max-tcp max-udp))
                        (sleep period)
                        (loop)))))))
    (make-thread thread period)))

; Some tools mainly usefull for tests

(if (defined? 'use-syntax) ; Guile 2 does not need nor provide this
  (use-syntax (ice-9 syncase)))
(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (begin
                               (simple-format #t "Assertion-failed: ~a\n" 'x)
                               (raise SIGABRT))))))
(export-syntax assert)

(define-public (repeat n f)
  (if (> n 0)
      (begin
        (f)
        (repeat (- n 1) f))))

