; vim:syntax=scheme expandtab
;;; This modules contains general purpose functions.

;; A global variable to avoid loading this several times

(define defs-loaded #t)

;; Some definitions the user likely want to use

(define log-emerg   0) (define log-alert  1) (define log-crit 2) (define log-err   3)
(define log-warning 4) (define log-notice 5) (define log-info 6) (define log-debug 7)

; This might be already defined somewhere ?
(define (neq? x y) (not (eq? x y)))

; This one might be usefull to display all help available
(define (help)
  (for-each (lambda (l)
              (display "------------------\n")
              (display l)
              (newline))
            (?)))

; A pretty printer
(define pp (@ (ice-9 pretty-print) pretty-print))

; Run a server on given port
(define (start-server ip-addr port serve-client)
  (let* ((sock-fd (socket PF_INET SOCK_STREAM 0))
         (serve-socket (lambda (fd)
                         (let* ((client-cnx  (accept fd))
                                (client-fd   (car client-cnx))
                                (client-addr (cdr client-cnx))
                                (client-name (hostent:name (gethostbyaddr (sockaddr:addr client-addr)))))
                           (set-current-input-port client-fd)
                           (set-current-output-port client-fd)
                           ; Now spawn a thread for serving client-fd
                           (call-with-new-thread serve-client (lambda (key . args) (close client-fd)))))))
    (sigaction SIGPIPE SIG_IGN)
    (setsockopt sock-fd SOL_SOCKET SO_REUSEADDR 1)
    (bind sock-fd AF_INET ip-addr port)
    (listen sock-fd 5)
    (while #t
           (let ((readables (car (select (list sock-fd) '() '()))))
             (map (lambda (fd)
                    (if (eq? fd sock-fd) (serve-socket fd)))
                  readables)))))

; Start a server that executes anything (from localhost only)
(define (start-repl-server port . rest)
  (letrec ((consume-white-spaces (lambda (port)
                                   (let ((c (peek-char port)))
                                     (cond ((eqv? c #\eot) (begin
                                                             (display "Bye!\r\n")
                                                             (throw 'quit)))
                                           ((char-whitespace? c) (begin
                                                                   (read-char)
                                                                   (consume-white-spaces port))))))))
    (let* ((prompt (if (null? rest) (lambda () "junkie> ") (car rest)))
           (repl   (lambda ()
                     (let ((reader  (lambda (port)
                                      (display (prompt))
                                      (consume-white-spaces port)
                                      (read port)))
                           (evaler  (lambda (expr)
                                      (catch #t
                                             (lambda () (eval expr (interaction-environment)))
                                             (lambda (key . args)
                                               (if (eq? key 'quit) (apply throw 'quit args))
                                               (simple-format #t "You slipped : ~A\r\n" key)))))
                           (printer pp))
                       (set-thread-name "J-guile-client")
                       ; Use repl defined in ice-9 boot
                       (repl reader evaler printer)))))
      (set-thread-name "J-guile-server")
      (start-server (inet-aton "127.0.0.1") port repl))))

; An equivalent of the old fashionned display command line option
(define (display-parameters)
  (let ((display-one (lambda (p)
                       (simple-format #t "~a: ~a\n" p (get-parameter-value p)))))
    (for-each display-one (parameter-names))))

; Display the memory consumption due to Guile
(use-modules (srfi srfi-1))
(define (guile-mem-stats)
  (let* ((maps (cdr (assoc 'cell-heap-segments (gc-stats))))
         (sum-size (lambda (x s)
                     (let ((a (car x))
                           (b (cdr x)))
                       (+ s (- b a))))))
    (fold sum-size 0 maps)))

; Display the memory consumption due to the redimentionable arrays
(define (array-mem-stats)
  (let* ((a2size (map (lambda (h)
                        (let* ((stats (array-stats h))
                               (nb-elmts (cdr (assoc 'nb-entries stats)))
                               (elmt-size (cdr (assoc 'entry-size stats)))
                               (size (* nb-elmts elmt-size)))
                          (cons h size)))
                      (array-names)))
         (stat-one (lambda (h) (const h (cdr (assoc h a2size)))))
         (sum-size (lambda (x s)
                     (let ((h (car x))
                           (a (cdr x)))
                       (+ a s))))
         (tot-size (fold sum-size 0 a2size)))
    (append!
      (map stat-one (array-names))
      (list (cons "total" tot-size)))))

; Display malloc statistics
(define (mallocer-mem-stats)
  (let* ((size     (lambda (name) (cdr (assoc 'tot-size (mallocer-stats name)))))
         (tot-size (apply + (map size (mallocer-names))))
         (stat-one (lambda (name) (cons name (size name)))))
    (append!
      (map stat-one (mallocer-names))
      (list (cons "total" tot-size)))))

; Macro to ignore exceptions
(use-syntax (ice-9 syncase))
(define-syntax without-exception
  (syntax-rules ()
                ((without-exception key thunk ...)
                 (catch key (lambda () thunk ...) (lambda (a . r) #f)))))

; get the percentage of duplicate frames over the total number (check out if the
; port mirroring is correctly set)
(define (duplicate-percentage)
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
(define (dropped-percentage)
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
(use-modules (ice-9 regex))
(define (ifaces-matching pattern)
  (filter
    (lambda (ifname) (string-match pattern ifname))
    (list-ifaces)))

(define (set-ifaces pattern)
  (let ((bufsize (if (defined? 'bufsize) bufsize 0))
        (caplen  (if (defined? 'caplen) caplen 0)))
    (for-each
      (lambda (ifname) (open-iface ifname #t "" caplen bufsize))
      (ifaces-matching pattern))))

(define (get-ifaces) (iface-names))

; build a list of pcap filter suitable to split traffic through 2^n+1 processes
; n must be >= 1
(use-modules (ice-9 format))
(define (pcap-filters-for-split n)
  (letrec ((mask        (- (ash 1 n) 1))
           (next-filter (lambda (prevs i)
                          (if (> i mask)
                            prevs
                            (let* ((this-filter (format #f "(ip[11] & 0x~x = ~d) or (vlan and ip[11] & 0x~x = ~d)" mask i mask i)))
                              (next-filter (cons this-filter prevs) (1+ i)))))))
    (next-filter (list "not ip and not (vlan and ip)") 0)))

; Equivalent of set-ifaces for multiple CPUs
(define (open-iface-multiple n . args)
  (let* ((ifname      (car args))
         (promisc     (catch 'wrong-type-arg (lambda () (cadr   args)) (lambda (k . a) #t)))
         (caplen      (catch 'wrong-type-arg (lambda () (caddr  args)) (lambda (k . a) 0)))
         (bufsize     (catch 'wrong-type-arg (lambda () (cadddr args)) (lambda (k . a) 0)))
         (filters     (pcap-filters-for-split n))
         (open-single (lambda (flt) (open-iface ifname promisc flt caplen bufsize))))
    (for-each open-single filters)))

(define (set-ifaces-multiple n pattern)
  (let ((bufsize (if (defined? 'bufsize) bufsize 0))
        (caplen  (if (defined? 'caplen) caplen 0)))
    (for-each
      (lambda (ifname) (open-iface-multiple n ifname #t caplen bufsize))
      (ifaces-matching pattern))))

; (list-ifaces) will only report the currently mounted network devices.
; So we merely up all devices here. This works because we are the allmighty root.
; First we start by a function that can execute a function per file :
(define (for-each-file-in path fun)
  (let ((dir (opendir path)))
    (do ((entry (readdir dir) (readdir dir)))
      ((eof-object? entry))
      (if (not (string-match "^\\.\\.?$" entry))
          (fun entry)))
    (closedir dir)))

(define (up-all-ifaces)
  (let* ((up-iface    (lambda (file)
                        (let ((cmd (simple-format #f "/sbin/ifconfig ~a up" file)))
                          (system cmd)))))
    (for-each-file-in "/sys/class/net" up-iface)))

; A simple function to check wether the agentx module is available or not
(define have-snmp (false-if-exception (resolve-interface '(agentx tools))))

; Helper function handy for answering SNMP queries : cache a result of some expensive function for some time
(define (cached timeout)
  (let* ((hash      (make-hash-table 50)) ; hash from (func . args) into (timestamp . value)
         (ts-of     car)
         (value-of  cdr))
    (lambda func-args
      (let* ((hash-v (hash-ref hash func-args))
             (now    (current-time)))
        (if (and hash-v (<= now (+ timeout (ts-of hash-v))))
            (value-of hash-v)
            (let ((v (primitive-eval func-args)))
              (hash-set! hash func-args (cons now v))
              v))))))

; Helper functions that comes handy when configuring muxer hashes
(define (get-mux-hash-size proto)
  (let ((stats (mux-stats proto)))
    (assq-ref stats 'hash-size)))

(define (nb-tot-parsers)
  (let* ((stats      (map proto-stats (proto-names)))
         (nb-parsers (map (lambda (s) (assq-ref s 'nb-parsers)) stats)))
    (reduce + 0 nb-parsers)))

(define (make-mux-hash-controller coll-avg-min coll-avg-max h-size-min h-size-max)
  (lambda (proto)
    (let* ((stats    (mux-stats proto))
           (h-size   (assq-ref stats 'hash-size))
           (colls    (assq-ref stats 'nb-collisions))
           (lookups  (assq-ref stats 'nb-lookups))
           (coll-avg (if (> lookups 0) (/ colls lookups) -1))
           (resize   (lambda (coll-avg new-h-size)
                       (simple-format #t "Collision avg of ~A is ~A. Setting hash size to ~A\n" proto (exact->inexact coll-avg) new-h-size)
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

(define (best-dedup-delay run-t)
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

(define (best-nb-digests max-eol-ratio run-t)
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
                                  (ratio  (/ (* 100 eols) sum)))
                             (format #t "~3,2f%\n" (exact->inexact ratio))
                             ratio)))
         (max-nb-digests 5000) ; should be enought for any delay! (ie packet rate should be under max-nb-digests*NB_QUEUES/dedup-delay)
         (min-nb-digests 1)
         (is-acceptable  (lambda (ratio) (< ratio max-eol-ratio)))
         (best           (dichoto (lambda (nbd) (get-eol-ratio run-t (round nbd)))
                                  is-acceptable 10 max-nb-digests min-nb-digests)))
    (round best)))

; And then, a function to calibrate deduplication automatically

(define (dedup-calibration run-t)
  (set-nb-digests 5000) ; see remark above concerning max-nb-digests
  (let ((best-delay (best-dedup-delay run-t)))
    (format #t "Best dedup delay: ~dus\n" best-delay)
    (set-dup-detection-delay best-delay))
  (let ((best-nbd (best-nb-digests 5 run-t)))  ; arround 5% of list limit hits is acceptable
    (format #t "Best nb-digests: ~d\n" best-nbd)
    (set-nb-digests best-nbd)))

