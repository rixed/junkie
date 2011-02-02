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
  (let* ((prompt (if (null? rest) (lambda () "junkie> ") (car rest)))
         (repl (lambda ()
                 (let ((reader  (lambda (port) (display (prompt)) (read port)))
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
    (start-server (inet-aton "127.0.0.1") port repl)))

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
  (let* ((size (lambda (name) (cdr (assoc 'tot-size (mallocer-stats name)))))
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
  (let* ((dups         (get-nb-duplicates))
         (total-frames (+ dups (assoc-ref (proto-stats "Ethernet") 'nb-frames))))
    (if (eq? 0 total-frames)
        0
        (* 100.0 (/ dups total-frames)))))

; get the percentage of dropped packets
(define (dropped-percentage)
  (let* ((tot-drop (fold (lambda (stats prevs)
                           (let ((received  (assq-ref stats 'tot-received))
                                 (dropped   (assq-ref stats 'tot-dropped))
                                 (prev-recv (car prevs))
                                 (prev-drop (cdr prevs)))
                             (cons (+ prev-recv received) (+ prev-drop dropped))))
                         '(0 . 0)
                         (map iface-stats (iface-names))))
         (total    (car tot-drop))
         (dropped  (cdr tot-drop)))
    (exact->inexact (/ (* 100 dropped) total))))

; backward compatible function set-ifaces
(use-modules (ice-9 regex))
(define (ifaces-matching pattern)
  (filter
    (lambda (ifname) (string-match pattern ifname))
    (list-ifaces)))

(define (set-ifaces pattern)
  (for-each
    (lambda (ifname) (open-iface ifname #t "" bufsize))
    (ifaces-matching pattern)))

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
         (promisc     (catch 'wrong-type-arg (lambda () (cadr  args)) (lambda (k . a) #t)))
         (bufsize     (catch 'wrong-type-arg (lambda () (caddr args)) (lambda (k . a) bufsize)))
         (filters     (pcap-filters-for-split n))
         (open-single (lambda (flt) (open-iface ifname promisc flt bufsize))))
    (for-each open-single filters)))

(define (set-ifaces-multiple n pattern)
  (for-each
    (lambda (ifname) (open-iface-multiple n ifname #t bufsize))
    (ifaces-matching pattern)))

; (list-ifaces) will only report the currently mounted network devices.
; So we merely up all devices here. This works because we are the allmighty root.
; First we start by a function that can execute a function per file :
(define (for-each-file-in path fun)
  (let ((dir (opendir path)))
    (do ((entry (readdir dir) (readdir dir)))
      ((eof-object? entry))
      (fun entry))
    (closedir dir)))

(define (up-all-ifaces)
  (let* ((is-iface    (lambda (file)
                        (not (string-match "^\\.\\.?$" file))))
         (up-iface    (lambda (file)
                        (let ((cmd (simple-format #f "/sbin/ifconfig ~a up" file)))
                          (system cmd))))
         (up-if-iface (lambda (file)
                        (if (is-iface file) (up-iface file)))))
    (for-each-file-in "/sys/class/net" up-if-iface)))

; A simple function to check wether the agentx module is available or not
(define have-snmp (false-if-exception (resolve-interface '(agentx tools))))

; Helper function that comes handy when seting max-children
(define (get-mux-hash-size proto)
  (let ((stat (mux-stats proto)))
    (assq-ref stat 'hash-size)))

