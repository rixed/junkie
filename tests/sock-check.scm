#!../src/junkie -c
; vim:syntax=scheme expandtab filetype=scheme
; coding: iso-8859-1
!#

(use-modules (ice-9 match))

(display "Testing some sock related functions\n")

(let ((logfile "sock-check.log"))
  (false-if-exception (delete-file logfile))
  (set-log-file logfile)
  (set-log-level log-debug "sock")
  (set-log-level log-debug "guile"))

(slog log-debug "Check UDP socks")
; We first try to setup a server connection (guess until we found an unused port)
(define (random-between mi ma) ; inclusive
  (+ mi (random (1+ (- ma mi)))))
(define (random-port)
  (random-between 1024 65535))

(slog log-debug "Check some erroneous make-sock")
(catch 'invalid-argument
       (lambda () (make-sock 'quantum-teleportation 123))
       (lambda (k . args)
         (slog log-debug "Catched exception with args: ~s" args)))

(define (test-udp-sock-to host port)
  (false-if-exception
    (let ((sock (make-sock 'udp host port)))
      (sock-send sock "hello"))))

(slog log-debug "test UDP sock")
(call-with-values
  (lambda ()
    (let loop ((nb-try 0))
      (if (>= nb-try 10)
          (throw 'cannot-create-udp-server)
          (let ((port (random-port)))
            (catch 'cannot-create-sock
                   (lambda ()
                     (values port (make-sock 'udp port)))
                   (lambda (k . args) (loop (1+ nb-try))))))))
  (lambda (port srv-sock)
    (slog log-debug "UDP server listening on port ~s, socket ~s" port srv-sock)
    ; now try to connect to it
    (assert (test-udp-sock-to "localhost" port)) ; should work
    (assert (test-udp-sock-to "localhost" (number->string port))) ; should work as well
    (assert (test-udp-sock-to "127.0.0.1" port))
    port)) ; and again

(slog log-debug "test UNIX sock")
(let ((file     "./sock-check.sock")
      (srv-sock #f)
      (clt-sock #f)
      (test-msg "glop glop"))
  (set! srv-sock (make-sock 'unix 'server file))
  (slog log-debug "UNIX domain server: ~s" srv-sock)
  ; now try to connect to it
  (set! clt-sock (make-sock 'unix 'client file))
  (slog log-debug "UNIX domain client: ~s" clt-sock)
  (assert (sock-send clt-sock test-msg))
  (assert (string=? (sock-recv srv-sock) test-msg))
  ; Now let's test garbage collecting of srv-sock
  (slog log-debug "GCing sock objects")
  (set! srv-sock #f)
  (gc)
  (slog log-debug "Trying to connect again to server...")
  (assert (not (sock-send clt-sock "pas glop"))))

(slog log-debug "test FILE sock")
(define (test-file max-file-size)
  (let ((file     "./sock-check")
        (srv-sock #f)
        (clt-sock #f)
        (test-msg "glop glop"))
    (system (string-append "rm -rf " file))
    (set! srv-sock (make-sock 'file 'server file max-file-size))
    (slog log-debug "File-msg server: ~s" srv-sock)
    ; now try to connect to it
    (set! clt-sock (make-sock 'file 'client file max-file-size))
    (slog log-debug "File-msg client: ~s" clt-sock)
    ; test the connection with enough messages to trigger several file changes
    (let loop ((n 20))
      (assert (sock-send clt-sock test-msg))
      (assert (string=? (sock-recv srv-sock) test-msg))
      (if (> n 0) (loop (- n 1))))))
(test-file 0)  ; all msgs in one big file
(test-file 60) ; a few msgs per file
(test-file 1)  ; one file per message
(gc)

(slog log-debug "test UDP _buffered_ sock")
(define (test-buf mtu)
  (let ((srv-sock    #f)
        (clt-sock    #f)
        (ll-srv-sock #f) ; keep a reference so that the underlying C struct wont be freed (nor socket closed)
        (ll-clt-sock #f)
        (port        (random-port))
        (test-msg    "glop glop pas glop")
        (nb-rcvd     0)
        (nb-sent     0))
    (set! ll-srv-sock (make-sock 'udp port))
    (set! ll-clt-sock (make-sock 'udp "localhost" port))
    (set! srv-sock (make-sock 'buffered mtu ll-srv-sock))
    (slog log-debug "server: ~s" srv-sock)
    ; now try to connect to it
    (set! clt-sock (make-sock 'buffered mtu ll-clt-sock))
    (slog log-debug "client: ~s" clt-sock)
    (let ((thread (make-thread (lambda ()
                                 (set-thread-name "buf reader")
                                 (let loop ()
                                   (let ((msg (sock-recv srv-sock)))
                                     (slog log-debug "received: ~s" msg)
                                     (cond
                                       [(string=? "END" msg)
                                        (slog log-debug "Read END")]
                                       [(string=? test-msg msg)
                                        (slog log-debug "Read 1 message")
                                        (set! nb-rcvd (1+ nb-rcvd))
                                        (loop)]
                                       [else
                                         (assert #f)])))))))
      (let loop ((n 20))
        (assert (sock-send clt-sock test-msg))
        (slog log-debug "Write 1 message")
        (set! nb-sent (1+ nb-sent))
        (if (> n 1) (loop (- n 1))))
      (assert (sock-send clt-sock "END"))
      (slog log-debug "Disconnecting client")
      (set! clt-sock #f) ; flush
      (gc)
      (join-thread thread)
      (slog log-debug "Disconnecting server")
      (set! srv-sock #f)
      (set! ll-srv-sock #f)
      (set! ll-clt-sock #f)
      (gc)
      (assert (= nb-sent nb-rcvd)))))
(test-buf 32) ; small buffer
(test-buf 100) ; a few msgs per PDU
(test-buf 1000) ; all in one PDU

(exit)
