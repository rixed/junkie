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

; UDP
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
    ; now try to connect to it (max file size of 60 bytes
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
(exit)

