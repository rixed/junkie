; vim:syntax=scheme filetype=scheme expandtab
;;; This module does not depend on junkie runtime

(define-module (junkie tools))

(use-modules (srfi srfi-1)
             (ice-9 regex)
             (ice-9 format))

; A pretty printer
(define pp (@ (ice-9 pretty-print) pretty-print))
(export pp)

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

(export start-server)

; (list-ifaces) will only report the currently mounted network devices.
; So we merely up all devices here. This works because we are the allmighty root.
; First we start by a function that can execute a function per file :
(define (for-each-file-in path fun)
  (let ((dir (opendir path)))
    (do ((entry (readdir dir) (readdir dir)))
      ((eof-object? entry))
      (if (not (string-match "^\\.\\.?$" entry))
          (fun (string-append path "/" entry))))
    (closedir dir)))

(export for-each-file-in)

; Some tools mainly usefull for tests

(define-syntax assert
  (syntax-rules ()
                ((assert x)
                 (if (not x) (begin
                               (simple-format #t "Assertion-failed: ~a\n" 'x)
                               (raise SIGABRT))))))
(export-syntax assert)

(define (repeat n f)
  (if (> n 0)
      (begin
        (f)
        (repeat (- n 1) f))))

(export repeat)

