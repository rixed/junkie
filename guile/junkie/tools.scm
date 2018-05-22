; vim:syntax=scheme filetype=scheme expandtab
;;; This module does not depend on junkie runtime

(define-module (junkie tools))

(use-modules (srfi srfi-1)
             (ice-9 regex)
             (ice-9 format)
             (ice-9 match)
             (system repl server))

; A pretty printer
(define pp (@ (ice-9 pretty-print) pretty-print))
(export pp)

; Equivalent of mkdir -p
(define (ensure-directories-exist path)
  (letrec ((rec (lambda (path)
                 (let ((parent (dirname path)))
                   (if (and (string<> parent "/") (string<> parent "."))
                       (rec parent)))
                 (catch 'system-error
                        (lambda ()
                          (mkdir path))
                        (lambda stuff
                          (let ((errno (system-error-errno stuff)))
                            ;; Ignore error if the directory already exists.
                            (if (not (= errno EEXIST))
                             (throw stuff))))))))
    (rec path))
  ;; Now check the we have actually a directory.
  (if (not (eq? (stat:type (stat path)) 'directory))
      (throw 'file-exists path)))

(export ensure-directories-exist)

; Run a server on given port
(define (start-server ip-addr port)
  (let* ((sock-fd (socket PF_INET SOCK_STREAM 0)))
    (setsockopt sock-fd SOL_SOCKET SO_REUSEADDR 1)
    (bind sock-fd AF_INET ip-addr port)
    (spawn-server sock-fd)))

(export start-server)

; A function that can execute a function per file :
(define (for-each-entry-in path fun)
  (let ((dir (opendir path)))
    (do ((entry (readdir dir) (readdir dir)))
      ((eof-object? entry))
      (fun (string-append path "/" entry)))
    (closedir dir)))

(export for-each-entry-in)

(define (for-each-file-in path fun)
  (for-each-entry-in path (lambda (path)
                            (if (not (eqv? 'directory (stat:type (stat path))))
                                (fun path)))))

(export for-each-file-in)

; Convert (quickly, aka no format) an eth address as a number into usual string representation
(define (eth->string e)
  (let ((digits "0123456789abcdef")
        (str    (string-copy "00:00:00:00:00:00")))
    (do ((e e (ash e -4)) ; move one digit at a time
         (new-digit #t (not new-digit)) ; are we patching the first digit of a 2 byte value?
         (p 16 (- p (if new-digit 1 2)))) ; offset in str
      ((zero? e))
      (string-set! str p (string-ref digits (logand #b1111 e))))
    str))

(export eth->string)

; And the other way around (no need to be fast here)
(define (string->eth s)
  (fold (lambda (d e)
          ; add this digit to e
          (logior (ash e 8) d))
        0
        (map (lambda (b)
               (string->number b 16))
             (string-split s #\:))))

(export string->eth)

; for these function to work, ip should be under the form (FAMILY, number)
(define (ip->string i)
  (inet-ntop (car i) (cdr i)))

(export ip->string)

(define (string->ip s)
  (or (false-if-exception (cons AF_INET6 (inet-pton AF_INET6 s)))
      (cons AF_INET (inet-pton AF_INET s))))

(export string->ip)

(define (timestamp->string t)
  (string-append (number->string (car t)) "s " (number->string (cdr t)) "us"))

(export timestamp->string)

(define (timestamp->float t)
  (+ (car t) (/ (cdr t) 1000000.)))

(export timestamp->float)

(define (ber-time->string t)
  (match t
         ((year month day hour min sec)
          (format #f "~4,,,'0@s-~2,,,'0@s-~2,,,'0@s ~2,,,'0@s:~2,,,'0@s:~2,,,'0@s"
                  year month day hour min sec))))

(export ber-time->string)

; Some tools mainly useful for tests

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

