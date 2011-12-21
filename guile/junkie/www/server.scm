; vim:syntax=scheme filetype=scheme expandtab
;;; This module runs a small http server.
;;; Most of it comes straight from Guile's manual.
;;; This module should be external.

(define-module (junkie www server))

(use-modules (junkie runtime) ; for set-thread-name and set-quit-when-done
             (junkie defs) ; for slog
             (web server)
             (web request)
             (web response)
             (web uri)
             (sxml simple)
             (ice-9 regex)
             (ice-9 threads)
             (ice-9 match)
             (rnrs bytevectors)
             (rnrs io ports)
             (junkie instvars))

;;
;; Tools
;;

(define (print-headers request)
  `(table
     (tr (th "header") (th "value"))
     ,@(map (lambda (pair)
              `(tr (td (tt ,(with-output-to-string
                              (lambda () (display (car pair))))))
                   (td (tt ,(with-output-to-string
                              (lambda ()
                                (write (cdr pair))))))))
            (request-headers request))))

(define (print-params params)
  `(table
     (tr (th "name") (th "value"))
     ,@(map (lambda (pair)
              `(tr (td ,(car pair)) (td ,(cdr pair))))
            params)))

(define (uri-path-components uri)
  (split-and-decode-uri-path (uri-path uri)))

; returns an alist of (symbol . string-value)
; additionally, use the var name to choose a coercion?
(define (uri-query-components str)
  (let* ((pairs (string-split str #\&)))
    (map (lambda (pair)
           (let ((eq (string-index pair #\=)))
             (if eq
                 (cons (string->symbol (uri-decode (substring pair 0 eq)))
                       (uri-decode (substring pair (1+ eq))))
                 (cons (string->symbol (uri-decode pair)) 'unset))))
         pairs)))

(define (templatize title body)
  `(html (head (title ,title)
               (link (@ (type . "text/css") (href . "/junkie.css") (rel . "stylesheet")) ""))
         (body
           (div (@ (id . title))
                (p "Junkie the Network Sniffer"))
           ,@body
           (div (@ (id . footer))
                (p ,junkie-version)))))
; TODO: if debug is on, add the dump of headers+params?

(define* (respond #:optional body #:key
                  (status 200)
                  (title "Hello hello!")
                  (doctype "<!DOCTYPE html>\n")
                  (content-type-params '((charset . "utf-8")))
                  (content-type 'text/html)
                  (extra-headers '())
                  (sxml (and body (templatize title body))))
         (list (build-response
                 #:code status
                 #:headers `((content-type
                               . (,content-type ,@content-type-params))
                             ,@extra-headers))
               (lambda (port)
                 (if sxml
                     (begin
                       (if doctype (display doctype port))
                       (sxml->xml sxml port))))))

(export respond)

(define* (respond-raw bv #:optional body #:key
                      (status 200)
                      (content-type-params '((charset . "utf-8")))
                      (content-type 'text/html)
                      (extra-headers '()))
         (slog log-debug "respond-raw ~a bytes" (bytevector-length bv))
         (list (build-response
                 #:code status
                 #:headers `((content-type
                               . (,content-type ,@content-type-params))
                             ,@extra-headers))
               bv
               #;(lambda (port)
                 (set-port-encoding! port "ISO-8859-1")
                 (slog log-debug "port is now in ~s mode" (port-transcoder port))
                 (put-bytevector port bv))))

(export respond-raw)

;;
;; Pages
;;

(define (no-such-page path params)
  (slog log-debug "404 for path = ~s" path)
  (respond
    `((h1 "Is this what you were looking for?")
      ,(print-params params))
    #:status 404))

(define (error-page str)
  `((h1 "Error")
    (p ,str)))

(export error-page)

(define (content-type-of-filename fname)
  (let ((ext (string->symbol (car (reverse (string-split fname #\.))))))
    (slog log-debug "What's the content-type of a file which extension is ~s?" ext)
    (case ext
      ((ico) 'image/x-icon)
      ((css) 'text/css)
      (else 'text/plain))))

(define (static-dispatch path params)
  (match path
         ((path)
          (catch #t
                 (lambda ()
                   (let* ((full-path  (string-append wwwdir "/" path))
                          (input-port (open-file-input-port full-path)))
                     (respond-raw (get-bytevector-all input-port)
                                  #:content-type (content-type-of-filename path) #:content-type-params '())))
                 (lambda (key . args)
                   (slog log-err "Cannot serve ~s: ~s ~s" path key args)
                   #f)))
          (_ #f)))

(export static-dispatch)

;;
;; Server
;;

(define (run dispatch . rest)
  (let ((list->values (lambda (l) (apply values l))))
    (run-server (lambda (request body)
                  (let* ((uri     (request-uri request))
                         (method  (request-method request))
                         (path    (uri-path-components uri))
                         (body    (if body (utf8->string body) #f))
                         (ctype   (request-content-type request))
                         (query   (uri-query uri))
                         (gparams (if query (uri-query-components query) '()))
                         (pparams (if (and (eq? method 'POST)
                                           (eq? (car ctype) 'application/x-www-form-urlencoded)
                                           body)
                                      (uri-query-components
                                        (regexp-substitute/global #f "\\+" body 'pre " " 'post))
                                      '()))
                         (params  (append gparams pparams)))
                    (slog log-debug "method = ~s, path = ~s, body = ~s, params = ~s" method path body params)
                    (list->values (or (dispatch path params)
                                      (no-such-page path params)))))
                'http rest)))

(export run)

(define (start-dispatch dispatch . rest)
  (make-thread (lambda ()
                 (set-thread-name "J-www-server")
                 (apply run `(,dispatch ,@rest)))))

(export start-dispatch)

(define (chain-dispatchers l)
  (match l
         (()      (lambda (path params) #f))
         ((h . t) (lambda (path params)
                    (or (h path params)
                        ((chain-dispatchers t) path params))))))

(export chain-dispatchers)

(define (start port)
  ((@ (junkie www monitor) register))
  (set-quit-when-done #f)
  (let ((dispatch (chain-dispatchers
                    (list
                      static-dispatch
                      (@ (junkie www crud) crud-dispatch)))))
    (start-dispatch dispatch #:port port)))

(export start)

