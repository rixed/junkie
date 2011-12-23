; vim:syntax=scheme filetype=scheme expandtab
;;; This module defines a www dispatcher for some monitoring pages

(define-module (junkie www monitor))

(use-modules (rnrs lists)
             (rnrs bytevectors)
             (ice-9 match)
             (junkie defs)
             (junkie runtime)
             (junkie www server)
             (junkie www crud))

(define (seq start stop)
  (if (>= start stop)
      '()
      (cons start (seq (1+ start) stop))))

; id should be a hash of the values instead to work also when several users are editing the conf
(define (make-id-of f)
  (lambda ()
    (map number->string (seq 0 (length (f))))))

(define (create-port-using f)
  (lambda (proto port-min port-max)
    (let ((param->int (lambda (str)
                        (if (string=? str "")
                            0
                            (string->number str)))))
      (f proto (param->int port-min) (param->int port-max)))))

(define (del-port-of f del)
  (lambda (id)
    (let ((stats ((stats-from-id f) id)))
      (del (assq-ref stats 'proto)
           (assq-ref stats 'port-min)
           (assq-ref stats 'port-max)))))

(define (stats-from-id f)
  (lambda (id)
    (list-ref (f) (string->number id))))

(define (rev f)
  (lambda ()
    (reverse (f))))

;; A disptach function takes a broken down path and an alist of HTTP parameters
;; It should return a response or #f if the request was not answered yet (so that we can chain
;; dispatchers and ultimately return a 404).

(define (register)
  (register-crudable (make-crudable "iface" iface-names iface-stats #f
                                    (lambda (name)
                                      (slog log-debug "open iface ~s" name)
                                      (open-iface name))
                                    `(("Del" . ,(lambda (name)
                                                  (slog log-debug "close iface ~s" name)
                                                  (close-iface name))))))
  (register-crudable (make-crudable "protocol" proto-names proto-stats #f #f '()))
  (register-crudable (make-crudable "muxer" mux-names mux-stats #f #f '()))
  (register-crudable (make-crudable "array" array-names array-stats #f #f '()))
  (register-crudable (make-crudable "mallocer" mallocer-names mallocer-stats #f #f '()))
  (register-crudable (make-crudable "hash" hash-names hash-stats #f #f '()))
  (register-crudable (make-crudable "waitlist" wait-list-names wait-list-stats #f #f '()))
  (register-crudable (make-crudable "tcp-ports" (make-id-of (rev tcp-ports)) (stats-from-id (rev tcp-ports)) #f
                                    (create-port-using tcp-add-port)
                                    `(("Del" . ,(del-port-of (rev tcp-ports) tcp-del-port)))))
  (register-crudable (make-crudable "udp-ports" (make-id-of (rev udp-ports)) (stats-from-id (rev udp-ports)) #f
                                    (create-port-using udp-add-port)
                                    `(("Del" . ,(del-port-of (rev udp-ports) udp-del-port)))))
  (register-crudable (make-crudable "config" parameter-names
                                    (lambda (n) `((value . ,(get-parameter-value n))))
                                    (lambda (n f v)
                                      (if (not (string=? f "value")) (throw 'bad-field))
                                      (let ((v (with-input-from-string v read)))
                                        (slog log-debug "Received new value ~s for field ~s of crudable ~s" v f n)
                                        (if (equal? v (get-parameter-value n))
                                            (slog log-debug "Skipping parameter ~a already to ~s" n v)
                                            (set-parameter-value n v))))
                                    #f '())))

(export register)

