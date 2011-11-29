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

;; A disptach function takes a broken down path and an alist of HTTP parameters
;; It should return a response or #f if the request was not answered yet (so that we can chain
;; dispatchers and ultimately return a 404).

(define (register)
  (register-crudable (make-crudable "iface" iface-names iface-stats #f
                                    (lambda (name)
                                      (slog log-debug "open iface ~s" name)
                                      (open-iface name))
                                    (lambda (name)
                                      (slog log-debug "close iface ~s" name)
                                      (close-iface name))))
  (register-crudable (make-crudable "protocol" proto-names proto-stats #f #f #f))
  (register-crudable (make-crudable "muxer" mux-names mux-stats #f #f #f))
  (register-crudable (make-crudable "array" array-names array-stats #f #f #f))
  (register-crudable (make-crudable "mallocer" mallocer-names mallocer-stats #f #f #f))
  (register-crudable (make-crudable "hash" hash-names hash-stats #f #f #f))
  (register-crudable (make-crudable "waitlist" wait-list-names wait-list-stats #f #f #f))
  (register-crudable (make-crudable "config" parameter-names
                                    (lambda (n) `((value . ,(get-parameter-value n))))
                                    (lambda (n f v)
                                      (if (not (string=? f "value")) (throw 'bad-field))
                                      (let ((v (with-input-from-string v read)))
                                        (slog log-debug "Received new value ~s for field ~s of crudable ~s" v f n)
                                        (if (equal? v (get-parameter-value n))
                                            (slog log-debug "Skipping parameter ~a already to ~s" n v)
                                            (set-parameter-value n v))))
                                    #f #f)))

(export register)

