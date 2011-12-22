; vim:syntax=scheme filetype=scheme expandtab
;;; This module defines some web pages to handle captures online

(define-module (junkie writer capturer))

(use-modules (junkie defs)
             (junkie runtime)
             (junkie www crud))

;; We keep a list of all created capture-conf
(define captures '())
(define (add-capture name cap) ; keep the string used for regex?
  (slog log-debug "Add capture for ~s" name)
  (set! captures (cons (cons name cap) captures)))

;; Operations on captures

(define (capture-names)
  (map car captures))

(define (capture-fields name)
  (let ((cap (assoc-ref captures name)))
    (capture-stats cap)))

(define (capture-new filename rotation regex max-pkts max-size max-secs caplen)
  (slog log-debug "New capture for ~s" filename)
  (let* ((param->int (lambda (str)
                       (if (string=? str "")
                           0
                           (string->number str))))
         (cap (make-capture-conf filename 'pcap
                                 regex
                                 (param->int max-pkts)
                                 (param->int max-size)
                                 (param->int max-secs)
                                 (param->int caplen)
                                 (param->int rotation))))
    (capture-start cap) ; we'd rather start it at this point
    (add-capture filename cap)))

(define (capture-del name)
  (slog log-debug "Del capture for ~s" name)
  (set! captures (filter (lambda (pair)
                           (if (string=? name (car pair))
                               (begin
                                 (capture-stop (cdr pair))
                                 #f)
                               #t))
                         captures)))

(define (pause-resume name)
  (slog log-debug "(Un)Pause capture for ~s" name)
  (let* ((cap   (assoc-ref captures name))
         (stats (capture-stats cap)))
    (if (assq-ref stats 'paused)
        (capture-resume cap)
        (capture-pause cap))))

;; Register our crudable

; TODO: additional actions for download, pause/resume, ... del should not be a special action, but an alist of label->action should be allowed.
(define (register)
  (register-crudable (make-crudable "capture" capture-names capture-fields #f capture-new
                                    `(("Del" . ,capture-del)
                                      ("Pause/Resume" . ,pause-resume)))))

(export register)

