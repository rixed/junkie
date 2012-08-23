; vim:syntax=scheme filetype=scheme expandtab
;;; This module defines some web pages to handle captures online

(define-module (junkie writer))

(use-modules (junkie defs)
             (junkie runtime)
             (junkie www crud)
             (junkie www server))

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

(define (capture-new filename rotation regexp netmatch max-pkts max-size max-secs caplen)
  (slog log-debug "New capture for ~s" filename)
  (let* ((param->opt-int (lambda (str)
                           (if (string=? str "")
                               #f
                               (string->number str))))
         (param->opt-string (lambda (str)
                              (if (string=? str "")
                                  #f
                                  str)))
         (cap (make-capture-conf filename 'pcap
                                 (param->opt-string regexp)
                                 (param->opt-string netmatch)
                                 (param->opt-int max-pkts)
                                 (param->opt-int max-size)
                                 (param->opt-int max-secs)
                                 (param->opt-int caplen)
                                 (param->opt-int rotation))))
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

(define (download name)
  (slog log-debug "Download capture for ~s" name)
  (let* ((cap      (assoc-ref captures name)) ; both to check that we do not atempt to download an arbitrary file and got the rotation
         (stats    (capture-stats cap))
         (rotation (assq-ref stats 'rotation)))
    (if (number? rotation)
        (throw 'todo)
        (respond-file name))))

;; Register our crudable

; TODO: additional actions for download, pause/resume, ... del should not be a special action, but an alist of label->action should be allowed.
(define (register)
  (load-plugin "writer")
  (register-crudable (make-crudable "capture" capture-names capture-fields #f capture-new
                                    `(("Del" . ,capture-del)
                                      ("Pause|Resume" . ,pause-resume)
                                      ("Get" . ,download)))))

(export register)

