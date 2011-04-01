; vim:syntax=scheme expandtab
;;; This file implements Junkie's SNMP subagent, with the help of guile-agentx

(use-modules ((agentx net)     :renamer (symbol-prefix-proc 'net:))
             ((agentx session) :renamer (symbol-prefix-proc 'sess:))
             (guile-user))

(define securactive-mib '(1 3 6 1 4 1 36773))
(define junkie-mib  (append securactive-mib '(1)))

(define (getoid-version)
  (cons 'octet-string junkie-version))

(define (getoid-dup-detection-delay)
  (cons 'integer (get-dup-detection-delay)))

(define (oid-less oid1 oid2) ; returns true if oid1 < oid2
  (< ((@ (agentx tools) oid-compare) (car oid1) (car oid2)) 0))

(define cached-stats (cached 15))

(define (junkie-getters)
  (letrec ((parser-getters
             (lambda (prevs idx names)
               (if (null? names) prevs  ; no more parsers on the table
                 (let* ((name          (car names))
                        (stats         (cached-stats proto-stats name))
                        (parser-getter (list (cons (append junkie-mib (list 3 1 1 1 idx)) (lambda () (cons 'octet-string name)))
                                             (cons (append junkie-mib (list 3 1 1 2 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-frames))))
                                             (cons (append junkie-mib (list 3 1 1 3 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-bytes))))
                                             (cons (append junkie-mib (list 3 1 1 4 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'nb-parsers)))))))
                   (parser-getters
                     (append! prevs parser-getter)
                     (1+ idx)
                     (cdr names))))))
           (muxer-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name          (car names))
                        (stats         (cached-stats mux-stats name))
                        (mux-getter    (list (cons (append junkie-mib (list 3 2 1 1 idx)) (lambda () (cons 'octet-string name)))
                                             (cons (append junkie-mib (list 3 2 1 2 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'hash-size))))
                                             (cons (append junkie-mib (list 3 2 1 3 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'nb-max-children))))
                                             (cons (append junkie-mib (list 3 2 1 4 idx)) (lambda () (cons 'counter32 (assq-ref stats 'nb-infanticide))))
                                             (cons (append junkie-mib (list 3 2 1 5 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-collisions))))
                                             (cons (append junkie-mib (list 3 2 1 6 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-lookups)))))))
                   (muxer-getters
                     (append! prevs mux-getter)
                     (1+ idx)
                     (cdr names))))))
           (source-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name          (car names))
                        (stats         (cached-stats iface-stats name))
                        (source-getter (list (cons (append junkie-mib (list 2 1 1 1 idx)) (lambda () (cons 'octet-string name)))
                                             (cons (append junkie-mib (list 2 1 1 2 idx)) (lambda () (cons 'counter64 (assq-ref stats 'tot-received))))
                                             (cons (append junkie-mib (list 2 1 1 3 idx)) (lambda () (cons 'counter64 (assq-ref stats 'tot-dropped))))
                                             (cons (append junkie-mib (list 2 1 1 4 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-packets))))
                                             (cons (append junkie-mib (list 2 1 1 5 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-duplicates))))
                                             (cons (append junkie-mib (list 2 1 1 6 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-cap-bytes))))
                                             (cons (append junkie-mib (list 2 1 1 7 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-wire-bytes)))))))
                   (source-getters
                     (append! prevs source-getter)
                     (1+ idx)
                     (cdr names)))))))
    (let* ((scalars      (list (cons (append junkie-mib '(1 1 0))   getoid-version)
                               (cons (append junkie-mib '(2 2 0))   getoid-dup-detection-delay)))
           (getters-list (parser-getters scalars      1 (proto-names)))
           (muxers-list  (muxer-getters  getters-list 1 (mux-names)))
           (sources-list (source-getters muxers-list  1 (iface-names))))
      (sort! sources-list oid-less))))


(define (start-junkie-subagent)
  (set-thread-name "junkie-snmp-subagent")
  (while #t
         (catch #t
                (lambda ()
                  (let ((junkie-subagent (net:make-subagent "junkie" junkie-mib junkie-getters)))
                    (net:loop junkie-subagent)))
                (lambda (key . args)
                  (sleep 10)))))

