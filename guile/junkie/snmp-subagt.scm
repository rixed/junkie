; vim:syntax=scheme filetype=scheme expandtab
;;; This file implements Junkie's SNMP subagent, with the help of guile-agentx

(define-module (junkie snmp-subagt))

(use-modules (ice-9 threads)
             (rnrs bytevectors)
             ((agentx net)     :renamer (symbol-prefix-proc 'net:))
             ((agentx session) :renamer (symbol-prefix-proc 'sess:))
             (junkie defs)
             (junkie runtime))

(define-public securactive-mib '(1 3 6 1 4 1 36773))
(define mib  (append securactive-mib '(1)))

(define (getoid-version)
  (cons 'octet-string (string->utf8 junkie-version)))

(define (getoid-dup-detection-delay)
  (cons 'integer (get-max-dup-delay)))

(define (getoid-guile-mem-stats)
  (cons 'gauge32 (guile-mem-stats)))

(define-public (oid-less oid1 oid2) ; returns true if oid1 < oid2
  (< ((@ (agentx tools) oid-compare) (car oid1) (car oid2)) 0))

(define cached-stats (cached 15))

(define (getters)
  (letrec ((parser-getters
             (lambda (prevs idx names)
               (if (null? names) prevs  ; no more parsers on the table
                 (let* ((name          (car names))
                        (stats         (cached-stats proto-stats name))
                        (parser-getter (list (cons (append mib (list 3 1 1 1 idx)) (lambda () (cons 'octet-string (string->utf8 name))))
                                             (cons (append mib (list 3 1 1 2 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-frames))))
                                             (cons (append mib (list 3 1 1 3 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-bytes))))
                                             (cons (append mib (list 3 1 1 4 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'nb-parsers)))))))
                   (parser-getters
                     (append! prevs parser-getter)
                     (1+ idx)
                     (cdr names))))))
           (muxer-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name          (car names))
                        (stats         (cached-stats mux-stats name))
                        (mux-getter    (list (cons (append mib (list 3 2 1 1 idx)) (lambda () (cons 'octet-string (string->utf8 name))))
                                             (cons (append mib (list 3 2 1 2 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'hash-size))))
                                             (cons (append mib (list 3 2 1 3 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'nb-max-children))))
                                             (cons (append mib (list 3 2 1 4 idx)) (lambda () (cons 'counter32 (assq-ref stats 'nb-infanticide))))
                                             (cons (append mib (list 3 2 1 5 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-collisions))))
                                             (cons (append mib (list 3 2 1 6 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-lookups)))))))
                   (muxer-getters
                     (append! prevs mux-getter)
                     (1+ idx)
                     (cdr names))))))
           (source-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name          (car names))
                        (stats         (cached-stats iface-stats name))
                        (source-getter (list (cons (append mib (list 2 1 1 1 idx)) (lambda () (cons 'octet-string (string->utf8 name))))
                                             (cons (append mib (list 2 1 1 2 idx)) (lambda () (cons 'counter64 (assq-ref stats 'tot-received))))
                                             (cons (append mib (list 2 1 1 3 idx)) (lambda () (cons 'counter64 (assq-ref stats 'tot-dropped))))
                                             (cons (append mib (list 2 1 1 4 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-packets))))
                                             (cons (append mib (list 2 1 1 5 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-duplicates))))
                                             (cons (append mib (list 2 1 1 6 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-cap-bytes))))
                                             (cons (append mib (list 2 1 1 7 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-wire-bytes)))))))
                   (source-getters
                     (append! prevs source-getter)
                     (1+ idx)
                     (cdr names))))))
           (malloc-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name          (car names))
                        (stats         (cached-stats mallocer-stats name))
                        (malloc-getter (list (cons (append mib (list 4 1 1 1 idx)) (lambda () (cons 'octet-string (string->utf8 name))))
                                             (cons (append mib (list 4 1 1 2 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'tot-size))))
                                             (cons (append mib (list 4 1 1 3 idx)) (lambda () (cons 'gauge32   (assq-ref stats 'nb-blocks))))
                                             (cons (append mib (list 4 1 1 4 idx)) (lambda () (cons 'counter64 (assq-ref stats 'nb-allocs)))))))
                   (malloc-getters
                     (append! prevs malloc-getter)
                     (1+ idx)
                     (cdr names))))))
           (array-getters
             (lambda (prevs idx names)
               (if (null? names) prevs
                 (let* ((name         (car names))
                        (stats        (cached-stats array-stats name))
                        (array-getter (list (cons (append mib (list 4 3 1 1 idx)) (lambda () (cons 'octet-string (string->utf8 name))))
                                            (cons (append mib (list 4 3 1 2 idx)) (lambda () (cons 'gauge32      (assq-ref stats 'nb-used))))
                                            (cons (append mib (list 4 3 1 3 idx)) (lambda () (cons 'gauge32      (assq-ref stats 'nb-malloced))))
                                            (cons (append mib (list 4 3 1 4 idx)) (lambda () (cons 'gauge32      (assq-ref stats 'nb-holes))))
                                            (cons (append mib (list 4 3 1 5 idx)) (lambda () (cons 'gauge32      (assq-ref stats 'nb-chunks))))
                                            (cons (append mib (list 4 3 1 6 idx)) (lambda () (cons 'integer      (assq-ref stats 'alloc-size))))
                                            (cons (append mib (list 4 3 1 7 idx)) (lambda () (cons 'integer      (assq-ref stats 'entry-size)))))))
                   (array-getters
                     (append! prevs array-getter)
                     (1+ idx)
                     (cdr names)))))))
    (let* ((scalars      (list (cons (append mib '(1 1 0)) getoid-version)
                               (cons (append mib '(2 2 0)) getoid-dup-detection-delay)
                               (cons (append mib '(4 2 0)) getoid-guile-mem-stats)))
           (getters-list (parser-getters scalars      1 (proto-names)))
           (muxers-list  (muxer-getters  getters-list 1 (mux-names)))
           (sources-list (source-getters muxers-list  1 (iface-names)))
           (malloc-list  (malloc-getters sources-list 1 (mallocer-names)))
           (array-list   (array-getters  malloc-list  1 (array-names))))
      (sort! malloc-list oid-less))))


(define-public (start)
  (let ((thread (lambda ()
                  (set-thread-name "J-guile-snmp-subagt")
                  (while #t
                         (catch #t
                                (lambda ()
                                  (let ((subagent (net:make-subagent "junkie" mib getters '())))
                                    (net:loop subagent)))
                                (lambda (key . args)
                                  (sleep 10)))))))
    (if have-snmp
        (make-thread thread)
        (slog log-notice "Skip starting of junkie SNMP subagent."))))

