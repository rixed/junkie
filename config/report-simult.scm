; vim:syntax=scheme expandtab
;;; Source this file if you want junkie to report number of simultaneous connections.

(if (not (defined? 'defs-loaded)) (load "defs.scm"))

; Report simultaneous number of TCP/UDP connection every period seconds
(define (report-cnx period)
  (let ((max-tcp 0)
        (max-udp 0))
    (letrec ((update (lambda ()
                       (let ((cur-tcp (assq-ref (proto-stats "TCP") 'nb-parsers))
                             (cur-udp (assq-ref (proto-stats "UDP") 'nb-parsers)))
                         (if (> cur-tcp max-tcp) (set! max-tcp cur-tcp))
                         (if (> cur-udp max-udp) (set! max-udp cur-udp))
                         (simple-format #t "Current TCP:~a UDP:~a total:~a / Max TCP:~a UDP:~a total:~a\n"
                                        cur-tcp cur-udp (+ cur-tcp cur-udp)
                                        max-tcp max-udp (+ max-tcp max-udp))
                         (sleep period)
                         (update)))))
      (update))))

(use-modules (ice-9 threads))
(make-thread report-cnx 60)
