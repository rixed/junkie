; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch nettrack))

(use-modules (ice-9 match)
             (junkie tools)
             (junkie runtime) ; for make-nettrack
			 ((junkie netmatch netmatch) :renamer (symbol-prefix-proc 'match:))
             ((junkie netmatch types)    :renamer (symbol-prefix-proc 'type:))) ; for string->C-ident

;;; This takes a name and a nettrack expression with all tests developped, and returns:
;;; - the required shared object file name,
;;; - the required number of registers,
;;; - the nettrack graph SMOB object.
;;;
;;; For instance, let's consider this nettrack expression:
#;(
(; edges
  [] ; notice that edges are filled with default attributes as required
  ; vertices
  [(root web-syn
         ((ip with  (do
                      (src as ip-client)
                      (dst as ip-server)
                      #t))
          (tcp with (and syn
                         (dst-port == 80)
                         (do (src-port as client-port) #t))))
         spawn)
   (web-syn http-answer
            ((ip with   ((src =i %ip-server) && (dst =i %ip-client)))
             (tcp with  ((src-port == 80) && (dst-port == %client-port)))
             (http with ((set? (status as %http-status)))))
            kill)])
)
;;; We want to gather from it the list of matches:
;;; -> ((("root_2_web_syn" . ((ip with ....) (tcp with ...)))
;;;      ("web_syn_2_http_answer" . (...)))

; returns the C name of the test function from "from" to "to"
(define match-name
  (let ((seq 0))
    (lambda (from to)
      (set! seq (+ 1 seq))
      (string-append
        (type:string->C-ident (symbol->string from))
        "_2_"
        (type:string->C-ident (symbol->string to))
        "_"
        (number->string seq)))))

; returns a vertice suitable for make-nettrack and the (match-name . match) pair
(define (chg-vertice vertice)
  (let* ((from  (car vertice))
         (to    (cadr vertice))
         (match (caddr vertice))
         (rest  (cdddr vertice))
         (fname (match-name from to)))
    (cons
      (list fname from to rest)
      (cons fname match))))

; takes a full expression and do the work
(define (compile name expr)
  (let ((edges       (car expr))
        (vertices    (cadr expr))
        (matches     '())
        (vertices-ll '()))
    (for-each
      (lambda (v)
        (match (chg-vertice v)
               ((new-v . new-m)
                (set! matches
                  (cons new-m matches))
                (set! vertices-ll
                  (cons new-v vertices-ll)))))
      vertices)
    (match (match:compile matches)
           ((so-name . nb-regs)
            (make-nettrack name so-name nb-regs edges vertices-ll)))))

(export compile)
