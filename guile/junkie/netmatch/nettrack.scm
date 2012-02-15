; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch nettrack))

(use-modules (ice-9 match)
             (junkie tools)
             (junkie runtime) ; for make-nettrack
             (junkie defs) ; for slog
             ((junkie netmatch netmatch) :renamer (symbol-prefix-proc 'netmatch:))
             ((junkie netmatch types)    :renamer (symbol-prefix-proc 'type:))) ; for string->C-ident

;;; This takes a name and a nettrack expression with all tests developped, and returns:
;;; - the required shared object file name,
;;; - the required number of registers,
;;; - the nettrack graph SMOB object.
;;;
;;; For instance, let's consider this nettrack expression:
#;(
(; edges (notice that edges are filled with default attributes as required)
  [(http-answer (pass "printf(\"%u\\n\", " %http-status ");\n"))] ; an action to perform whenever the http-answer node is entered
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
             (http with (do (status as http-status) (set? status))))
            kill)])
)
;;; For actions, here we use 'eval' with parameters of various types (eval is a special form which parameters are
;;; evaluated but not type checked, see netmatch.scm).
;;; We could also use 'call' which would call this function with given parameters (it's up to you (and ld) to
;;; ensure this call will eventually succeed). See netmatch.scm for these (and others) interesting special forms...
;;;
;;; We want to gather from this nettrack expression the list of matches:
;;; -> ((("root_2_web_syn" . ((ip with ....) (tcp with ...)))
;;;      ("web_syn_2_http_answer" . (...)))

; returns the C name of the test function from "from" to "to"
(define match-name
  (let ((seq 0))
    (lambda (from to)
      (set! seq (+ 1 seq))
      (string-append
        (type:symbol->C-ident from)
        "_2_"
        (type:symbol->C-ident to)
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
        (actions     '())
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
    (for-each
      (lambda (e)
        (slog log-debug "Got action: ~a~%" e)
        (match e
               ((name code)
                (set! actions
                  (cons (cons (string-append "entry_" (type:symbol->C-ident name))
                              code)
                        actions)))
               (_ #f)))
      edges)
    (match (netmatch:compile matches actions)
           ((so-name . nb-regs)
            (make-nettrack name so-name nb-regs edges vertices-ll)))))

(export compile)
