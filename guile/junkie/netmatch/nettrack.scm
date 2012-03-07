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
(; vertices (notice that edges are filled with default attributes as required)
  [(http-answer (pass "printf(\"%u\\n\", " %http-status ");\n"))] ; an action to perform whenever the http-answer node is entered
  ; edges
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

(define (inner-proto-of-test test)
  (let ((ll-test (netmatch:test->ll-test test)))
    (car ll-test)))

(define (inner-proto-of-match match)
  (if (null? (cdr match))
      (inner-proto-of-test (car match))
      (inner-proto-of-match (cdr match))))

; returns an edge suitable for make-nettrack and the (match-name . match) pair
(define (chg-edge edge)
  (let* ((from        (car edge))
         (to          (cadr edge))
         (match       (caddr edge))
         (rest        (cdddr edge))
         (fname       (match-name from to))
         (inner-proto (inner-proto-of-match match)))
    (cons
      (list fname inner-proto from to rest)
      (cons fname match))))

; takes a full expression and do the work
(define (compile name expr)
  (netmatch:reset-register-types) ; since we are going to call test->ll-test (FIXME: test->ll-test is too much hassle just for obtaining the proto!)
  (let ((vertices    (car expr))
        (edges       (cadr expr))
        (matches     '())
        (actions     '())
        (edges-ll    '()))
    (for-each
      (lambda (e)
        (match (chg-edge e)
               ((new-e . new-m)
                (set! matches
                  (cons new-m matches))
                (set! edges-ll
                  (cons new-e edges-ll)))))
      edges)
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
      vertices)
    (match (netmatch:compile matches actions)
           ((so-name . nb-regs)
            (make-nettrack name so-name nb-regs vertices edges-ll)))))

(export compile)
