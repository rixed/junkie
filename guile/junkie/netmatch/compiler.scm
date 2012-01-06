; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch compiler))

(use-modules ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
;             ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:))
             (junkie tools))

;;; This takes terse expressions like:
;;;
;;; '(log-or #f client-is-connected)
;;;
;;; and transforms them into:
;;;
;;; ((op-function log-or) ((type-imm bool) #f) ((type-ref bool) 'client-is-connected))
;;;
;;; So we have to deduce the actual types of the parameters according to their scheme types:
;;;
;;;   symbol -> some register name of some type or some field name to fetch
;;;   bool -> bool
;;;   number -> uint
;;;   ... -> ...
;;;   list -> recurse
;;;
;;; For refing the register file we need to know the types of each register or infer it from
;;; the operations involved, which is simple given our operations.
;;;
;;; For other parameters than symbols, we use the operation signature to typecheck.
;;;

(define string->C-ident
  (let ((ident-charset (char-set-intersection char-set:ascii char-set:letter)))
    (lambda (str)
      (list->string (map (lambda (c)
                           (if (char-set-contains? ident-charset c)
                               c
                               #\_))
                         (string->list str))))))

; return the code stub corresponding to the expression, given its expected type
(define (expr->stub expr expected-type)
  (cond
    ((list? expr)
     (if (null? expr)
         (throw 'you-must-be-jocking "what's for the empty list?")
         (let* ((op-name (car expr))
                (params  (cdr expr))
                (op      (or (type:symbol->op op-name)
                             (throw 'you-must-be-jocking op-name)))
                (itypes  (type:op-itypes op))
                (otype   (type:op-otype op)))
           (simple-format #t "expr->stub of ~a outputing a ~a~%" op-name (type:type-name otype))
           (type:check otype expected-type)
           (if (not (eqv? (length itypes) (length params)))
               (throw 'you-must-be-jocking
                      (simple-format #f "bad number of parameters for ~a: ~a instead of ~a" op-name (length params) (length itypes))))
           (apply
             (type:op-function op)
             (map expr->stub params itypes)))))
    ((boolean? expr)
     (simple-format #t "expr->stub of the boolean ~a~%" expr)
     (type:check type:bool expected-type)
     ((type:type-imm type:bool) expr))
    ((number? expr)
     (type:check type:uint expected-type)
     ((type:type-imm type:uint) expr))
    ((symbol? expr)
     ; field names are spelled proto.field (then some field names must be further processed)
     (let* ((str     (symbol->string expr))
            (dot-idx (string-index str #\.)))
       (if dot-idx
           (let ((proto (substring str 0 dot-idx))
                 (field (case expr
                          ; transform known fields we must arrange somewhat
                          ; ((ip.src ip.source) "key.addr[0]")
                          ; but in the general case field name is the same
                          (else (substring str (1+ dot-idx))))))
             ((type:type-fetch expected-type) proto field))
           ; Everything that's not spelled as a field name is supposed to be a register name
           ((type:type-ref expected-type) (string->C-ident str)))))
    (else
      (throw 'you-must-be-jocking
             (simple-format #f "~a? you really mean it?" expr)))))

(export expr->stub)
