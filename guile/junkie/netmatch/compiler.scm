; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch compiler))

(use-modules (ice-9 match)
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
;             ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:))
             (junkie tools))

;;; This takes terse expressions like:
;;;
;;; '(log-or #f client-is-connected)
;;; or:
;;; '(#f || client-is-connected) ; since operators starting with special chars are supposed to be infix
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

; If "Any sufficiently complicated C program contains an ad-hoc, informally-specified,
; bug-ridden, slow implementation of half of lisp", then any sufficiently complicated
; list program contains an ad-hoc, etc, slow implementation of a type checker. This is
; it. :-)
; return the code stub corresponding to the expression, given its expected type.
; proto is the layer we are at (fields will be fetched from this structure).


(define (expr->stub proto expr expected-type)
  (let ((perform-op (lambda (op-name params)
                      (let* ((op (or (type:symbol->op op-name)
                                     (throw 'you-must-be-jocking (simple-format #f "operator ~s?" op-name))))
                             (itypes  (type:op-itypes op))
                             (otype   (type:op-otype op)))
                        (simple-format #t "expr->stub of ~a outputing a ~a~%" op-name (type:type-name otype))
                        (type:check otype expected-type)
                        (if (not (eqv? (length itypes) (length params)))
                            (throw 'you-must-be-jocking
                                   (simple-format #f "bad number of parameters for ~a: ~a instead of ~a" op-name (length params) (length itypes))))
                        (apply
                          (type:op-function op)
                          (map (lambda (p t) (expr->stub proto p t)) params itypes)))))
        (is-infix   (let ((prefix-chars (string->char-set "!@#$%^&*-+=|~/:><")))
                      (lambda (op)
                        (and (symbol? op)
                             (char-set-contains? prefix-chars (string-ref (symbol->string op) 0))
                             (false-if-exception (type:symbol->op op)))))))
    (cond
      ((list? expr)
       (match expr
              (()
               (throw 'you-must-be-jocking "what's the empty list for?"))
              ; Try first to handle some few special forms (only (x as y) for now
              ((x 'as name)
               (let ((x-stub (expr->stub proto x expected-type)))
                 (or (symbol? name)
                     (throw 'you-must-be-jocking (simple-format #f "register name must be a symbol not ~s" name)))
                 ((type:type-bind expected-type) (string->C-ident (symbol->string name)) x-stub)))
              ((? (lambda (expr) (is-infix (cadr expr))) (v1 op-name v2))
               (simple-format #t "Infix operator ~s~%" op-name)
               (perform-op op-name (list v1 v2)))
              ; Now that we have ruled out the empty list and special forms we must face an operator
              ((op-name . params)
               (perform-op op-name params))))
      ((boolean? expr)
       (simple-format #t "expr->stub of the boolean ~a~%" expr)
       (type:check type:bool expected-type)
       ((type:type-imm type:bool) expr))
      ((number? expr)
       (type:check type:uint expected-type)
       ((type:type-imm type:uint) expr))
      ((symbol? expr)
       ; field names are spelled without percent sign prefix
       (let* ((str        (symbol->string expr))
              (is-regname (eqv? (string-ref str 0) #\%)))
         (if is-regname
             ((type:type-ref expected-type) (string->C-ident (substring str 1)))
             ; else we have to fetch this field from current proto
             (let* ((expr (case proto
                            ; transform known fields we must/want make friendlier
                            ((cap)
                             (case expr
                               ((dev-id device dev) 'dev_id)
                               ((timestamp ts) 'tv)
                               (else expr)))))
                    ; then we have a few generic transformation regardless of the proto
                    (expr (case expr
                            ((header-size header-length header-len) 'info.head_len)
                            ((payload-size payload-length payload-len payload) 'info.payload)
                            ; but in the general case field name is the same
                            (else expr))))
               ((type:type-fetch expected-type) (symbol->string proto) (symbol->string expr))))))
      (else
        (throw 'you-must-be-jocking
               (simple-format #f "~a? you really mean it?" expr))))))

(export expr->stub)

;;; Also, for complete matches, transform this:
;;;
;;; '(("node1" . (match (first cap with (|| #f $client-is-connected))
;;;                     (find ip with (= tos 2))))
;;;   ("node2" . ...))
;;;
;;; into this:
;;;
;;; (("node1" . ((cap #f ((op-function log-or) ((type-imm bool) #f)
;;;                                            ((type-ref bool) 'client-is-connected)))
;;;              (ip #t ((op-function =) ((type-fetch "ip" 'tos)) ((type-imm uint) 2)))))
;;;  ("node2" . ...))
;;;

