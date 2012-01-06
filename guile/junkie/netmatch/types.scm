; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch types))

(use-modules (ice-9 regex)
             (rnrs records syntactic)
             (ice-9 format)
             (junkie tools))


;;; We have a few types likes integer, ip address, string (or known max size) that we
;;; manipulate (for fetching values of these types from info fields, storing them in
;;; register, and applying various operators on them.
;;;
;;; For each, we need a few basic operations:
;;; - imm v: returns an immediate value as a stub (from its representation as a guile value);
;;; - fetch p n i: returns the code stub that fetch the field n (string) from info at
;;;   address i (string) for the proto named p (string);
;;; - ref n: returns the code stub to reach the value bound to register named n (string)
;;; - bind n s: returns the code stub to bind stub s (stub) to register named n (string)
;;;
;;; Then we have the operators:
;;; - binary-op op s1 s2: return the code stub to perform this operation and the name of the
;;;   result;
;;; - unary-op op s: return the code stub to perform this operation and the name of the
;;;   result.
;;;
;;; All these operators are typed (by type-assertions that will fail when generating the code)

; we take the type rather than the type name because one day we may want to try implicit convertion?
(define (check t1 t2)
  (if (not (eq? t1 t2))
      (throw 'type-error (type-name t1) (type-name t2))))

(export check)

(define-record-type type (fields name imm fetch ref bind))
(export type-name type-imm type-fetch type-ref type-bind)

;;; But what's a code stub? It's the code required to compute a value, this value's name,
;;; and the list of used register(s).

(define-record-type stub (fields code result regnames))
(export make-stub stub-code stub-result stub-regnames)

;;; Operators (itypes is the list of input types and thus gives the number of parameters as
;;; well as their types)

(define-record-type op (fields name otype itypes function))
(export make-op op-name op-otype op-itypes op-function)

;;; Tools
;;; By convention, and to aleviate the code from unnecessary closures, we will assume that:
;;; - the current regfile is pointed to by a pointer named regfile;
;;; - the current proto is pointed by proto;
;;; - the current info is pointed by info.
;;; This also makes test and match expressions easier to write.

(define (unboxed-ref regname)
  (make-stub
    ""
    (string-append "regfile[" regname "].value")
    '(regname)))

(define (unboxed-bind regname value)
  (make-stub
    (string-append
      (stub-code value)
      "    regfile[" regname "].value = " (stub-result value) ";\n")
    (string-append "regfile[" regname "].value")
    (cons regname (stub-regnames value))))

(define gensymC
  (let ((c 0))
    (lambda (prefix)
      (set! c (1+ c))
      (string-append "npc__" prefix (number->string c)))))

(export gensymC)

(define (indent-more str)
  (regexp-substitute/global #f (make-regexp "^ {4}" regexp/newline) str 'pre "        " 'post))

;;; The unit type

;(define ignored #f)
;(define make-empty-stub
;  (lambda dummy (make-stub "" "" '())))
;(set! ignored
;  (make-type
;    'ignored
;    make-empty-stub   ; imm
;    make-empty-stub   ; fetch
;    make-empty-stub   ; ref
;    make-empty-stub)) ; bind
;
;(export ignored)


;;; Booleans

(define bool
  (make-type
    'bool
    (lambda (v) ; imm
      (make-stub "" (if v "true" "false") '()))
    (lambda (proto field) ; fetch
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append field "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    bool " res " = " tmp "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind))

(export bool)


;;; Unsigned ints (less then 64 bits wide)

(define uint
  (make-type
    'uint
    (lambda (v) ; imm
      (make-stub "" (format #f "~d" v) '()))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append field "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    uint_least64_t " res " = " tmp "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind))

(export uint)


;;; Logical Operators

(define operators (make-hash-table 31))

(define log-or
  (make-op
    'or
    bool
    (list bool bool)
    (lambda (v1 v2)
      (let ((res (gensymC "result")))
        (make-stub
          (string-append
            (stub-code v1)
            "    bool " res " = true;\n"
            "    if (! (" (stub-result v1) ")) {\n"
            (indent-more (stub-code v2))
            "        " res " = " (stub-result v2) ";\n"
            "    }\n")
          res
          '())))))

(hashq-set! operators '| log-or)
(hashq-set! operators '|| log-or)
(hashq-set! operators 'or log-or)
(hashq-set! operators 'log-or log-or)

(define log-and
  (make-op
    'and
    bool
    (list bool bool)
    (lambda (v1 v2)
      (let ((res (gensymC "result")))
        (make-stub
          (string-append
            (stub-code v1)
            "    bool " res " = false;\n"
            "    if (" (stub-result v1) ") {\n"
            (indent-more (stub-code v2))
            "        " res " = " (stub-result v2) ";\n"
            "    }\n")
          res
          '())))))

(hashq-set! operators '& log-and)
(hashq-set! operators '&& log-and)
(hashq-set! operators 'and log-and)
(hashq-set! operators 'log-and log-and)

(define log-not
  (make-op
    'not
    bool
    (list bool)
    (lambda (v)
      (let ((res (gensymC "result")))
        (make-stub
          (string-append
            (stub-code v)
            "    bool " res " = ! (" (stub-result v) ");\n")
          res
          '())))))

(hashq-set! operators '! log-not)
(hashq-set! operators 'not log-not)

(export log-or log-and log-not)

;;; Arithmetic Operators

(define (simple-binary-op C-op C-otype)
  (lambda (v1 v2)
    (let ((res (gensymC "result")))
      (make-stub
        (string-append
          (stub-code v1)
          (stub-code v2)
          "    " C-otype " " res " = " (stub-result v1) " " C-op " " (stub-result v2) ";\n")
        res
        '()))))

(define add
  (make-op '+ uint (list uint uint) (simple-binary-op "+" "uint_least64_t")))

(define sub
  (make-op '- uint (list uint uint) (simple-binary-op "-" "uint_least64_t")))

(define mult
  (make-op '* uint (list uint uint) (simple-binary-op "*" "uint_least64_t")))

(define div
  (make-op '/ uint (list uint uint) (simple-binary-op "/" "uint_least64_t")))

(define mod
  (make-op 'mod uint (list uint uint) (simple-binary-op "%" "uint_least64_t")))

(define gt
  (make-op '> bool (list uint uint) (simple-binary-op ">" "bool")))

(define ge
  (make-op '>= bool (list uint uint) (simple-binary-op ">=" "bool")))

(define lt
  (make-op '< bool (list uint uint) (simple-binary-op "<" "bool")))

(define le
  (make-op '<= bool (list uint uint) (simple-binary-op "<=" "bool")))

(define eq
  (make-op '= bool (list uint uint) (simple-binary-op "==" "bool")))

(hashq-set! operators '+ add)
(hashq-set! operators '- sub)
(hashq-set! operators '* mult)
(hashq-set! operators '/ div)
(hashq-set! operators 'mod mod)
(hashq-set! operators '% mod)
(hashq-set! operators '> gt)
(hashq-set! operators '>= ge)
(hashq-set! operators '< lt)
(hashq-set! operators '<= le)
(hashq-set! operators '= eq)

(export add sub mult div mod gt ge lt le eq)

;;; TODO: operations on IP addresses, on strings...


;;; Mapping from symbols to operators

(define (symbol->op sym)
  (hashq-ref operators sym))

(export symbol->op)

