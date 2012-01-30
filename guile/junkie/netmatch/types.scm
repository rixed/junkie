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
;;; - fetch p n: returns the code stub that fetch the field n (string) from info at
;;;   address "info" for the proto named p (string);
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
  (if (and (not (eq? t1 t2))
           (not (eq? t1 any))
           (not (eq? t2 any)))
      (throw 'type-error (type-name t1) (type-name t2))))

(export check)

(define-record-type type (fields name imm fetch ref bind))
(export type-name type-imm type-fetch type-ref type-bind)

;;; But what's a code stub? It's the code required to compute a value, this value's name,
;;; and the list of used register(s).

(define-record-type stub (fields code result regnames))

; additionally, this is useful to concat two stubs
(define (stub-concat s1 s2)
  (make-stub
    (string-append (stub-code s1) (stub-code s2))
    (stub-result s2)
    (append (stub-regnames s1) (stub-regnames s2))))

(export make-stub stub-code stub-result stub-regnames stub-concat)

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
    (list regname)))

(define (unboxed-bind regname value)
  (make-stub
    (string-append
      (stub-code value)
      "    regfile[" regname "].value = " (stub-result value) ";\n")
    (string-append "regfile[" regname "].value")
    (cons regname (stub-regnames value))))

(define (boxed-ref regname)
  (make-stub
    ""
    (string-append "regfile[" regname "].value")
    (list regname)))

(define (boxed-bind regname value)
  (make-stub
    (string-append
      (stub-code value)
      "    if (regfile[" regname "].value) {\n"
      "        free(regfile[" regname "].value);\n"
      "    }\n"
      "    regfile[" regname "].value = malloc(sizeof(*" (stub-result value) "));\n"
      "    assert(regfile[" regname "].value);\n" ; aren't assertions as good as proper error checks? O:-)
      "    memcpy(regfile[" regname "].value, " (stub-result value) ", sizeof(*" (stub-result value) "));\n")
    (string-append "regfile[" regname "].value")
    (cons regname (stub-regnames value))))

(define gensymC
  (let ((c 0))
    (lambda (prefix)
      (set! c (1+ c))
      (string-append "npc__" prefix (number->string c)))))

(export gensymC)

(define string->C-ident
  (let ((ident-charset (char-set-intersection char-set:ascii char-set:letter)))
    (lambda (str)
      (list->string (map (lambda (c)
                           (if (char-set-contains? ident-charset c)
                               c
                               #\_))
                         (string->list str))))))

(export string->C-ident)

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

;;; The any type that can be used in some cases for bypass typecheck. Cannot be used.

(define any
  (make-type
    'any
    (lambda (v) ; imm
      (throw 'type-error "No immediate of type any"))
    (lambda (proto field) ; fetch
      (throw 'type-error "Cannot fetch without type"))
    (lambda (regname) ; ref
      (throw 'type-error "Cannot reference without type"))
    (lambda (regname value) ; bind
      (throw 'type-error "Cannot bind without type"))))

(export any)

;;; Booleans

(define bool
  (make-type
    'bool
    (lambda (v) ; imm
      (make-stub "" (if v "true" "false") '()))
    (lambda (proto field) ; fetch
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *const " tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    bool const " res " = " tmp "->" field ";\n")
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
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    uint_least64_t " res " = " tmp "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind))

(export uint)

;;; Strings

(define str ; the stub-result will be a pointer to the nul terminated string
  (make-type
    'str
    (lambda (v) ; imm
      (let ((res (gensymC "str")))
        (make-stub
          (string-append "    char " res "[] = \"" v "\";\n")
          res
          '())))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    char const *" res " = " tmp "->" field ";\n")
          res
          '())))
    boxed-ref
    (lambda (regname value) ; bind needs special attention since sizeof(*res) won't work, we need strlen(*res)
      (let ((tmp (gensymC)))
        (make-stub
          (string-append
            (stub-code value)
            "    /* " (stub-result value) " is supposed to point to a null terminated string */\n"
            "    size_t " tmp " = strlen(" (stub-result value) ");\n"
            "    if (regfile[" regname "].value) {\n"
            "        free(regfile[" regname "].value);\n"
            "    }\n"
            "    regfile[" regname "].value = malloc(" tmp ");\n"
            "    assert(regfile[" regname "].value);\n" ; aren't assertions as good as proper error checks? O:-)
            "    memcpy(regfile[" regname "].value, " (stub-result value) ", " tmp ");\n")
          (string-append "regfile[" regname "].value")
          (cons regname (stub-regnames value)))))))

(export str)

;;; Timestamps

(define timestamp ; the stub-result will be a pointer to a struct timeval
  (make-type
    'timestamp
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    struct timeval const *" res " = &" tmp "->" field ";\n")
          res
          '())))
    boxed-ref
    boxed-bind))

(export timestamp)


;;; Eth addresses

(define mac ; the stub-result will be a pointer to an array of ETH_ADDR_LEN chars
  (make-type
    'mac
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    char const (*" res ")[ETH_ADDR_LEN] = &" tmp "->" field ";\n")
          res
          '())))
    boxed-ref
    boxed-bind))

(export mac) ; TODO: a constructor


;;; IP addresses

(define ip ; the stub-result will be a pointer to a struct ip_addr
  (make-type
    'ip
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    struct ip_addr const *" res " = &" tmp "->" field ";\n")
          res
          '())))
    boxed-ref
    boxed-bind))

(export ip)


;;;
;;; Operators
;;;

(define operators (make-hash-table 31))

;;; Logical Operators

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
          (append (stub-regnames v1) (stub-regnames v2)))))))

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
          (append (stub-regnames v1) (stub-regnames v2)))))))

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
          (append (stub-regnames v)))))))

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
        (append (stub-regnames v1) (stub-regnames v2))))))

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
(hashq-set! operators '== eq)

(export add sub mult div mod gt ge lt le eq)

;;; Timestamp manipulation

(define make-timestamp ; build a timestamp from a UNIX timestamp (as uint)
  (make-op 'make-timestamp timestamp (list uint)
           (lambda (ts)
             (let ((res (gensymC "timestamp")))
               (make-stub
                 (string-append
                   (stub-code ts)
                   "    struct timeval " res " = { .tv_sec = " (stub-result ts) "; .tv_usec = 0; };\n")
                 res
                 (stub-regnames ts))))))

(hashq-set! operators 'make-timestamp make-timestamp)

(define now ; build a timestamp based from current local time
  (make-op 'now timestamp '()
           (lambda ()
             (let ((res (gensymC "now")))
               (make-stub
                 (string-append
                   "    struct timeval " res ";\n"
                   "    timeval_set_now(&" res ");\n")
                 res
                 '())))))

(hashq-set! operators 'now now)

(define age ; returns the number of microsecs between now and a given timestamp from the past (since result is unsigned)
  (make-op 'age uint (list timestamp)
           (lambda (ts)
             (let ((res (gensymC "now")))
               (make-stub
                 (string-append
                   (stub-code ts)
                   "    int64_t " res " = timeval_age(&" (stub-result ts) ");\n")
                 res
                 (stub-regnames ts))))))

(hashq-set! operators 'age age)

(define timestamp-sub ; returns the number of microseconds between two timestamps (first minus second, must be positive!)
  (make-op 'timestamp-sub uint (list timestamp timestamp)
           (lambda (ts1 ts2)
             (let ((res (gensymC "ts_diff")))
               (make-stub
                 (string-append
                   (stub-code ts1)
                   (stub-code ts2)
                   "    int64_t " res " = timeval_sub(&" (stub-result ts1) ", &" (stub-result ts2) ");\n")
                 res
                 (append (stub-regnames ts1) (stub-regnames ts2)))))))

(hashq-set! operators 'timestamp-sub timestamp-sub)
(hashq-set! operators 'sub-timestamp timestamp-sub)
(hashq-set! operators '-TS timestamp-sub)

(export make-timestamp now age timestamp-sub)

;; IP addresses manipulation

(define make-ip ; build an ip addr from a string
  (make-op 'make-ip ip (list str)
           (lambda (s)
             (let ((res (gensymC "ts_diff")))
               (make-stub
                 (string-append
                   (stub-code s)
                   "    struct ip_addr " res ";\n"
                   "    ip_addr_ctor_from_str_any(&" res ", " (stub-result s) ");\n")
                 res
                 (stub-regnames s))))))

(hashq-set! operators 'make-ip make-ip)

(define routable?
  (make-op 'routable? bool (list ip)
           (lambda (ip)
             (let ((res (gensymC "is_routable")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   "    bool " res " = ip_addr_is_routable(&" (stub-result ip) ");\n")
                 res
                 (stub-regnames ip))))))

(hashq-set! operators 'routable? routable?)
(hashq-set! operators 'is-routable routable?)

(define broadcast?
  (make-op 'broadcast? bool (list ip)
           (lambda (ip)
             (let ((res (gensymC "is_broadcast")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   "    bool " res " = ip_addr_is_broadcast(&" (stub-result ip) ");\n")
                 res
                 (stub-regnames ip))))))

(hashq-set! operators 'broadcast? broadcast?)
(hashq-set! operators 'is-broadcast broadcast?)

(export make-ip routable? broadcast?)

;; String manipulation

(define str-null?
  (make-op 'str-null? bool (list str)
           (lambda (str)
             (let ((res (gensymC "null_len")))
               (make-stub
                 (string-append
                   (stub-code str)
                   "    bool " res " = " (stub-result str) "[0] == '\\0';\n")
                 res
                 (stub-regnames str))))))

(hashq-set! operators 'str-null? str-null?)

(define str-eq?
  (make-op 'str-eq? bool (list str str)
           (lambda (s1 s2)
             (let ((res (gensymC "str_eq")))
               (make-stub
                 (string-append
                   (stub-code s1)
                   (stub-code s2)
                   "    bool " res " = 0 == strcmp(" (stub-result s1) ", " (stub-result s2) ");\n")
                 res
                 (append (stub-regnames s1) (stub-regnames s2)))))))

(hashq-set! operators 'str-eq? str-eq?)
(hashq-set! operators '=S str-eq?)
(hashq-set! operators '=s str-eq?)

(export str-null? str-eq?)


;;; Mapping from symbols to operators

(define (symbol->op sym)
  (hashq-ref operators sym))

(export symbol->op)

