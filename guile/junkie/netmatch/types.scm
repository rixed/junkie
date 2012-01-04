; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch types))

(use-modules (rnrs records syntactic)
             (ice-9 format)
             (junkie tools))


;;; We have a few types likes integer, ip address, string (or known max size) that we
;;; manipulate (for fetching values of these types from info fields, storing them in
;;; register, and applying various operators on them.
;;;
;;; For each, we need a few basic operations:
;;; - imm v: returns an immediate value (from its representation as a guile value);
;;; - fetch p n i: returns the code stub that fetch the field n (string) from info at
;;;   address i (string) for the proto named p (string);
;;; - ref n f: return the code stub to reach the value bound to register named n (string)
;;;   from register file named f (string);
;;; - bind n s f: return the code stub to bind stub s (stub) to register named n (string)
;;;   of regfile named f (string).
;;;
;;; Then some operators:
;;; - binary-op op s1 s2: return the code stub to perform this operation and the name of the
;;;   result;
;;; - unary-op op s: return the code stub to perform this operation and the name of the
;;;   result.
;;;

(define-record-type type (fields name imm fetch ref bind binary-op unary-op))
(export type-name type-imm type-fetch type-ref type-bind type-binary-op type-unary-op)

;;; But what's a code stub? It's the code required to compute a value, this value's name,
;;; and the list of used register(s).

(define-record-type stub (fields code result regnames))
(export stub-code stub-result stub-regnames)

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

(define ident-charset (char-set-union char-set:ascii char-set:letter))
(define (string->ident str)
  (list->string (map (lambda (c)
                       (if (char-set-contains? ident-charset c)
                           c
                           #\_))
                     (string->list str))))


;;; Booleans

(define (bool-binary-op op v1 v2)
  (let ((res (gensymC "result")))
    (case op
      ((or)  (make-stub
               (string-append
                 (stub-code v1)
                 "    bool " res " = true;\n"
                 "    if (! (" (stub-result v1) ")) {\n"
                 "        " (stub-code v2)
                 "        " res " = " (stub-result v2) ";\n"
                 "    }\n")
               res
               '()))
      ((and) (make-stub
               (string-append
                 (stub-code v1)
                 "    bool " res " = false;\n"
                 "    if (" (stub-result v1) ") {\n"
                 "        " (stub-code v2)
                 "        " res " = " (stub-result v2) ";\n"
                 "    }\n")
               res
               '()))
      (else (throw 'invalid-bin-op `(,op bool))))))

(define (bool-unary-op op v)
  (let ((res (gensymC "result")))
    (case op
      ((not) (make-stub
               (string-append
                 (stub-code v)
                 "    bool " res " = ! (" (stub-result v) ");\n")
               res
               '()))
      (else (throw 'invalid-unary-op `(,op bool))))))

(define bool
  (make-type
    'bool
    (lambda (v) ; imm
      (make-stub "" (if v "true" "false") '()))
    (lambda (proto field) ; fetch
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" tmp " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    bool " res " = " tmp "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind
    bool-binary-op
    bool-unary-op))

(export bool)


;;; Unsigned ints (less then 64 bits wide)

(define (uint-binary-op->C op v1 v2)
  (case op
    ((+)   (string-append v1 " + " v2))
    ((-)   (string-append v1 " - " v2))
    ((*)   (string-append v1 " * " v2))
    ((/)   (string-append v1 " / " v2))
    ((mod) (string-append v1 " % " v2))
    (else (throw 'invalid-bin-op `(,op uint)))))

(define (uint-unary-op->C op v)
  (case op
    ((not) (string-append "!" v))
    (else (throw 'invalid-unary-op `(,op uint)))))

(define uint
  (make-type
    'uint
    (lambda (v) ; imm
      (make-stub "" (format #f "~d" v) '()))
    (lambda (proto field) ; fetch
      (let* ((tmp (gensymC (string-append proto "_info")))
             (res (gensymC (string-append (string->ident field) "_field"))))
        (make-stub
          (string-append
            "    struct " proto "_proto_info const *" field " = DOWNCAST(info, info, " proto "_proto_info);\n"
            "    uint_least64_t " res " = " tmp "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind
    (lambda (op v1 v2) ; binary-op
      (let* ((res (gensymC "result")))
        (make-stub
          (string-append
            (stub-code v1)
            (stub-code v2)
            "    uint_least64_t " res " = " (uint-binary-op->C op (stub-result v1) (stub-result v2)) ";\n")
          res
          '())))
    (lambda (op v) ; unary-op
      (let* ((res (gensymC "result")))
        (make-stub
          (string-append
            (stub-code v)
            "    uint_least64_t " res " = " (uint-unary-op->C op (stub-result v)) ";\n")
          res
          '())))))
(export uint)

;;; Tests

(define (check)
  (let* ((expr1 ((type-binary-op bool)
                 'or
                 ((type-unary-op bool)
                   'not ((type-imm bool) #t))
                 ((type-imm bool) #f))))
    expr1))

