; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch types))

(use-modules (ice-9 regex)
             (srfi srfi-1)
             (srfi srfi-8) ; for receive
             (rnrs records syntactic)
             (ice-9 format)
             (junkie tools)
             (junkie defs))


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
;;; - to-scm n: returns the code stub to get the scm value out of a register
;;;
;;; All the operators are typed (by type-assertions that will fail when generating the code)

; we take the type rather than the type name because one day we might want to try implicit conversion?
(define (check t1 t2)
  (assert (type? t1))
  (assert (type? t2))
  (if (and (not (eq? t1 t2))
           (not (eq? t1 any))
           (not (eq? t2 any)))
      (throw 'type-error (type-name t1) (type-name t2))))

(export check)

(define-record-type type (fields name imm fetch ref bind to-scm))
(export type-name type? type-imm type-fetch type-ref type-bind type-to-scm)

;;; But what's a code stub? It's the code required to compute a value, this value's name,
;;; and the list of used register(s).

(define-record-type stub (fields code result regnames))

(define empty-stub (make-stub "" "" '()))

; additionally, this is useful to concat two stubs
(define (stub-concat-2 s2 s1)
  (make-stub
    (string-append (stub-code s1) (stub-code s2))
    (stub-result s2)
    (append (stub-regnames s1) (stub-regnames s2))))

(define (stub-concat . s)
  (reduce stub-concat-2 empty-stub s))

(export make-stub stub-code stub-result stub-regnames stub-concat empty-stub)

;;; Operators (itypes is the list of input types and thus gives the number of parameters as
;;; well as their types)

(define-record-type op (fields name otype itypes function))
(export make-op op-name op-otype op-itypes op-function)

;;; Tools
;;; By convention, and to alleviate the code from unnecessary closures, we will assume that:
;;; - the current regfile is pointed to by a pointer named regfile;
;;; - the current proto is pointed by proto;
;;; - the current info is pointed by info.
;;; This also makes test and match expressions easier to write.

(define (unboxed-ref regname)
  (make-stub
    ""
    (string-append "prev_regfile[nm_reg_" regname "__].value")
    (list regname)))

(define (unboxed-bind regname value)
  (make-stub
    (string-append
      (stub-code value)
      "    new_regfile[nm_reg_" regname "__].value = " (stub-result value) ";\n"
      "    new_regfile[nm_reg_" regname "__].size = 0;\n")
    (string-append "new_regfile[nm_reg_" regname "__].value")
    (cons regname (stub-regnames value))))

(define (boxed-ref c-type)
  (lambda (regname)
    (make-stub
      ""
      (string-append "(("c-type" *)prev_regfile[nm_reg_" regname "__].value)")
      (list regname))))

(define (simple-to-scm gtypename ctypename)
  (lambda (stub)
    (let ((res (gensymC "to_scm_res")))
      (make-stub
        (string-append
          (stub-code stub)
          "    SCM " res " = scm_from_" gtypename "((" ctypename ")" (stub-result stub) ");\n")
        res
        (stub-regnames stub)))))

(define (boxed-bind regname value)
  (make-stub
    (string-append
      (stub-code value) ; FIXME: this won't work when rebinding the same boxed register (ie (%foo as foo)), which should not be possible anyway
      "    if (new_regfile[nm_reg_" regname "__].size > 0) {\n"
      "        free((void *)new_regfile[nm_reg_" regname "__].value);\n"
      "    }\n"
      "    new_regfile[nm_reg_" regname "__].value = (intptr_t)malloc(sizeof(*" (stub-result value) "));\n"
      "    new_regfile[nm_reg_" regname "__].size = sizeof(*" (stub-result value) ");\n"
      "    assert(new_regfile[nm_reg_" regname "__].value);\n" ; aren't assertions as good as proper error checks? O:-)
      "    memcpy((void *)new_regfile[nm_reg_" regname "__].value, " (stub-result value) ", sizeof(*" (stub-result value) "));\n")
    (string-append "new_regfile[nm_reg_" regname "__].value")
    (cons regname (stub-regnames value))))

; FIXME: move all the thing->C-thing into a separate module,
; included both by this one and ll-compiler.

(define gensymC
  (let ((c 0))
    (lambda (prefix)
      (set! c (1+ c))
      (string-append "npc__" prefix (number->string c)))))

(export gensymC)

(define string->C-ident
  (let* ((ident-1st-charset (char-set-intersection char-set:ascii char-set:letter))
         (ident-charset (char-set-union
                          ident-1st-charset
                          (char-set-intersection char-set:ascii char-set:digit))))
    (lambda (str)
      (let ((s
              (list->string (map (lambda (c)
                                   (if (char-set-contains? ident-charset c)
                                     c
                                     #\_))
                                 (string->list str)))))
        (if (not (char-set-contains? ident-1st-charset (string-ref s 0)))
          (string-set! s 0 #\_))
        s))))

(export string->C-ident)

(define (symbol->C-ident s) (string->C-ident (symbol->string s)))

(export symbol->C-ident)

(define (string->C-string s)
  (let* ((s (regexp-substitute/global #f "\\\\" s 'pre "\\\\" 'post)) ; escape backslashes (notice how slash must be doubled in the regex (not in the replacement)
         (s (regexp-substitute/global #f "\"" s 'pre "\\\"" 'post)) ; escape quotes
         (s (regexp-substitute/global #f "\n" s 'pre "\\n" 'post))) ; escape newlines which would prevent compilation
    (string-append "\"" s "\"")))

(export string->C-string)

(define (to-string s)
  (if (symbol? s) (symbol->string s) s))

(define (symbol->C-string s)
  (string->C-string (to-string s)))

(export symbol->C-string)

(define (bool->C v)
  (if v "true" "false"))

(export bool->C)

(define (indent-more str)
  (regexp-substitute/global #f (make-regexp "^ {4}" regexp/newline) str 'pre "        " 'post))

(export indent-more)

; Given a length and a number, returns a string like "{ 12, 43, 4 }" suitable to initialize a C byte array.
; The first argument is the number of expected digits (thus (number->C-byte-array 3 1) will yield "{0,0,1}")
(define (number->C-byte-array l n)
  (let* ((number->bytes (lambda (l n)
                          (letrec ((aux (lambda (prev l n)
                                          (if (<= l 0)
                                              prev
                                              (let ((lo (logand n #xff))
                                                    (hi (ash n -8)))
                                                (aux (cons lo prev) (- l 1) hi))))))
                            (aux '() l n))))
         (bytes         (number->bytes l n)))
    (string-append
      "{ "
      (fold (lambda (n s)
              (if (eqv? 0 (string-length s))
                  (number->string n)
                  (string-append s ", " (number->string n))))
            "" bytes)
      " }")))

(define (fold-vector i f v)
  (let loop ((n 0)
             (p i))
    (if (>= n (vector-length v))
        p
        (loop (1+ n) (f p (vector-ref v n))))))

(define (bytes->C-byte-array v)
  (string-append
    "{ " (fold-vector "" (lambda (str x)
                           (string-append str (number->string x) ", "))
                      v)
    " }"))

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

;;; The any type that can be used in some cases to bypass typecheck. Cannot be used.

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
      (throw 'type-error "Cannot bind without type"))
    (lambda (stub) ; to-scm
      (throw 'type-error "Cannot convert to scm without type"))))

(export any)

;;; Booleans

(define bool
  (make-type
    'bool
    (lambda (v) ; imm
      (make-stub "" (if v "true" "false") '()))
    (lambda (proto field) ; fetch
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    bool const " res " = " proto "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind
    (simple-to-scm "bool" "bool")))

(export bool)

;;; Unsigned ints (less then 64 bits wide)

(define uint
  (make-type
    'uint
    (lambda (v) ; imm
      (make-stub "" (format #f "~d" v) '()))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    uint_least64_t " res " = " proto "->" field ";\n")
          res
          '())))
    unboxed-ref
    unboxed-bind
    (simple-to-scm "uint64" "uint64_t")))

(export uint)

;;; Strings

(define str ; the stub-result will be a pointer to the nul terminated string
  (make-type
    'str
    (lambda (v) ; imm
      (let ((res (gensymC "str")))
        (make-stub
          (string-append "    char " res "[] = " (string->C-string v) ";\n")
          res
          '())))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    char const *" res " = " proto "->" field ";\n")
          res
          '())))
    (boxed-ref "char")
    (lambda (regname value) ; bind needs special attention since sizeof(*res) won't work, we need strlen(*res)+1
      (let ((tmp (gensymC "strbind")))
        (make-stub
          (string-append
            (stub-code value)
            "    /* " (stub-result value) " is supposed to point to a null terminated string */\n"
            "    size_t " tmp " = 1 + strlen(" (stub-result value) ");\n"
            "    if (new_regfile[nm_reg_" regname "__].value) {\n" ; FIXME: same as above
            "        free((void *)new_regfile[nm_reg_" regname "__].value);\n"
            "    }\n"
            "    new_regfile[nm_reg_" regname "__].value = (intptr_t)malloc(" tmp ");\n"
            "    new_regfile[nm_reg_" regname "__].size = " tmp ";\n"
            "    assert(new_regfile[nm_reg_" regname "__].value);\n" ; aren't assertions as good as proper error checks? O:-)
            "    memcpy((void *)new_regfile[nm_reg_" regname "__].value, " (stub-result value) ", " tmp ");\n")
          (string-append "new_regfile[nm_reg_" regname "__].value")
          (cons regname (stub-regnames value)))))
    (simple-to-scm "latin1_string" "char const *")))

(export str)

;;; Bytes (represented in C as struct npc_register so we have both addr and size)

(define bytes
  (make-type
    'bytes
    (lambda (v) ; imm, v is a numeric vector
      (let ((res   (gensymC "bytes"))
            (tmp   (gensymC "bytes_tmp")))
        (make-stub
          (string-append
            "    static unsigned char " tmp "[] = " (bytes->C-byte-array v) ";\n"
            "    struct npc_register " res " = { .value = (uintptr_t)" tmp ", .size = sizeof(" tmp ") };\n")
          res
          '())))
    (lambda (proto field)
      ; we cannot do much since we have no size indication
      (throw 'type-error "Cannot fetch bytes"))
    (lambda (regname) ; ref
      (make-stub
        ""
        (string-append "prev_regfile[" regname "]")
        (list regname)))
    (lambda (regname value) ; bind
      (make-stub
        (string-append
          (stub-code value)
          "    memcpy(&new_regfile[nm_reg_" regname "__], &" (stub-result value) ", sizeof(new_regfile[0]));\n"
        (string-append "new_regfile[nm_reg_" regname "__]")
        (cons regname (stub-regnames value)))))
    (lambda (stub) ; to SCM (as a string) (TODO: as a vector of numbers?)
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            (stub-code stub)
            "    SCM " res " = scm_from_latin1_stringn((char const *)" (stub-result stub) ".value, " (stub-result stub) ".size);\n")
          res
          (stub-regnames stub))))))

(export bytes)

; Is this symbol a list of bytes?
(define (looks-like-bytes? v)
  (and (vector? v)
       (fold-vector #t (lambda (p x)
                         (and p (number? x)))
                    v)))

(export looks-like-bytes?)

;;; Timestamps

(define timestamp ; the stub-result will be a pointer to a struct timeval
  (make-type
    'timestamp
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct timeval const *" res " = &" proto "->" field ";\n")
          res
          '())))
    (boxed-ref "struct timeval")
    boxed-bind
    (lambda (stub) ; to-scm
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            "    SCM " res " = scm_cons(\n"
            "        scm_from_uint64(((struct timeval const *)" (stub-result stub) ")->tv_sec),\n"
            "        scm_from_uint64(((struct timeval const *)" (stub-result stub) ")->tv_usec)\n"
            "    );\n")
          res
          (stub-regnames stub))))))

(export timestamp)

;;; Broken down time (used for TLS certificates)

(define ber-time; the stub-result will be a pointer to a struct timeval
  (make-type
    'ber-time
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct ber_time const *" res " = &" proto "->" field ";\n")
          res
          '())))
    (boxed-ref "struct ber_time")
    boxed-bind
    (lambda (stub) ; to-scm
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            "    SCM " res " = scm_list_n(\n"
            "        scm_from_uint16(((struct ber_time const *)" (stub-result stub) ")->year),\n"
            "        scm_from_uint8(((struct ber_time const *)" (stub-result stub) ")->month),\n"
            "        scm_from_uint8(((struct ber_time const *)" (stub-result stub) ")->day),\n"
            "        scm_from_uint8(((struct ber_time const *)" (stub-result stub) ")->hour),\n"
            "        scm_from_uint8(((struct ber_time const *)" (stub-result stub) ")->min),\n"
            "        scm_from_uint8(((struct ber_time const *)" (stub-result stub) ")->sec),\n"
            "        SCM_UNDEFINED);\n")
          res
          (stub-regnames stub))))))

(export ber-time)

;;; Large integers (represented as strings of digits) (used for TLS serial numbers)

(define ber-uint ; the stub-result will be a pointer to a struct timeval
  (make-type
    'ber-uint
    (lambda (v) ; imm
      #f)
    (lambda (proto field) ; fetch
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct ber_uint const *" res " = &" proto "->" field ";\n")
          res
          '())))
    (boxed-ref "struct ber_uint")
    boxed-bind
    (lambda (stub) ; to-scm
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            "    SCM " res " = scm_from_latin1_string(ber_uint_2_str(" (stub-result stub) "));\n")
          res
          (stub-regnames stub))))))

(export ber-uint)

;;; IP addresses

(define ip ; the stub-result will be a pointer to a struct ip_addr
  (make-type
    'ip
    (lambda (v) ; imm
      (let ((res (gensymC "ip")))
        (make-stub
          (string-append
            "    struct ip_addr " res ";\n"
            "    ip_addr_ctor_from_str_any(&" res ", " (string->C-string (to-string v)) ");\n")
          (string-append "&" res)
          '())))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    struct ip_addr const *" res " = &" proto "->" field ";\n")
          res
          '())))
    (boxed-ref "struct ip_addr")
    boxed-bind
    (lambda (stub) ; to-scm (as a (FAMILY, number))
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            "    SCM " res " = scm_from_ip_addr(" (stub-result stub) ");\n")
          res
          (stub-regnames stub))))))

(export ip)

; Is this symbol an IP address?
(define (looks-like-ip? s)
  (let ((s (to-string s)))
    (or (false-if-exception (inet-pton AF_INET s))
        (false-if-exception (inet-pton AF_INET6 s)))))

(export looks-like-ip?)

(define subnet ; stored as two consecutive IP addresses
  (make-type
    'subnet
    (lambda (v) ; imm
      (receive (addr mask) (apply values (string-split (to-string v) #\/))
               (let ((addr-stub ((type-imm ip) addr))
                     (mask-stub ((type-imm ip) mask))
                     (res (gensymC "subnet")))
                 (make-stub
                   (string-append
                     (stub-code addr-stub)
                     (stub-code mask-stub)
                     "    struct ip_addr *" res " = calloc(2, sizeof(*" res "));\n" ; we use calloc to set padding bytes at 0 (to please subnet-hash operator)
                     "    assert(" res ");\n" ; aren't assertions as good as proper error checks? O:-)
                     "    memcpy(" res "+0, " (stub-result addr-stub) ", sizeof(" res "[0]));\n"
                     "    memcpy(" res "+1, " (stub-result mask-stub) ", sizeof(" res "[1]));\n")
                   res
                   (append (stub-regnames addr-stub) (stub-regnames mask-stub))))))
    (lambda (proto field) ; fetch
      (throw 'cannot-fetch-a-subnet))
    (boxed-ref "(struct ip_addr[2])")
    boxed-bind
    (lambda (stub) ; to-scm (as a pair of ip1, ip2)
      (let ((res (gensymC "to_scm_res")))
        (make-stub
          (string-append
            "    SCM " res " = scm_cons(\n"
            "        scm_from_ip_addr((struct ip_addr const *)" (stub-result stub) "+0),\n"
            "        scm_from_ip_addr((struct ip_addr const *)" (stub-result stub) "+1)\n"
            "    );\n")
          res
          (stub-regnames stub))))))

(export subnet)

(define (looks-like-subnet? s)
  (let ((s (to-string s)))
    (catch #t
           (lambda ()
             (receive (addr mask) (apply values (string-split s #\/))
                      (and (looks-like-ip? addr)
                           (looks-like-ip? mask))))
           (lambda (key . args)
             #f))))

(export looks-like-subnet?)

;;; Ethernet addresses

(define mac ; the stub-result will be a pointer to an array of ETH_ADDR_LEN chars
  (make-type
    'mac
    (lambda (v) ; imm
      (let ((res (gensymC "mac")))
        (make-stub
          (string-append
            "    unsigned char " res "[ETH_ADDR_LEN] = " (number->C-byte-array 6 (string->eth (symbol->string v))) ";\n")
          res
          '())))
    (lambda (proto field) ; fetch (TODO: factorize with other types)
      (let* ((res (gensymC (string-append (string->C-ident field) "_field"))))
        (make-stub
          (string-append
            "    unsigned char const (*" res ")[ETH_ADDR_LEN] = &" proto "->" field ";\n")
          res
          '())))
    (boxed-ref "unsigned char")
    boxed-bind
    (simple-to-scm "eth_addr" "unsigned char *"))) ; to-scm (as a number)

(export mac)

; Is this symbol a mac address?
(define (looks-like-mac? s)
  (string-match
    "^[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}:[0-9a-f]{1,2}$"
    (symbol->string s)))

(export looks-like-mac?)


;;;
;;; Operators
;;;

; A hash of name -> list of functions of this name
(define operators (make-hash-table 31))

; Welcome the helper for insertion
(define (add-operator sym fun)
  (let ((prev (hashq-ref operators sym '())))
    (hashq-set! operators sym (cons fun prev))))

; Mapping from symbols to operators
(define (symbol->ops sym)
  (hashq-ref operators sym))

(export symbol->ops)

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

(add-operator '|| log-or)
(add-operator 'or log-or)
(add-operator 'log-or log-or)

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

(add-operator '&& log-and)
(add-operator 'and log-and)
(add-operator 'log-and log-and)

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

(add-operator '! log-not)
(add-operator 'not log-not)

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

(define shift-left
  (make-op 'shift-left uint (list uint uint) (simple-binary-op "<<" "uint_least64_t")))

(define shift-right
  (make-op 'shift-right uint (list uint uint) (simple-binary-op ">>" "uint_least64_t")))

(define int-and
  (make-op '& uint (list uint uint) (simple-binary-op "&" "uint_least64_t")))

(define int-or
  (make-op '| uint (list uint uint) (simple-binary-op "|" "uint_least64_t")))


(define (simple-binary-fun fun)
  (lambda (v1 v2)
    (let ((tmp1 (gensymC "tmp_1_"))
          (tmp2 (gensymC "tmp_2_"))
          (res  (gensymC "result")))
      (make-stub
        (string-append
          (stub-code v1)
          (stub-code v2)
          "    uint_least64_t " tmp1 " = " (stub-result v1) ", " tmp2 " = " (stub-result v2) ";\n"
          "    uint_least64_t " res " = MAX(" tmp1 ", " tmp2 ");\n")
        res
        (append (stub-regnames v1) (stub-regnames v2))))))

(define max
  (make-op 'max uint (list uint uint) (simple-binary-fun "MAX")))

(define min
  (make-op 'max uint (list uint uint) (simple-binary-fun "MIN")))

(define random
  (make-op 'random uint (list uint)
           (lambda (m)
             (let ((res (gensymC "random")))
               (make-stub
                 (string-append
                   (stub-code m)
                   "    uintptr_t " res " = (uintptr_t)random() % " (stub-result m) ";\n")
                 res
                 (stub-regnames m))))))

(add-operator '+ add)
(add-operator '- sub)
(add-operator '* mult)
(add-operator '/ div)
(add-operator 'mod mod)
(add-operator '% mod)
(add-operator '> gt)
(add-operator '>= ge)
(add-operator '< lt)
(add-operator '<= le)
(add-operator '= eq)
(add-operator '== eq)
(add-operator 'max max)
(add-operator 'min min)
(add-operator 'random random)
(add-operator '<< shift-left)
(add-operator '>> shift-right)
(add-operator '& int-and)
(add-operator '| int-or)

(export add sub mult div mod gt ge lt le eq shift-left shift-right)

;;; Timestamp manipulation

(define make-timestamp ; build a timestamp from a UNIX timestamp (as uint)
  (make-op 'make-timestamp timestamp (list uint)
           (lambda (ts)
             (let ((res (gensymC "timestamp")))
               (make-stub
                 (string-append
                   (stub-code ts)
                   "    struct timeval " res " = { .tv_sec = " (stub-result ts) "; .tv_usec = 0; };\n")
                 (string-append "&" res)
                 (stub-regnames ts))))))

(add-operator 'make-timestamp make-timestamp)

(define now ; build a timestamp based from current local time
  (make-op 'now timestamp '()
           (lambda ()
             (let ((res (gensymC "now")))
               (make-stub
                 (string-append
                   "    struct timeval " res ";\n"
                   "    timeval_set_now(" res ");\n")
                 (string-append "&" res)
                 '())))))

(add-operator 'now now)

(define age ; returns the number of microsecs between now and a given timestamp from the past (since result is unsigned)
  (make-op 'age uint (list timestamp)
           (lambda (ts)
             (let ((res (gensymC "now")))
               (make-stub
                 (string-append
                   (stub-code ts)
                   "    int64_t " res " = timeval_age(" (stub-result ts) ");\n")
                 res
                 (stub-regnames ts))))))

(add-operator 'age age)

(define timestamp-sub ; returns the number of microseconds between two timestamps (first minus second, must be positive!)
  (make-op 'timestamp-sub uint (list timestamp timestamp)
           (lambda (ts1 ts2)
             (let ((res (gensymC "ts_diff")))
               (make-stub
                 (string-append
                   (stub-code ts1)
                   (stub-code ts2)
                   "    int64_t " res " = timeval_sub(" (stub-result ts1) ", " (stub-result ts2) ");\n")
                 res
                 (append (stub-regnames ts1) (stub-regnames ts2)))))))

(add-operator 'timestamp-sub timestamp-sub)
(add-operator 'sub-timestamp timestamp-sub)
(add-operator '-TS timestamp-sub)
(add-operator '- timestamp-sub)

(define (timestamp-comp-op opname cmp-cond)
  (lambda (ts1 ts2)
    (let ((res (gensymC (string-append "ts_" opname))))
      (make-stub
        (string-append
          (stub-code ts1)
          (stub-code ts2)
          "    bool " res " = timeval_cmp(" (stub-result ts1) ", " (stub-result ts2) ") " cmp-cond ";\n")
        res
        (append (stub-regnames ts1) (stub-regnames ts2))))))

(define timestamp-gt
  (make-op 'timestamp-gt bool (list timestamp timestamp) (timestamp-comp-op "gt" "> 0")))
(add-operator '> timestamp-gt)
(define timestamp-ge
  (make-op 'timestamp-ge bool (list timestamp timestamp) (timestamp-comp-op "ge" ">= 0")))
(add-operator '>= timestamp-gt)
(define timestamp-lt
  (make-op 'timestamp-lt bool (list timestamp timestamp) (timestamp-comp-op "lt" "< 0")))
(add-operator '< timestamp-gt)
(define timestamp-le
  (make-op 'timestamp-le bool (list timestamp timestamp) (timestamp-comp-op "le" "<= 0")))
(add-operator '<= timestamp-gt)
(define timestamp-eq
  (make-op 'timestamp-eq bool (list timestamp timestamp) (timestamp-comp-op "eq" "== 0")))
(add-operator '== timestamp-gt)
(add-operator '= timestamp-gt)

(export make-timestamp now age timestamp-sub)

;; IP addresses manipulation

(define routable?
  (make-op 'routable? bool (list ip)
           (lambda (ip)
             (let ((res (gensymC "is_routable")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   "    bool " res " = ip_addr_is_routable((struct ip_addr *)" (stub-result ip) ");\n")
                 res
                 (stub-regnames ip))))))

(add-operator 'routable? routable?)
(add-operator 'is-routable routable?)

(define broadcast?
  (make-op 'broadcast? bool (list ip)
           (lambda (ip)
             (let ((res (gensymC "is_broadcast")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   "    bool " res " = ip_addr_is_broadcast((struct ip_addr *)" (stub-result ip) ");\n")
                 res
                 (stub-regnames ip))))))

(define in-subnet?
  (make-op 'in-subnet? bool (list ip subnet)
           (lambda (ip subnet)
             (let ((res (gensymC "in_subnet")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   (stub-code subnet)
                   "    bool " res " = ip_addr_match_mask(" (stub-result ip) ", " (stub-result subnet) "+0, " (stub-result subnet) "+1);\n")
                 res
                 (append (stub-regnames ip) (stub-regnames subnet)))))))

(add-operator 'broadcast? broadcast?)
(add-operator 'is-broadcast broadcast?)
(add-operator 'in-subnet? in-subnet?)

(define ip-eq?
  (make-op 'ip-eq? bool (list ip ip)
           (lambda (ip1 ip2)
             (let ((res (gensymC "same_ips")))
               (make-stub
                 (string-append
                   (stub-code ip1)
                   (stub-code ip2)
                   "    bool " res " = 0 == ip_addr_cmp((struct ip_addr *)" (stub-result ip1) ", (struct ip_addr *)" (stub-result ip2) ");\n")
                 res
                 (append (stub-regnames ip1) (stub-regnames ip2)))))))

(add-operator '=I ip-eq?)
(add-operator '=i ip-eq?)
(add-operator '= ip-eq?)
(add-operator '== ip-eq?)

(export routable? broadcast?)

;; Eth addresses manipulation

; TODO: add is-broadcast and so on

(define mac-eq?
  (make-op 'mac-eq? bool (list mac mac)
           (lambda (mac1 mac2)
             (let ((res (gensymC "same_macs")))
               (make-stub
                 (string-append
                   (stub-code mac1)
                   (stub-code mac2)
                   "    bool " res " = 0 == memcmp((void *)" (stub-result mac1) ", (void *)" (stub-result mac2) ", ETH_ADDR_LEN);\n")
                 res
                 (append (stub-regnames mac1) (stub-regnames mac2)))))))

(add-operator '=E mac-eq?)
(add-operator '=e mac-eq?)
(add-operator '= mac-eq?)
(add-operator '== mac-eq?)

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

(add-operator 'str-null? str-null?)

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

(add-operator 'str-eq? str-eq?)
(add-operator '=S str-eq?)
(add-operator '=s str-eq?)
(add-operator '= str-eq?)
(add-operator '== str-eq?)

(export str-null? str-eq?)

;; Bytes manipulation

(define num-bytes
  (make-op 'num-bytes uint (list bytes)
           (lambda (b)
             (let ((res (gensymC "num_bytes")))
               (make-stub
                 (string-append
                   (stub-code b)
                   "    uint_least64_t " res " = " (stub-result b) ".size;\n")
                 res
                (stub-regnames b))))))

(add-operator 'num-bytes num-bytes)

(define byte-at
  (make-op 'byte-at uint (list bytes uint)
           (lambda (b i)
             (let ((res (gensymC "byte_at")))
               (make-stub
                 (string-append
                   (stub-code i)
                   (stub-code b)
                   "    uint8_t " res " = ((uint8_t *)" (stub-result b) ".value)[" (stub-result i) "];\n")
                 res
                 (append (stub-regnames i) (stub-regnames b)))))))

(add-operator '@ byte-at)

(define uint16n-at
  (make-op 'uint16-at uint (list bytes uint)
           (lambda (b i)
             (let ((res (gensymC "uint16_at")))
               (make-stub
                 (string-append
                   (stub-code i)
                   (stub-code b)
                   "    uint16_t " res " = READ_U16N(" (stub-result b) ".value + " (stub-result i) ");\n")
                 res
                 (append (stub-regnames i) (stub-regnames b)))))))

(add-operator '@16n uint16n-at)

(define uint32n-at
  (make-op 'uint32-at uint (list bytes uint)
           (lambda (b i)
             (let ((res (gensymC "uint32_at")))
               (make-stub
                 (string-append
                   (stub-code i)
                   (stub-code b)
                   "    uint32_t " res " = READ_U32N(" (stub-result b) ".value + " (stub-result i) ");\n")
                 res
                 (append (stub-regnames i) (stub-regnames b)))))))

(add-operator '@32n uint32n-at)

(define bytes-eq?
  (make-op 'bytes-eq? bool (list bytes bytes)
           (lambda (b1 b2)
             (let ((res (gensymC "same_bytes")))
               (make-stub
                 (string-append
                   (stub-code b1)
                   (stub-code b2)
                   "    bool " res " = "(stub-result b1)".size == "(stub-result b2)".size &&\n"
                   "        0 == memcmp((void *)"(stub-result b1)".value, (void *)"(stub-result b2)".value, "(stub-result b1)".size);\n")
                 res
                 (append (stub-regnames b1) (stub-regnames b2)))))))

(add-operator 'bytes-eq? bytes-eq?)
(add-operator '=B bytes-eq?)
(add-operator '=b bytes-eq?)
(add-operator '= bytes-eq?)
(add-operator '== bytes-eq?)

(define firsts
  (make-op 'firsts bytes (list uint bytes)
           (lambda (n b)
             (let ((res (gensymC "firsts_res")))
               (make-stub
                 (string-append
                   (stub-code n)
                   (stub-code b)
                   "    struct npc_register " res " = { .value = " (stub-result b) ".value, .size = " (stub-result n) " };\n")
                 res
                 (append (stub-regnames n) (stub-regnames b)))))))

(add-operator 'firsts firsts)

(define index-of-bytes
  (make-op 'index-of-bytes uint (list bytes bytes uint uint uint)
           (lambda (haystack needle offset maxlen default) ; FIXME We should return a better type than uint to get rid of default
             (let ((res (gensymC "index_of_bytes_res"))
                   (tmp (gensymC "mem_ptr")))
               (make-stub
                 (string-append
                   (stub-code haystack)
                   (stub-code needle)
                   (stub-code offset)
                   (stub-code maxlen)
                   (stub-code default)
                   "    uint_least64_t " res " = " (stub-result default) " ;\n"
                   "    if ( " (stub-result haystack) ".size >= " (stub-result offset) " ) {\n"
                   "        void *" tmp " = memmem((char const *)" (stub-result haystack) ".value + " (stub-result offset) ","
                   "MIN(" (stub-result haystack) ".size - " (stub-result offset) ", " (stub-result maxlen) " + " (stub-result needle) ".size ) "
                   "   , (void *)" (stub-result needle) ".value, " (stub-result needle) ".size);\n"
                   "        if ( " tmp " ) " res " = " tmp " - ((void *)" (stub-result haystack) ".value);\n"
                   "    }\n"
                   )
                 res
                 (append (stub-regnames haystack) (stub-regnames needle)))))))

(add-operator 'index-of-bytes index-of-bytes)

(define str-in-bytes
  (make-op 'str-in-bytes bool (list bytes str)
           (lambda (b s)
             (let ((res (gensymC "str_in_bytes_res")))
               (make-stub
                 (string-append
                   (stub-code b)
                   (stub-code s)
                   "    bool " res " = NULL != memmem((char const *)" (stub-result b) ".value, " (stub-result b) ".size, " (stub-result s) ", sizeof(" (stub-result s) "));\n")
                 res
                 (append (stub-regnames b) (stub-regnames s)))))))

(add-operator 'str-in-bytes str-in-bytes)

(define bytes-starts-with-str
  (make-op 'bytes-starts-with-str bool (list bytes str)
           (lambda (b s)
             (let ((len (gensymC "strlength"))
                   (res (gensymC "starts_with_res")))
               (make-stub
                 (string-append
                   (stub-code b)
                   (stub-code s)
                   "    size_t " len " = strlen(" (stub-result s) "); // hopefully will be optimized away for const strings\n"
                   "    bool " res " =\n"
                   "        ((size_t)" (stub-result b) ".size >= " len ") &&\n"
                   "        0 == strncmp((char const *)" (stub-result b) ".value, (char const *)" (stub-result s) ", " len ");\n")
                 res
                 (append (stub-regnames b) (stub-regnames s)))))))

(define bytes-starts-with-bytes
  (make-op 'bytes-starts-with-bytes bool (list bytes bytes)
           (lambda (b1 b2)
             (let ((res (gensymC "starts_with_res")))
               (make-stub
                 (string-append
                   (stub-code b1)
                   (stub-code b2)
                   "    bool " res " =\n"
                   "        (" (stub-result b1) ".size >= " (stub-result b2) ".size) &&\n"
                   "        0 == memcmp(" (stub-result b1) ".value, " (stub-result b2) ", " (stub-result b1) ".size);\n")
                 res
                 (append (stub-regnames b1) (stub-regnames b2)))))))

(add-operator 'starts-with bytes-starts-with-str)
(add-operator 'starts-with bytes-starts-with-bytes)

;; Hash of base types

(define bool-hash
  (make-op 'bool-hash uint (list bool)
           (lambda (v)
             (let ((res (gensync "bool_hash")))
               (make-stub
                 (string-append
                   (stub-code v)
                   "    uint32_t " res " = (uint32_t) " (stub-result v) ";\n")
                 res
                 (stub-regnames v))))))

(add-operator 'hash bool-hash)

(define uint-hash
  (make-op 'uint-hash uint (list uint)
           (lambda (v) v)))

(add-operator 'hash uint-hash)

(define str-hash
  (make-op 'str-hash uint (list str)
           (lambda (str)
             (let ((res (gensymC "str_hash")))
               (make-stub
                 (string-append
                   (stub-code str)
                   "    uint32_t " res " = hashfun((void *)" (stub-result str) ", strlen(" (stub-result str) "));\n")
                 res
                 (stub-regnames str))))))

(add-operator 'hash str-hash)

(define bytes-hash
  (make-op 'bytes-hash uint (list bytes)
           (lambda (bytes)
             (let ((res (gensymC "bytes_hash")))
               (make-stub
                 (bytesing-append
                   (stub-code bytes)
                   "    uint32_t " res " = hashfun((void *)" (stub-result bytes) ".value, " (stub-result bytes) ".size);\n")
                 res
                 (stub-regnames bytes))))))

(add-operator 'hash bytes-hash)

(define timestamp-hash
  (make-op 'timestamp-hash uint (list timestamp)
           (lambda (timestamp)
             (let ((res (gensymC "timestamp_hash")))
               (make-stub
                 (string-append
                   (stub-code timestamp)
                   "    uint32_t " res " = hashfun((void *)" (stub-result timestamp) ", sizeof(struct timeval));\n")
                 res
                 (stub-regnames timestamp))))))

(add-operator 'hash timestamp-hash)

(define ip-hash
  (make-op 'ip-hash uint (list ip)
           (lambda (ip)
             (let ((res (gensymC "ip_hash")))
               (make-stub
                 (string-append
                   (stub-code ip)
                   "    uint32_t " res " = hashfun((void *)" (stub-result ip) ", sizeof(struct ip_addr));\n")
                 res
                 (stub-regnames ip))))))

(add-operator 'hash ip-hash)

(define subnet-hash
  (make-op 'subnet-hash uint (list subnet)
           (lambda (subnet)
             (let ((res (gensymC "subnet_hash")))
               (make-stub
                 (string-append
                   (stub-code subnet)
                   "    uint32_t " res " = hashfun((void *)" (stub-result subnet) ", sizeof(struct ip_addr) * 2);\n")
                 res
                 (stub-regnames subnet))))))

(add-operator 'hash subnet-hash)

(define mac-hash
  (make-op 'mac-hash uint (list mac)
           (lambda (mac)
             (let ((res (gensymC "mac_hash")))
               (make-stub
                 (string-append
                   (stub-code mac)
                   "    uint32_t " res " = hashfun((void *)" (stub-result mac) ", ETH_ADDR_LEN);\n")
                 res
                 (stub-regnames mac))))))

(add-operator 'hash mac-hash)


