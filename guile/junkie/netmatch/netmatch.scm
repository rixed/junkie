; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch netmatch))

(use-modules (ice-9 match)
             (srfi srfi-1) ; for fold
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:))
             (junkie tools)
             (junkie defs)
             (junkie runtime)) ; thus, junkie runtime as well

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

; If "Any sufficiently complicated C program contains an ad-hoc, informally-specified,
; bug-ridden, slow implementation of half of lisp", then any sufficiently complicated
; lisp program contains an ad-hoc, etc, slow implementation of a type checker. This is
; it. :-)
; return the code stub corresponding to the expression, given its expected type.
; proto is the layer we are at (fields will be fetched from this structure).

; Note regarding unset values
; ---------------------------
; We have several options to deal with unset fields:
; - handle the situation in fetch and fetch a default value instead
; - add a flag to every value telling if it's set or not (a la wireshark)
; - add a set? operator to the language and either let the user deal with it or handle it
;   automatically (ie. adding set? checks to protect the preceding bool/bind operator).
;
; This last option seams the best both for implementor and user.
; But we want to be able to write (set? dbname) for instance, ie use the name
; of an info field. set? must then be a special form and not an operator, converting
; (set? dbname) to "bool result = info->set_values & "(flags-for-field proto dbname).

(define flag-for-field
  (lambda proto-and-field
    (match proto-and-field
           ((or ('pgsql 'version) ('mysql 'version)  ('tns 'version)) "SQL_VERSION")
           ((or ('pgsql 'ssl-req) ('mysql 'ssl-req)  ('tns 'ssl-req)) "SQL_SSL_REQUEST")
           ((or ('pgsql 'user) ('mysql 'user)  ('tns 'user)) "SQL_USER")
           ((or ('pgsql 'dbname) ('mysql 'dbname)  ('tns 'dbname)) "SQL_DBNAME")
           ((or ('pgsql 'passwd) ('mysql 'passwd)  ('tns 'passwd)) "SQL_PASSWD")
           ((or ('pgsql 'auth-status) ('mysql 'auth-status)  ('tns 'auth-status)) "SQL_AUTH_STATUS")
           ((or ('pgsql 'sql) ('mysql 'sql) ('tns 'sql))      "SQL_SQL")
           ((or ('pgsql 'status) ('mysql 'status) ('tns 'status)) "SQL_STATUS")
           ((or ('pgsql 'nb-rows) ('mysql 'nb-rows) ('tns 'nb-rows)) "SQL_NB_ROWS")
           ((or ('pgsql 'nb-fields) ('mysql 'nb-fields) ('tns 'nb-fields)) "SQL_NB_FIELDS")
           (('http 'method) "HTTP_METHOD_SET")
           (('http 'error-code) "HTTP_CODE_SET")
           (('http 'content-length) "HTTP_LENGTH_SET")
           (('http 'mime-type) "HTTP_MIME_SET")
           (('http 'host) "HTTP_HOST_SET")
           (('http 'url) "HTTP_URL_SET")
           (('http 'chunked-encoding) "HTTP_TRANSFERT_ENCODING_SET")
           (('http 'user-agent) "HTTP_USER_AGENT_SET")
           ((or ('http 'referrer) ('http 'referer)) "HTTP_REFERRER_SET")
           (('http 'server) "HTTP_SERVER_SET")
           (('sip 'cmd) "SIP_CMD_SET")
           (('sip 'cseq) "SIP_CSEQ_SET")
           (('sip 'code) "SIP_CODE_SET")
           (('sip 'mime) "SIP_MIME_SET")
           (('sip 'content-length) "SIP_LENGTH_SET")
           (('sip 'from) "SIP_FROM_SET")
           (('sip 'to) "SIP_TO_SET")
           (('sip 'call-id) "SIP_CALLID_SET")
           (('sip 'via-protocol) "SIP_VIA_SET")
           (('sip 'via-addr) "SIP_VIA_SET")
           (('sip 'via-port) "SIP_VIA_SET")
           (('sdp 'host) "SDP_HOST_SET")
           (('sdp 'port) "SDP_PORT_SET")
           (('icmp 'protocol) "ICMP_ERR_SET")
           (('icmp 'src) "ICMP_ERR_SET")
           (('icmp 'dst) "ICMP_ERR_SET")
           (('icmp 'src-port) "(ICMP_ERR_SET+ICMP_ERR_PORT_SET)")
           (('icmp 'dst-port) "(ICMP_ERR_SET+ICMP_ERR_PORT_SET)")
           (('icmp 'id) "ICMP_ID_SET")
           (('gre 'key) "GRE_KEY_SET")
           (_ #f))))

; project all fieldname aliases to the cannonical name
(define fieldname
  (lambda proto-and-field
    (match proto-and-field
           ((or ('cap 'device) ('cap 'dev)) 'dev-id)
           ((or ('cap 'timestamp) ('cap 'ts)) 'tv)
           (('eth 'vlan) 'vlan-id)
           (('http 'status) 'error-code)
           (('sip 'via-proto) 'via-protocol)
           (('sip 'via-ip) 'via-addr)
           ((or ('pgsql 'numrows) ('mysql 'numrows) ('tns 'numrows)) 'nb-rows)
           ((or ('pgsql 'numfields) ('mysql 'numfields) ('tns 'numfields)) 'nb-fields)
           ((or ('pgsql 'nb-cols) ('mysql 'nb-cols) ('tns 'nb-cols)) 'nb-fields)
           ((or ('pgsql 'numcols) ('mysql 'numcols) ('tns 'numcols)) 'nb-fields)
           ((or ('pgsql 'dbuser) ('mysql 'dbuser) ('tns 'dbuser)) 'user)
           ; then we have a few generic transformation regardless of the proto
           ((or (_ 'header-length) (_ 'header-len) (_ 'head-len)) 'header-size)
           ((or (_ 'payload-length) (_ 'payload-len) (_ 'payload)) 'payload-size)
           ((_ 'source-port) 'src-port)
           ((_ 'dest-port) 'dst-port)
           ((_ 'source) 'src)
           ((_ 'dest) 'dst)
           ((_ 'proto) 'protocol)
           ((_ 'err-code) 'error-code)
           ((or (_ 'password) (_ 'pwd)) 'passwd)
           ((_ f) f))))

(define field->C
  (lambda proto-and-field
    (match proto-and-field
           ; transform known cannonical fieldnames we must/want make friendlier
           (('eth 'src)                                                      "addr[0]")
           (('eth 'dst)                                                      "addr[1]")
           (('ip 'src)                                                       "key.addr[0]")
           (('ip 'dst)                                                       "key.addr[1]")
           (('ip 'protocol)                                                  "key.protocol")
           (('tcp 'src-port)                                                 "key.port[0]")
           (('tcp 'dst-port)                                                 "key.port[1]")
           (('udp 'src-port)                                                 "key.port[0]")
           (('udp 'dst-port)                                                 "key.port[1]")
           (('dns 'txid)                                                     "transaction_id")
           (('dns 'class)                                                    "dns_class")
           (('dns 'type)                                                     "request_type")
           (('http 'error-code)                                              "code")
           ; FIXME: we can't anymore build a C expression for the proto_info field since we now need
           ;        the pointer itself (here "http"). We should, at a minimum, give this function the
           ;        name of the proto_info.
           (('http 'mime-type)                                               "strs+http->mime_type")
           (('http 'host)                                                    "strs+http->host")
           (('http 'user-agent)                                              "strs+http->user_agent")
           (('http 'referrer)                                                "strs+http->referrer")
           (('http 'server)                                                  "strs+http->server")
           (('http 'url)                                                     "strs+http->url")
           (('sip 'via-protocol)                                             "via.protocol")
           (('sip 'via-addr)                                                 "via.addr")
           (('sip 'via-port)                                                 "via.port")
           ((or ('pgsql 'sql) ('mysql 'sql) ('tns 'sql))                     "u.query.sql")
           ((or ('pgsql 'nb-rows) ('mysql 'nb-rows) ('tns 'nb-rows))         "u.query.nb_rows")
           ((or ('pgsql 'nb-fields) ('mysql 'nb-fields) ('tns 'nb-fields))   "u.query.nb_fields")
           ((or ('pgsql 'user) ('mysql 'user) ('tns 'user))                  "u.startup.user")
           ((or ('pgsql 'dbname) ('mysql 'dbname) ('tns 'dbname))            "u.startup.dbname")
           ((or ('pgsql 'passwd) ('mysql 'passwd) ('tns 'passwd))            "u.startup.passwd")
           ((or ('pgsql 'query?) ('mysql 'query?) ('tns 'query?))            "is_query")
           ; then we have a few generic transformation regardless of the proto
           ((_ 'header-size)                                                 "info.head_len")
           ((_ 'payload-size)                                                "info.payload")
           ; but in the general case field name is the same
           ((_ f) (type:symbol->C-ident f)))))

(define field->type
  (lambda proto-and-field
    (match proto-and-field
           ; return the type of all known cannonical fieldnames that are not uint
           ((or ('arp 'proto-addr-is-ip) ('arp 'hw-addr-is-ip)) type:bool)
           ((or ('arp 'sender) ('arp 'target)) type:ip)
           (('cap 'tv) type:timestamp)
           (('dns 'query) type:bool)
           (('dns 'name) type:str)
           ((or ('eth 'src) ('eth 'dst)) type:mac)
           ((or ('ip 'src) ('ip 'dst)) type:ip)
           ((or ('http 'mime-type) ('http 'host) ('http 'url) ('http 'user-agent)
                ('http 'referrer) ('http 'referer) ('http 'server)) type:str)
           ((or ('http 'chunked-encoding) ('http 'ajax)) type:bool)
           ((or ('icmp 'src) ('icmp 'dst)) type:ip)
           (('mgcp 'response) type:bool)
           ((or ('mgcp 'dialed) ('mgcp 'cnx-id) ('mgcp 'call-id)) type:str)
           (('sdp 'host) type:ip)
           ((or ('sip 'from) ('sip 'to) ('sip 'call-id) ('sip 'mime-type)) type:str)
           (('sip 'via-addr) type:ip)
           ((or ('pgsql 'is-query) ('mysql 'is-query) ('tns 'is-query)) type:bool)
           ((or ('pgsql 'user) ('mysql 'user) ('tns 'user)) type:str)
           ((or ('pgsql 'dbname) ('mysql 'dbname) ('tns 'dbname)) type:str)
           ((or ('pgsql 'passwd) ('mysql 'passwd) ('tns 'passwd)) type:str)
           ((or ('pgsql 'sql) ('mysql 'sql) ('tns 'sql)) type:str)
           ((or ('tcp 'syn) ('tcp 'ack) ('tcp 'rst) ('tcp 'fin)) type:bool)
           ; then all others are uint
           (_ type:uint))))

; given a proto and flag names, return the stub for the bool test of the set_values
(define (set? proto flag)
  (let ((res (type:gensymC "test_set")))
    (type:make-stub
      (string-append
        "    bool const " res " = " proto "->set_values & " flag ";\n")
      res
      '())))

; Returns the new expression replacing a well-known constant, of #f
(define (well-known-cst? x)
  (match x
         ('arp-request 1) ('arp-reply 2)
         ('dns-unset 0)
         ('dns-A 1) ('dns-NS 2) ('dns-MD 3) ('dns-MF 4)
         ('dns-CNAME 5) ('dns-SOA 6) ('dns-MB 7) ('dns-MG 8)
         ('dns-MR 9) ('dns-NULL 10) ('dns-WKS 11) ('dns-PTR 12)
         ('dns-HINFO 13) ('dns-MINFO 14) ('dns-MX 15) ('dns-TXT 16)
         ('dns-AAAA #x1c) ('dns-NBNS #x20) ('dns-SRV #x21)
         ('dns-NBSTAT #x21) ; yes, same as above
         ('dns-A6 #x26) ('dns-IXFR #xfb) ('dns-AXFR #xfc) ('dns-ANY #xff)
         ('dns-IN 1) ('dns-CS 2) ('dns-CH 3) ('dns-HS 4)
         ((or 'eth-ip 'eth-ipv4 'eth-ip4) #x0800)
         ((or 'eth-ip6 'eth-ipv6) #x86dd)
         ('eth-arp #x0806) ('eth-ieee-802.1q #x8100) ('eth-unset -1)
         ('http-get 0) ('http-head 1) ('http-post 2) ('http-connect 3)
         ('http-put 4) ('http-options 5) ('http-trace 6) ('http-delete 7)
         ('sip-register 0) ('sip-invite 1) ('sip-ack 2) ('sip-cancel 3)
         ('sip-options 4) ('sip-bye 5)
         ('sql-unknown 0) ('sql-startup 1) ('sql-query 2) ('sql-exit 3)
         ('sql-requested 0) ('sql-granted 1) ('sql-refused 2)
         ('ssl-unset 0) ('ssl-v2 1) ('ssl-v3 2) ('ssl-tls 3)
         (_ #f)))

(define expected-type (make-fluid type:any))
(define (with-expected-type t thung)
  ; BEWARE: not your usual with-this -> if currently expected type is type:any, then its value is not restored!
  (slog log-debug "now expecting ~a instead of ~a" (type:type-name t) (type:type-name (fluid-ref expected-type)))
  (let ((result (if (eq? (fluid-ref expected-type) type:any)
                    (begin
                      (fluid-set! expected-type t)
                      (thung))
                    (with-fluid* expected-type t thung))))
    (slog log-debug "...back to expecting ~a" (type:type-name (fluid-ref expected-type)))
    result))

(define (type-check-or-set t)
  (let ((et (fluid-ref expected-type)))
    (if (eq? et type:any)
        (begin
          (slog log-debug "we are now expecting ~a" (type:type-name t))
          (fluid-set! expected-type t))
        (type:check t et))))

(define (explode-op op s params)
  (slog log-debug "explode operation ~a with params ~s" op params)
  (if (eqv? s (length params))
      `(,op ,@params)
      (let ((firsts (drop-right params (- s 1)))
            (lasts  (take-right params (- s 1))))
        `(,op ,(explode-op op s firsts) ,@lasts))))

(define register-types (make-fluid)) ; an alist of name->type (persistant data structure for fast save/restore (just in case)
(define (reset-register-types)
  (fluid-set! register-types '())
  (fluid-set! expected-type type:any))
(export reset-register-types)
(reset-register-types)
(define (set-register-type regname type)
  (assert (type:type? type))
  ;(slog log-debug "set-register-type ~a to ~a in ~s" regname (type:type-name type) (fluid-ref register-types))
  (let ((prev-type (assoc-ref (fluid-ref register-types) regname)))
    (slog log-debug "register ~a is now known to be of type ~a (previously a ~a)" regname (type:type-name type) (if prev-type (type:type-name prev-type) "unknown"))
    (if prev-type
        ; check this is not incompatible with a previous information
        (if (not (eq? prev-type type))
            (throw 'type-error (simple-format #f "register ~a was a ~a but is now a ~a"
                                              regname (type:type-name prev-type) (type:type-name type))))
        ; else record it for future checks
        (fluid-set! register-types (cons (cons regname type) (fluid-ref register-types))))))
(export set-register-type)
(define (get-register-type regname)
  (assoc-ref (fluid-ref register-types) regname))
(define (register->type regname)
  (or (get-register-type regname)
      (throw 'unknown-register regname (fluid-ref register-types))))

;;; We want to support only one kind of "function" taking and destructuring a proto stack and returning anything (the regfiles are implicit)
;;; (function_name (proto1 in proto2 in proto3...) expr)
;;; Note that when the destructuration of protos fails, 0 is returned (Ok when function result is interpreted as a bool)
;;; where expr can be either a constants, proto.field, %register, (expression ...) or (special-form ...) (a la lisp).
;;; some of these special form are for binding (set!), some for testing field set value (set?), some for if, etc...
;;; This gets compiled into a C function taking the last proto info (and the prev/new regfiles), and returning an intptr_t.

(define (function-preamble name public)
  (type:make-stub
    (string-append
      (if public "" "static ")
      "uintptr_t " name "(struct proto_info const *info, struct npc_register rest, struct npc_register const *prev_regfile, struct npc_register *new_regfile)\n"
      "{\n"
      "    /* We may not use any of these: */\n"
      "    (void)info;\n"
      "    (void)rest;\n"
      "    (void)prev_regfile;\n"
      "    (void)new_regfile;\n")
    "" '()))

(define (proto->C sym) ; placeholder for more elavorate translation
  (symbol->string sym))

(define (deconstruct-protos protos)
  (let ((deconstruct-1 (lambda (proto prev)
                         (type:stub-concat
                           prev
                           (type:make-stub
                             (let ((p (type:stub-result prev)))
                               (if (string=? p "info")
                                   (string-append "    ASSIGN_INFO_CHK(" (proto->C proto) ", " p ", 0);\n")
                                   (string-append "    ASSIGN_INFO_CHK(" (proto->C proto) ", &" p "->info, 0);\n")))
                             (proto->C proto) '())))))
    (fold deconstruct-1 (type:make-stub "" "info" '()) protos)))

(define (expr->stub expr)
  (slog log-debug "Compiling expression ~s, which should be of type ~a" expr (type:type-name (fluid-ref expected-type)))
  (let* ((perf-op    (lambda (op params)
                       (let* ((itypes (type:op-itypes op))
                              (otype  (type:op-otype op)))
                         (slog log-debug " compiling operator ~a, taking ~a and returning a ~a"
                               (type:op-name op) (map type:type-name itypes) (type:type-name otype))
                         ; If we were expecting any type, we now expect an otype
                         (type-check-or-set otype)
                         (type:check otype (fluid-ref expected-type))
                         (if (eqv? (length params) (length itypes))
                             (apply
                               (type:op-function op)
                               (map (lambda (p t)
                                      (with-expected-type t (lambda () (expr->stub p))))
                                    params itypes))
                             ; In some occasions we automatically transform (op a b c d) to (op (op (op a b) c) d), or
                             ; in the general case, when op require n<m arguments:
                             ; (op a1 .. am) -> (op (op (... (op a1 .. an) an+1 .. a2n) a2n+1 .. a3n) ...)
                             ; so we suppose that op is left associative.
                             (if (and (> (length params) (length itypes)) ; if we have params in excess
                                      (every (lambda (t) (eqv? otype t)) itypes)) ; and they are all of the same type = the output type
                                 (expr->stub (explode-op (type:op-name op) (length itypes) params))
                                 (throw 'you-must-be-joking
                                        (simple-format #f "bad number of parameters for ~a: ~a instead of ~a"
                                                       (type:op-name op) (length params) (length itypes))))))))
         ; takes an op name and try each binding for this op until one works (aka. generic buildins)
         (perform-op (lambda (op-name params)
                       (let* ((ops (or (type:symbol->ops op-name)
                                       (throw 'you-must-be-joking 'unknown-operator op-name))))
                         (slog log-debug "We have all these operators to test: ~s" (map type:op-name ops))
                         (or (any (lambda (op)
                                    ; save register types
                                    (let ((saved-regs (fluid-ref register-types)))
                                      (slog log-debug "Saving register types:")
                                      (for-each (lambda (a)
                                                  (slog log-debug "  ~a of type ~a" (car a) (type:type-name (or (get-register-type (car a)) "unknown"))))
                                                saved-regs)
                                      (catch 'type-error
                                             (lambda () (perf-op op params))
                                             (lambda (key . args)
                                               ; restore register types
                                               (slog log-debug "Cannot type (because (~s ~s)), rollback" key args)
                                               (for-each (lambda (a)
                                                           (slog log-debug "  ~a of type ~a->~a"
                                                                 (car a)
                                                                 (type:type-name (or (get-register-type (car a)) "unknown"))
                                                                 (type:type-name (cdr a))))
                                                         saved-regs)
                                               (fluid-set! register-types saved-regs)
                                               #f))))
                                  ops)
                             (throw 'type-error (simple-format #f "Cannot find a suitable type for (~s ~s)" op-name params))))))
         (is-infix   (let ((prefix-chars (string->char-set "!@#$%^&*-+=|~/:><")))
                       (lambda (op)
                         (slog log-debug "is ~s an infix op?" op)
                         (and (symbol? op)
                              (char-set-contains? prefix-chars (string-ref (symbol->string op) 0))
                              (false-if-exception (type:symbol->ops op))))))
         (fieldname? (lambda (sym)
                       (and (symbol? sym)
                            (let* ((str (symbol->string sym))
                                   (dot (string-index str #\.)))
                              (and dot
                                   (> dot 0)
                                   (< dot (- (string-length str) 1))
                                   (cons (string->symbol (substring str 0 dot))
                                         (string->symbol (substring str (1+ dot))))))))))
    (cond
      ((list? expr)
       ; So we have either a special form or an operator application
       (match expr
              (()
               (throw 'you-must-be-joking "what's the empty list for?"))
              ;; Try first to handle some few special forms
              ; set? tells if a field is set or not in a proto into
              (('set? fname) ; special operator
               (match (fieldname? fname)
                      ((proto . f)
                       (let* ((field (fieldname proto f))
                              (flag  (flag-for-field proto field)))
                         (slog log-debug "compiling special form 'set?' for field name ~a (flag ~a)" field flag)
                         (if (not flag)
                             (throw 'you-must-be-joking (simple-format #f "field ~s in ~s is either always set or unknown" f proto)))
                         (set? (type:symbol->C-ident proto)
                               flag)))
                      (_ (throw 'you-must-be-joking (simple-format #f "how could ~a be set or not?" fname)))))
              ; as a convenience for nettrack, (hash x y ...) is rewritten as ((hash x) + (hash y) + ...)
              (('hash x y . rest)
               (slog log-debug " simplifying special form 'hash'")
               (expr->stub `((hash ,x) + (hash ,y ,@rest))))
              ; binding
              ((name ':= x)
               (slog log-debug " compiling special form 'bind' for expr ~a to register ~a" x name)
               (or (symbol? name)
                   (throw 'you-must-be-joking (simple-format #f "register name must be a symbol not ~s" name)))
               (let* ((x-stub  (expr->stub x)) ; should set expected-type if unset yet
                      (regname (type:symbol->C-ident name))
                      (e-type  (fluid-ref expected-type)))
                 (slog log-debug " compiling actual bind of ~s, of type ~s" x (type:type-name e-type))
                 (set-register-type regname e-type)
                 ((type:type-bind e-type) regname x-stub)))
              ; Sequencing operator (special typing, returns the last evaluated expression)
              (('do v1) ; easy one
               (expr->stub v1))
              (('do v1 . v2) ; general case
               (slog log-debug " compiling special form 'do'")
               (type:stub-concat
                 (with-expected-type type:any (lambda () (expr->stub v1)))
                 (expr->stub (cons 'do v2))))
              ; Generate code to pass C code from expression to generated file.
              (('pass . params)
               (slog log-debug " compiling special form 'pass'")
               (let ((ps (map (lambda (p)
                                (if (string? p) ; anything that's not a string must be evaluated
                                    (type:make-stub "" p '())
                                    (with-expected-type type:any (lambda () (expr->stub p)))))
                              params)))
                 (type:make-stub ; concatenate all code then all results
                   (string-append
                     (apply string-append (map type:stub-code ps))
                     (apply string-append (map type:stub-result ps))
                     "\n")
                   "0"
                   (apply append (map type:stub-regnames ps)))))
              ; Generate code that pass the given values to a given SCM function.
              (('apply fname . params)
               (slog log-debug " compiling special form 'apply' to ~a" fname)
               (let* ((have-module (list? fname))
                      (module      (if have-module fname '()))
                      (fname       (if have-module (car params) fname))
                      (params      (if have-module (cdr params) params))
                      (stubs       (map (lambda (p)
                                          (with-expected-type
                                            type:any
                                            (lambda ()
                                              ; we go from any to any type -> the type set by (expr->stub p) will be kept.
                                              (let ((s (with-expected-type type:any (lambda () (expr->stub p))))) ; set expected-type to actual type
                                                (slog log-debug "  param ~s is of type ~a" p (type:type-name (fluid-ref expected-type)))
                                                ((type:type-to-scm (fluid-ref expected-type)) s))))) ; so whatever the returned type we use the proper to-scm method (TODO: type the stubs?))
                                   params))
                      (procname    (type:gensymC "proc_"))
                      (paramsname  (type:gensymC "params_"))
                      (resname     (type:gensymC "apply_res_")))
                 (type:make-stub
                   (string-append
                     ; first all the definitions
                     (apply string-append (map type:stub-code stubs))
                     ; then locate the guile function
                     "    static SCM " procname " = SCM_BOOL_F;\n"
                     "    if (scm_is_false(" procname ")) {\n"
                     (if have-module
                         (string-append
                           "        SCM module = scm_c_resolve_module(" (type:string->C-string (string-join (map symbol->string module) " ")) ");\n"
                           "        SCM var = scm_c_module_lookup(module, " (type:symbol->C-string fname) ");\n")
                         (string-append
                           "        SCM var = scm_c_lookup(" (type:symbol->C-string fname) ");\n"))
                     "        " procname " = scm_variable_ref(var);\n"
                     "    }\n"
                     ; then the actual guile function call (using an array of parameters)
                     "    SCM " paramsname "[] = {\n"
                     "        " (string-join (map type:stub-result stubs) ", ") "\n"
                     "    };\n"
                     "    SCM " resname " = scm_call_n(" procname ", " paramsname ", NB_ELEMS(" paramsname "));\n")
                   resname
                   (apply append (map type:stub-regnames stubs)))))
              (('if condition then . elses)
               (let* ((cond-stub (with-fluid*
                                   ; Yes, not "with-expected-type". This time if the type is any
                                   ; then we want it to stay undetermined until we evaluate the
                                   ; consequent.
                                   expected-type type:bool
                                   (lambda () (expr->stub condition))))
                      (then-stub (expr->stub then))
                      (else-stub (if (null? elses)
                                     ; By default we assume #f if the expected type is bool, nothing if the expected type is any,
                                     ; and throw an error otherwise.
                                     (if (eq? (fluid-ref expected-type) type:bool)
                                         (expr->stub #f)
                                         (if (eq? (fluid-ref expected-type) type:any)
                                             (type:empty-stub)
                                             (throw 'you-must-be-joking (simple-format #f "you must provide an alternative of type ~a" (type:type-name (fluid-ref expected-type))))))
                                     (if (eqv? 1 (length elses))
                                         (expr->stub (car elses))
                                         (throw 'you-must-be-joking (simple-format #f "'if' forms can have only one consequent and one alternative")))))
                      (tmp       (type:gensymC "if_res")))
                 (type:make-stub
                   (string-append
                     (type:stub-code cond-stub)
                     "    uintptr_t unused_ " tmp ";\n" ; unused since we are not always going to use the if expression value (if we use the if for choosing between two side effects
                     "    if (" (type:stub-result cond-stub) ") {\n"
                     (type:indent-more (type:stub-code then-stub))
                     "        " tmp " = " (type:stub-result then-stub) ";\n"
                     "    } else {\n"
                     (type:indent-more (type:stub-code else-stub))
                     "        " tmp " = " (type:stub-result else-stub) ";\n"
                     "    }\n")
                   tmp
                   (append (type:stub-regnames cond-stub)
                           (type:stub-regnames then-stub)
                           (type:stub-regnames else-stub)))))
              ; If a type implements '== then we give it '!= for free
              ((or (a '!= b) (a '<> b))
               (expr->stub `(not (,a == ,b))))
              ; Now that we have ruled out the empty list and special forms we must face an operator, which can be infix or prefix
              ((and (v1 op-name . rest) (? (lambda (expr) (is-infix (cadr expr)))))
               (perform-op op-name (cons v1 rest)))
              ((op-name . params)
               (perform-op op-name params))))
      ; We handled lists. What's left: constants, well known constants, field references and register references.
      ; Immediate constants
      ((boolean? expr)
       (slog log-debug " compiling immediate boolean ~a" expr)
       (type-check-or-set type:bool)
       ((type:type-imm type:bool) expr))
      ((number? expr)
       (slog log-debug " compiling immediate number ~a" expr)
       (type-check-or-set type:uint)
       ((type:type-imm type:uint) expr))
      ((string? expr)
       (slog log-debug " compiling immediate string ~a" expr)
       (type-check-or-set type:str)
       ((type:type-imm type:str) expr))
      ((symbol? expr)
       (slog log-debug " compiling symbol ~a" expr)
       ; A symbol might be:
       ; - an immediate value for ip, mac...
       ; - a well-known constant
       ; - a field name (proto.field)
       ; - rest (the payload as a byte array)
       ; - otherwise, a register name
       (cond
         ((eq? 'rest expr)
          (slog log-debug " ...with is the 'rest' bytes")
          (type-check-or-set type:bytes)
          ; So we return this 'rest' function parameter
          (type:make-stub "" "rest" '()))
         ((type:looks-like-subnet? expr)
          (slog log-debug " ...which is a subnet")
          (type-check-or-set type:subnet)
          ((type:type-imm type:subnet) expr))
         ((type:looks-like-ip? expr)
          (slog log-debug " ...which is an IP")
          (type-check-or-set type:ip)
          ((type:type-imm type:ip) expr))
         ((type:looks-like-mac? expr)
          (slog log-debug " ...which is a MAC")
          (type-check-or-set type:mac)
          ((type:type-imm type:mac) expr))
         ((type:looks-like-bytes? expr)
          (slog log-debug " ...which is a byte array")
          (type-check-or-set type:bytes)
          ((type:type-imm type:bytes) expr))
         ((well-known-cst? expr) => expr->stub)
         ((fieldname? expr) =>
          (lambda (x)
            (let* ((proto (car x))
                   (canon-name (fieldname proto (cdr x))))
              (type-check-or-set (field->type proto canon-name))
              ((type:type-fetch (fluid-ref expected-type))
               (type:symbol->C-ident proto) (field->C proto canon-name)))))
         (else ; A register name
           ; Notice: if we don't know the type yet it's time to think about it.
           (let* ((regname     (type:symbol->C-ident expr))
                  (e-type      (fluid-ref expected-type)))
             (if (eq? e-type type:any)
                 (let ((actual-type (register->type regname)))
                   (slog log-debug "set expected type of register ~a: ~a" regname (type:type-name actual-type))
                   (fluid-set! expected-type actual-type))
                 ; check the type we expect is not incompatible with a previously known type for this regname (or set it)
                 (set-register-type regname e-type))
             ((type:type-ref (fluid-ref expected-type)) regname)))))
      (else
        (throw 'you-must-be-joking
               (simple-format #f "~a? you really mean it?" expr))))))

(define (function->stub otype protos expr public)
  (slog log-debug "Compiling netmatch function ~s" expr)
  (let* ((name (type:gensymC "netmatch_fun"))
         (preamble (function-preamble name public))
         (proto-deconstruction (deconstruct-protos (reverse protos)))
         (function-body (with-expected-type otype
                                            (lambda ()
                                              (expr->stub expr)))))
    (type:stub-concat
      preamble
      proto-deconstruction
      function-body
      (type:make-stub
        (string-append
          "    return (uintptr_t)" (type:stub-result function-body) ";\n}\n\n")
        name '()))))

(export function->stub)

; takes an expression and return a pair (libname . nb-regs)
(define (compile otype protos expr)
  (let* ((funname "match")
         (stub    (function->stub otype protos expr #f))
         (stub    (type:make-stub
                    (string-append
                      (type:stub-code stub)
                      "\n"
                      "uintptr_t " funname "(struct proto_info const *info, struct npc_register rest, struct npc_register const *prev_regfile, struct npc_register *new_regfile)\n"
                      "{\n"
                      "    return " (type:stub-result stub) "(info, rest, prev_regfile, new_regfile);\n"
                      "}\n")
                    funname
                    (type:stub-regnames stub))))
    (ll:stub->so stub)))

(export compile)

