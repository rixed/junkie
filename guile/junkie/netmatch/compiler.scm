; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch compiler))

(use-modules (ice-9 match)
             (srfi srfi-1) ; for fold
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:))
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

; If "Any sufficiently complicated C program contains an ad-hoc, informally-specified,
; bug-ridden, slow implementation of half of lisp", then any sufficiently complicated
; list program contains an ad-hoc, etc, slow implementation of a type checker. This is
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
; But ww want to be able to write (set? dbname) for instance, ie use the name
; of an info field. set? must then be a special form and not an operator, converting
; (set? dbname) to "bool result = info->set_values & "(flags-for-field proto dbname).

(define flag-for-field (lambda proto_field
                         (match proto_field
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
(define fieldname (lambda proto_field
                    (match proto_field
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

(define (expr->stub proto expr expected-type)
  (let ((perform-op (lambda (op-name params)
                      (let* ((op (or (type:symbol->op op-name)
                                     (throw 'you-must-be-joking (simple-format #f "operator ~s?" op-name))))
                             (itypes  (type:op-itypes op))
                             (otype   (type:op-otype op)))
                        (simple-format #t "expr->stub of ~a outputing a ~a~%" op-name (type:type-name otype))
                        (type:check otype expected-type)
                        (if (not (eqv? (length itypes) (length params)))
                            (throw 'you-must-be-joking
                                   (simple-format #f "bad number of parameters for ~a: ~a instead of ~a" op-name (length params) (length itypes))))
                        (apply
                          (type:op-function op)
                          (map (lambda (p t) (expr->stub proto p t)) params itypes)))))
        (is-infix   (let ((prefix-chars (string->char-set "!@#$%^&*-+=|~/:><")))
                      (lambda (op)
                        (and (symbol? op)
                             (char-set-contains? prefix-chars (string-ref (symbol->string op) 0))
                             (false-if-exception (type:symbol->op op))))))
        (field->C   (lambda x
                      (match x
                             ; transform known cannonical fieldnames we must/want make friendlier
                             (('eth 'src)                                                      "addr[0]")
                             (('eth 'dst)                                                      "addr[1]")
                             (('ip 'src)                                                       "key.addr[0]")
                             (('ip 'dst)                                                       "key.addr[1]")
                             (('ip 'protocol)                                                  "key.protocol")
                             (('tcp 'src)                                                      "key.port[0]")
                             (('tcp 'dst)                                                      "key.port[1]")
                             (('udp 'src)                                                      "key.port[0]")
                             (('udp 'dst)                                                      "key.port[1]")
                             (('dns 'txid)                                                     "transaction_id")
                             (('dns 'class)                                                    "dns_class")
                             (('dns 'type)                                                     "request_type")
                             (('http 'error-code)                                              "code")
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
                             ((_ f) (type:string->C-ident (symbol->string f)))))))
    (cond
      ((list? expr)
       (match expr
              (()
               (throw 'you-must-be-joking "what's the empty list for?"))
              ; Try first to handle some few special forms
              (('set? f)
               (let* ((field (fieldname proto f))
                      (flag  (flag-for-field proto field)))
                 (if (not flag)
                     (throw 'you-must-be-joking (simple-format #f "field ~s in ~s is either always set or unknown" f proto)))
                 (ll:set? (type:string->C-ident (symbol->string proto))
                          (field->C proto field)
                          flag)))
              ((x 'as name)
               (let ((x-stub (expr->stub proto x expected-type)))
                 (or (symbol? name)
                     (throw 'you-must-be-joking (simple-format #f "register name must be a symbol not ~s" name)))
                 ((type:type-bind expected-type) (type:string->C-ident (symbol->string name)) x-stub)))
              ((and (v1 op-name v2) (? (lambda (expr) (is-infix (cadr expr)))))
               (perform-op op-name (list v1 v2)))
              ; Now that we have ruled out the empty list and special forms we must face an operator
              ((op-name . params)
               (perform-op op-name params))))
      ((boolean? expr)
       (type:check type:bool expected-type)
       ((type:type-imm type:bool) expr))
      ((number? expr)
       (type:check type:uint expected-type)
       ((type:type-imm type:uint) expr))
      ((string? expr)
       (type:check type:str expected-type)
       ((type:type-imm type:str) expr))
      ((symbol? expr)
       ; field names are spelled without percent sign prefix
       ; TODO: a way to have some precomputed, already available constants (for giving a name to some protocol constants)
       (let* ((str        (symbol->string expr))
              (is-regname (eqv? (string-ref str 0) #\%)))
         (if is-regname
             ((type:type-ref expected-type) (type:string->C-ident (substring str 1)))
             ; else we have to fetch this field from current proto
             ((type:type-fetch expected-type) (type:string->C-ident (symbol->string proto))
                                              (field->C proto (fieldname proto expr))))))
      (else
        (throw 'you-must-be-joking
               (simple-format #f "~a? you really mean it?" expr))))))

(export expr->stub)

;;; Also, for complete matches, transform this:
;;;
;;; '(("node1" . ((cap with (#f || $client-is-connected))
;;;               (next ip with (tos = 2))))
;;;   ("node2" . ...))
;;;
;;; into this:
;;;
;;; (("node1" .  ((next ip #t ((op-function =) ((type-fetch "ip" 'tos)) ((type-imm uint) 2)))
;;;               (next cap #f ((op-function log-or) ((type-imm bool) #f)
;;;                                                  ((type-ref bool) 'client-is-connected))))))
;;;  ("node2" . ...))
;;;
;;; note: then means skip-flag=#f, whereas next means skip-flag=#t.
;;; note: notice how we go from outer to inner proto (first->last) to last->first since
;;;       this is what we have. This implies that the first cap is allowed not to be
;;;       the outest protocol, contrary to what the expression specifies ("cap with...."
;;;       rather than "next cap with..."). Not a big deal in practice.

(define (test->ll-test test)
  (match test
         (('then proto 'with ex)
          `(,proto #f . ,(expr->stub proto ex type:bool)))
         (('then proto)
          `(,proto #f . ,(expr->stub proto #t type:bool)))
         ((proto 'with ex)
          `(,proto #t . ,(expr->stub proto ex type:bool)))
         ((proto)
          `(,proto #t . ,(expr->stub proto #t type:bool)))
         (('next proto 'with ex)
          `(,proto #t . ,(expr->stub proto ex type:bool)))
         (('next proto)
          `(,proto #t . ,(expr->stub proto #t type:bool)))
         (_
          (throw 'you-must-be-joking (simple-format #f "Cannot get my head around ~s" test)))))

(define (match->ll-match match)
  (let* ((patch-skip (lambda (test can-skip) ; as we revert the list of tests in a match, we have to propagate can-skip the other way around
                       `(,(ll:test-proto test)
                          ,can-skip .
                          ,(ll:test-expr test))))
         ; first compile each test into a ll-test and reverse the list
         (ll-match   (fold (lambda (test rev-list)
                             (cons (test->ll-test test) rev-list))
                           '()
                           match))
         ; then update the can-skip flags since we reverted the order of tests
         (ll-match   (map (lambda (test prev-skip)
                            `(,(ll:test-proto test)
                               ,prev-skip .
                               ,(ll:test-expr test)))
                          ll-match (cons #t (map ll:test-can-skip ll-match))))) ; FIXME: the inner specified proto is always allowed to not be the inner reported
    ll-match))

(define (matches->ll-matches matches)
  (map (lambda (r)
         (let ((n     (car r))
               (match (cdr r)))
           (cons n (match->ll-match match))))
       matches))

(define (make-so matches)
  (let ((ll-matches (matches->ll-matches matches)))
    (simple-format #t "~s~%translated into:~%~s~%" matches ll-matches)
    (ll:matches->so ll-matches)))

(export make-so)
