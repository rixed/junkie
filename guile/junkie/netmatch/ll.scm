; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch ll))

;;; We generate untyped C from untyped s-expressions.
;;; Supposedly, the typing was already done before this step, and the operator used, for instance, correspond to the used values.

;;; (fetch field) -> returns the code that fetch the given field (given a proto and a layer)
;;; (imm value) -> returns the immediate value
;;; (binary-op operator value1 value2) -> returns the code that computes this
;;; (unary-op operator value) -> returns the code that computes that
;;; (bind name value) -> generate the code that memoize the given value in the given register
;;; (ref var) -> return the value of the given register
;;; (bind-unboxed name value) -> copy value, casted to intptr_t, into the register

(use-modules (ice-9 format)
             (ice-9 match)
             (srfi srfi-1))

; FIXME: instead of this, an alist of protos (records) giving the header name, the fields, etc...
(define *all-protos*
  '(cap eth ip gre arp udp icmp tcp sip bittorrent http rtp netbios ssl dns rtcp ftp mgcp sdp sql))

(define (headers-for proto-list)
  ; TODO : uniquifies then map to include stenzas
  proto-list)

(define C-header ; TODO: make this a function of the required protos?
  (let ((lines `("// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-\n" ; just in case someone is crazy enough to edit these
                 "// vim:sw=4 ts=4 sts=4 expandtab\n"
                 "#include <stdlib.h>\n"
                 "#include <stddef.h>\n"
                 "#include <assert.h>\n"
                 "#include <junkie/tools/netmatch.h>\n"
                 "#include <junkie/tools/miscmacs.h>\n"
                 "#include <junkie/proto/proto.h>\n"
                 ,@(map (lambda (proto) (string-append "#include <junkie/proto/" (symbol->string proto) ".h>\n")) (headers-for *all-protos*))
                 "\n")))
    (apply string-append lines)))

(define gensymC
  (let ((c 0))
    (lambda (prefix)
      (set! c (1+ c))
      (string-append "npc__" prefix (number->string c)))))

; Given an exprs and a hash of already existing varnames, extract the required bindings (ie. all that's bound).
; Note: If we ref something that's not defined then that will trigger a compile error which is fine.
;       We do not look for refs instead of binds because it's allowed to bind values without using them (these
;       migh be usefull for the actions we will be calling).
; Note that we dont care about type, how nice is that! :)
(define (extract-varnames-from expr varnames)
  ; Walk the expression looking for bindings
  (case (car expr)
    [(bind)      (begin
                   (display "Found a bind!\n")
                   (hash-set! varnames (cadr expr) #t)
                   (extract-varnames-from (caddr expr) varnames))]
    [(binary-op) (begin
                   (extract-varnames-from (caddr expr) varnames)
                   (extract-varnames-from (cadddr expr) varnames))]
    [(unary-op)  (extract-varnames-from (caddr expr) varnames)]))

; Return the code required to define all varnames used in the given list of test-exprs
(define (extract-varnames exprs)
  (let ((varnames (make-hash-table 11)))
    (let loop ((remaining-exprs exprs)
               (idx 0))
      (if (null? remaining-exprs)
          (hash-fold (lambda (varname dummy code)
                       ; note: struct npc_register { intptr_t value; size_t size; }
                       (string-append
                         code
                         "#define " varname " " idx "\n"))
                     (string-append
                       "/* Register definitions */\n\n")
                     varnames)
          (let ((expr (car remaining-exprs)))
            (extract-varnames-from expr varnames)
            (loop (cdr remaining-exprs) (1+ idx)))))))


; Some helpers to convert scheme values into C string values
(define (str->C value)
  (string-append "\"" value "\""))
(define (integer->C value)
  (format #f "~d" value))
(define (proto->C value) ; value is the name of the proto
  (string-append "proto_" value))
(define (operator->C operator)
  (symbol->string operator))

(define (imm->C value)
  (let ((res (cond
               ((string? value) (str->C value))
               ((number? value) (integer->C value)))))
    (cons "" res)))

; Here proto is a string (the name of proto, for junkie (ie. prepending "proto_" to it gives its struct proto,
; appending _proto_info gives the name of it's proto_info struct...).
; We can only fetch a field from the current layer (see binding of fields to register for refering to any past fields).
(define (fetch->C field current-proto current-info)
  (let* ((name (gensymC (string-append current-proto "_info")))
         (res  (gensymC (string-append field "_field"))))
    (cons (string-append
            "    struct " current-proto "_proto_info const *" name " = DOWNCAST(" current-info ", info, " current-proto "_proto_info);\n"
            "    typeof(" name "->" field ") " res " = " name "->" field ";\n")
          res)))

(define (ref->C varname regfile)
  (cons "" (string-append regfile "[" varname "].value")))

(define (bind->C varname value regfile)
  (cons (string-append
          "    if (" regfile "[" varname "].size != sizeof(*(" value "))) { // realloc\n"
          "        free(" regfile "[" varname "].value);\n"
          "        " regfile "[" varname "].value = malloc(sizeof(*(" value ")));\n"
          "        " regfile "[" varname "].size = sizeof(*(" value "));\n"
          "        assert(" regfile "[" varname "].value);\n"
          "    }\n"
          "    memcpy(" regfile "[" varname "].value, " value ", sizeof(*(" value ")));\n")
        (string-append regfile "[" varname "].value")))

(define (bind-unboxed->C varname value regfile)
  (cons (string-append
          "    assert(" regfile "[" varname "].size <= sizeof(intptr_t));\n" ; should not be necessary: perform type checks upfront!
          "    " regfile "[" varname "].value = (intptr_t)" value ";\n")
        (string-append regfile "[" varname "].value")))

; FIXME: we require a much more complex handling for some operators. For instance, logical operator (1||B must not eval B...), operators on complex types such as ip_addr...
(define (binary-op->C operator value1 value2)
  (let* ((res (gensymC "result")))
    (cons (string-append
            "    typeof(" value1 ") " res " = " value1 " " (operator->C operator) " " value2 ";\n")
          res)))

(define (unary-op->C operator value)
  (let* ((res (gensymC "result")))
    (cons (string-append
            "    typeof(" value ") " res " = " (operator->C operator) ";\n")
          res)))

; return the code and the result
(define (layer-test->C expr current-proto current-info current-regfile)
  (case (car expr)
    [(bind)      (let* ((value (layer-test->C (caddr expr) current-proto current-info current-regfile))
                        (ops   (bind->C (cadr expr) (cdr value) current-regfile)))
                   (cons (string-append (car value) (car ops))
                         (cdr ops)))]
    [(ref)       (ref->C (cadr expr) current-regfile)]
    [(imm)       (imm->C (cadr expr))]
    [(fetch)     (fetch->C (cadr expr) current-proto current-info)]
    [(binary-op) (let* ((left  (layer-test->C (caddr expr)  current-proto current-info current-regfile))
                        (right (layer-test->C (cadddr expr) current-proto current-info current-regfile))
                        (ops   (binary-op->C (cadr expr) (cdr left) (cdr right))))
                   (cons (string-append (car left)
                                        (car right)
                                        (car ops))
                         (cdr ops)))]
    [(unary-op)  (let* ((value (layer-test->C (caddr expr) current-proto current-info current-regfile))
                        (ops   (unary-op->C (cadr expr) (cdr value))))
                   (cons (string-append (car value)
                                        (car ops))
                         (cdr ops)))]
    [else (throw 'unknown-opcode (car expr))]))

; returns both the function definition and its name
(define (layer-test->function expr current-proto)
  (let ((res (gensymC "layer_test_fun"))
        (ops (layer-test->C expr current-proto "info" "regfile")))
    (cons
      (string-append
        "static bool " res "(struct proto_info const *info, struct npc_register *regfile)\n"
        "{\n" (car ops) "    return " (cdr ops) ";\n}\n\n")
      res)))

;;; Then, we want to look for the next protocol of a given type (optionaly skipping some)
;;; that satisfies some tests. We then have a full multilayer test, suitable for instance
;;; for a packet filter.

; takes the proto name, a flag telling if we are allowed to skip some layers, the name of
; the function performing the layer test, the name of the pointer to first proto_info;
; returns the code and the name of the variable storing the matching proto_info of NULL.
; Note that we match from first proto layer to last, using the next proto_info pointer to
; be defined (also usefull to have "nth next field" in addition to "nth last field".
(define (find-matching-proto->C proto can-skip test-function first-info regfile)
  (let ((res (gensymC "info")))
    (cons
      (string-append
        "    struct proto_info const *" res ";\n"
        "    for (" res " = " first-info "; " res "; " res " = " res "->next) {\n"
        "        if (! " res "->parser->proto != " proto ") continue;\n"
        "        if (" test-function "(" res ", " regfile ")) break;\n"
        (if (not can-skip)
            "        res = NULL;\n"
            "")
        "    }\n")
      res)))

; Given a list of tripplets (proto, can-skip, test-expr),
; returns the code of a function performing the test given the first proto_info, and the name of it.
(define (match->function tests)
  ; First output all the required functions to perform layer-tests
  (let* ((fun-name (gensymC "match_fun"))
         (code     (string-append
                     "/* These functions perform entry test for:\n"
                     "   " (simple-format #f "~s" tests) "\n"
                     "   See function " fun-name "\n"
                     " */\n\n"))
         (retests  (map (lambda (test)
                          (let* ((proto     (car test))
                                 (can-skip  (cadr test))
                                 (test-expr (caddr test))
                                 (ops       (layer-test->function test-expr proto))
                                 (new-code  (car ops))
                                 (test-fun  (cdr ops)))
                            (set! code (string-append code new-code))
                            (list proto can-skip test-fun)))
                        tests)))
    ; Now output the function we asked for
    (let loop ((remaining-tests retests)
               (first-unmatched "first")
               (code            (string-append
                                  code
                                  "static bool " fun-name "(struct proto_info const *first, struct npc_register *regfile)\n"
                                  "{\n")))
      (if (null? remaining-tests)
          (cons (string-append
                  code
                  "    return true;\n"
                  "}\n\n")
                fun-name)
          (let* ((test      (car remaining-tests))
                 (proto     (car test))
                 (can-skip  (cadr test))
                 (test-fun  (caddr test))
                 (match-one (find-matching-proto->C proto can-skip test-fun first-unmatched "regfile"))
                 (next-info (cdr match-one)))
            (loop (cdr remaining-tests)
                  next-info
                  (string-append
                    code
                    (car match-one)
                    "    if (! " next-info ") return false;\n")))))))

;;; Now we want to manage a FSM, where we have many 'walkers' going from one state to the next, either moving or being copied
;;; (note: when copying, the new walker have a pointer toward its ancestor, and every walker have a list of sons).
;;; In the starting state we have a single nul walker.
;;; A walker is:
;;;  - the state its in
;;;  - pointer to its parent
;;;  - list of its sons
;;;  - a regfile
;;; For each state, we have:
;;;  - a list of output transitions, a transition being: a match, a flag copy/move, a flag reapply, a flag grab, a dest state
;;;  - a list of actions to be performed on arrival (like, killing all walkers sharing a given ancestor)
;;; Note about flags:
;;;  When receiving a new event, we try all walkers in turn. When one match, we move/copy it.
;;;  Then, if reapply is set, we retry the same event on the new walker, until it stops moving.
;;;  Then, if grab is not set, we keep trying the event on following walkers.
;;;
;;; For this set of waiting walkers, we can have several indices (hash on some field of the regfile).
;;; Then, when we know we are going to perform a check on a varname then use the index to reduce the
;;; size of the possible set. But if the and function works properly (ie. not evaluating B in 0&&B)
;;; then this may not be required. Keep this for later then.
;;;
;;; !!! NOTE NOTE NOTE NOTE NOTE !!!
;;;
;;; Nothing in there requires to be dynamically generated!
;;; We may want to use this code generator to supply only a matcher, then the matcher is dynamically loaded
;;; and we make use of it in the FSM by using its match function alone. Except that we need to know the regfile
;;; structure for all used matches. So we need the code generator to build a single .so with all the matches,
;;; and then this .so will give us N match functions and a size for the regfile structure.
;;;
;;; So it's API is : match list -> matching-funs list * regfile size
;;; (yes the generator also compiles and loads the .so)
;;;
;;; If we have this then we can write a plugin for matching single events or a plugin for following dialogs.
;;; But what if we want to implement some indexes of walkers? This can be done before calling the matchers
;;; since the index can easily be build on any regfile structure, given the regfile is actually an array of npc_registers.
;;; (TODO: we should reflect this by having the code generator taking an array of N npc_registers as input
;;; instead of a struct npc_regfile. then the code generator would only need to #define VARNAME index into this array).

