; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch compiler))

;;; We generate untyped C from untyped s-expressions.
;;; Supposedly, the typing was already done before this step, and the operators that are used correspond to the used values.

;;; (fetch field) -> returns the code that fetch the given field (given a proto and a layer)
;;; (imm value) -> returns the immediate value
;;; (binary-op operator value1 value2) -> returns the code that computes this
;;; (unary-op operator value) -> returns the code that computes that
;;; (bind name value) -> generate the code that memoize the given value in the given register
;;; (ref var) -> return the value of the given register
;;; (bind-unboxed name value) -> copy value, casted to intptr_t, into the register

(use-modules (ice-9 format)
             (srfi srfi-1)
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             (junkie tools))

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
                 "#include <stdbool.h>\n"
                 "#include <stdint.h>\n"
                 "#include <assert.h>\n"
                 "#include <junkie/tools/netmatch.h>\n"
                 "#include <junkie/tools/miscmacs.h>\n"
                 "#include <junkie/proto/proto.h>\n"
                 ,@(map (lambda (proto) (string-append "#include <junkie/proto/" (symbol->string proto) ".h>\n")) (headers-for *all-protos*))
                 "\n\n")))
    (apply string-append lines)))

;;; A match being a list of triplets (proto can-skip . test-expr):

(define match-proto car)
(define match-can-skip cadr)
(define match-test cddr)

;;; A test expression (or merely test) is any (untyped!) scheme expression returning a code stub.

; Given a test and a hash of already existing varnames, extract the required bindings (ie. all  that's bound).
; Note: If we ref something that's not defined then that will trigger a compile error which is fine.
;       We do not look for refs instead of binds because it's allowed to bind values without using them (these
;       migh be usefull for the actions we will be calling).
; Note that we dont care about type, how nice is that! :)

; Return the code required to define all regnames used in the given stub and the number of regnames
(define (extract-regnames stub)
  (let ((regnames-h (make-hash-table 11))
        (idx        0))
    (foreach (lambda (regname)
               (hash-set! regnames-h regname #t))
             (type:stub-regnames stub))
    (cons
      (string-append
        (hash-fold (lambda (regname dummy code)
                     ; note: these are indexes into an array of struct npc_register { intptr_t value; size_t size; }
                     (let ((res (string-append
                                  code
                                  "#define " regname " " (number->string idx) "\n")))
                       (set! idx (1+ idx))
                       res))
                   "/* Register definitions */\n\n"
                   regnames-h)
        "\n\n")
      idx)))

; given the stub for a test, return the stub for a function performing the test given the current info and regfile
(define (test->function test proto)
  (let ((res (gensymC "test_fun")))
    (type:make-stub
      (string-append
        "static bool " res "(struct proto_info const *info, struct npc_register *regfile)\n"
        "{\n"
        (type:stub-code test)
        "    return " (type:stub-result test) ";\n}\n\n")
      res
      (type:stub-regnames test))))

;;; Then, we want to look for the next protocol of a given type (optionaly skipping some)
;;; that satisfies some tests. We then have a full multilayer test, suitable for instance
;;; for a packet filter.

; takes the proto name, a flag telling if we are allowed to skip some layers, the name of
; the function performing the layer test.
; returns the code and the name of the variable storing the matching proto_info of NULL.
; Note that we match from first proto layer to last, using the next proto_info pointer to
; be defined (also usefull to have "nth next field" in addition to "nth last field".
(define (find-next-matching-proto proto can-skip test)
  (let ((res (gensymC "info")))
    (type:make-stub
      (string-append
        "    struct proto_info const *" res ";\n"
        "    for (" res " = info; " res "; " res " = " res "->next) {\n"
        "        if (! " res "->parser->proto != proto_" proto ") continue;\n"
        "        if (" (type:stub-result test) "(" res ", " regfile ")) break;\n"
        (if (not can-skip)
            "        res = NULL;\n"
            "")
        "    }\n")
      res
      (type:stub-regnames test))))

; Given a list of triplets (proto can-skip . test-expr),
; returns the stub for a function performing the test given the first proto_info, and the name of it.
(define (match->stub tests)
  ; First output all the required functions to perform layer-tests
  (let* ((fun-name (gensymC "match"))
         (code     (string-append
                     "/* These functions perform entry test for:\n"
                     "   " (simple-format #f "~s" tests) "\n"
                     "   See function " fun-name "\n"
                     " */\n\n")))
    (let loop ((remaining-tests tests)
               (first-unmatched "first")
               (code            (string-append
                                  code
                                  "static bool " fun-name "(struct proto_info const *info, struct npc_register *regfile)\n"
                                  "{\n"))
               (regnames '()))
      (if (null? remaining-tests)
          (type:make-stub
            (string-append
              code
              "    return true;\n"
              "}\n\n")
            fun-name
            regnames)
          (let* ((test      (car remaining-tests))
                 (proto     (match-proto test))
                 (can-skip  (match-can-skip test))
                 (test-expr (match-test test))
                 (match-one (find-next-matching-proto proto can-skip test-expr))
                 (next-info (type:stub-result match-one)))
            (loop (cdr remaining-tests)
                  next-info
                  (string-append
                    code
                    (type:stub-code match-one)
                    "    if (! " next-info ") return false;\n")
                  (append (type:stub-regnames match-one) regnames)))))))

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
;;; For this set of waiting walkers, we can have several indexes (hash on some field of the regfile).
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

; Given an alist of name->matches (a match being a list of triplets (proto, can-skip, test-expr)),
; return the code of all matching functions, as well as the length of the npc_register array.
(define (matches->stub matches)
  (let* ((headers   C-header)
         (functions (fold (lambda (entry prev)
                            (let* ((match-name (car entry))
                                   (match      (cdr entry))
                                   (stub       (match->stub match)))
                              (type:make-stub
                                (string-append
                                  (type:stub-code prev)
                                  (type:stub-code stub)
                                  "bool " match-name "(struct proto_info const *info, struct npc_register *regfile)\n"
                                  "{\n"
                                  "    return " (type:stub-result stub) "(info, regfile);\n"
                                  "}\n\n")
                                match-name
                                (append (type:stub-regnames stub) (type:stub-regnames prev)))))
                          (type:make-stub "/* Functions */\n\n" "" '())
                          matches))
         (tmp       (extract-regnames functions))
         (regnames  (car tmp))
         (nb-regs   (cdr tmp)))
    (cons (string-append headers regnames functions "/* end */")
          nb-regs)))

(export matches->stub)

; Given an alist of name->matches, return the name of the dynlib containing the required functions, and the length of the regfile
(define (matches->so matches)
  (let* ((srcname     (string-copy "/tmp/netmatch-ll.c.XXXXXX"))
         (libname     (string-copy "/tmp/netmatch-ll.so.XXXXXX"))
         (srcport     (mkstemp! srcname))
         (tmp         (matches->C matches))
         (code        (car tmp))
         (nb-varnames (cdr tmp)))
    (display code srcport)
    (close-port srcport)
    (let* ((cc       (or (getenv "CC")      "gcc")) ; FIXME: insert here the CC used to compile junkie?
           (cppflags (or (getenv "CPPFLAGS") "")) ; FIXME: insert here the cppflags used to compile junkie?
           (cflags   (or (getenv "CFLAGS")   "-std=c99 -O0 -ggdb3 -D_GNU_SOURCE")) ; FIXME: you got it
           (ldflags  (or (getenv "LDFLAGS")  ""))
           (cmd      (string-append cc " " cppflags " " cflags " " ldflags " -o " libname " -xc " srcname))
           (status   (system cmd)))
      (if (eqv? 0 (status:exit-val status))
          (begin
            (delete-file srcname)
            (cons libname nb-varnames))
          (begin
            (simple-format
              (current-error-port) "Cannot exec ~s: exit-val=~s, term-sig=~s stop-sig=~s~%"
              cmd
              (status:exit-val status)
              (status:term-sig status)
              (status:stop-sig status))
            #f)))))

(export matches->so)
