; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch ll-compiler))

;;; We generate untyped C from untyped code stubs.
;;; Some type checking happened earlier, and more will happen when compiling the generated C code.

(use-modules (ice-9 format)
             (srfi srfi-1)
             ((junkie netmatch types) :renamer (symbol-prefix-proc 'type:))
             (junkie tools)
             (junkie instvars))

; FIXME: instead of this, an alist of protos (records) giving the header name, the fields, etc...
(define *all-protos*
  '(cap eth ip gre arp udp icmp tcp sip http rtp netbios dns rtcp ftp mgcp sdp cifs sql))

(define (headers-for proto-list)
  ; TODO : uniquifies then map to include stenzas
  proto-list)

(define C-header ; TODO: make this a function of the required protos?
  (let ((lines `("// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-\n" ; just in case someone is crazy enough to edit these
                 "// vim:sw=4 ts=4 sts=4 expandtab syntax=c filetype=c\n"
                 "#include <stdlib.h>\n"
                 "#include <stddef.h>\n"
                 "#include <stdbool.h>\n"
                 "#include <stdint.h>\n"
                 "#include <inttypes.h>\n"
                 "#include <assert.h>\n"
                 "#include <string.h>\n"
                 "#include <junkie/netmatch.h>\n"
                 "#include <junkie/tools/miscmacs.h>\n"
                 "#include <junkie/tools/ip_addr.h>\n"
                 "#include <junkie/tools/timeval.h>\n"
                 "#include <junkie/tools/hash.h>\n"
                 "#include <junkie/proto/proto.h>\n"
                 ,@(map (lambda (proto) (string-append "#include <junkie/proto/" (symbol->string proto) ".h>\n")) (headers-for *all-protos*))
                 "\n\n")))
    (apply string-append lines)))

; uniquify the given list (useful for regnames)
(define (uniquify lst)
  (let ((h (make-hash-table 11)))
    (for-each (lambda (v)
                (hash-set! h v #t))
              lst)
    (hash-fold (lambda (v dummy new-lst)
                 (cons v new-lst))
               '()
               h)))

; Return the the code required to define the given regnames
(define (extract-regnames regnames)
  (let ((idx 0))
    (string-append
      (fold (lambda (regname code)
              ; note: these are indexes into an array of struct npc_register { uintptr_t value; size_t size; }
              (let ((res (string-append
                           code
                           "#define nm_reg_" regname "__ " (number->string idx) "\n")))
                (set! idx (1+ idx))
                res))
            "/* Register definitions */\n\n"
            regnames)
      "unsigned nb_registers = " (number->string idx) "U;\n"
      "\n\n")))

; Given a stub, returns the complete C source code
(define (stub->C stub)
  (let* ((headers   C-header)
         (regnames  (extract-regnames (uniquify (type:stub-regnames stub)))))
    (string-append
      headers
      regnames
      (type:stub-code stub)
      "\n/* end */\n")))

; Given a stub, returns the name of the corresponding dynlib
(define (stub->so stub)
  (let* ((srcname     (string-copy "/tmp/netmatch-ll.c.XXXXXX"))
         (srcport     (mkstemp! srcname))
         (libname     (string-append srcname ".so"))
         (code        (stub->C stub)))
    (display code srcport)
    (close-port srcport)
    (let* ((cc       (or (getenv "NETMATCH_CC")       build-cc))
           (cppflags (or (getenv "NETMATCH_CPPFLAGS") (string-append build-cppflags " -I" includedir " -D_GNU_SOURCE")))
           (cflags   (or (getenv "NETMATCH_CFLAGS")   (string-append "-std=c99 " build-cflags)))
           (ldflags  (or (getenv "NETMATCH_LDFLAGS")  build-ldflags))
           (cmd      (string-append cc " " cppflags " " cflags " " ldflags " -fPIC -shared -o " libname " -xc " srcname))
           (status   (system cmd)))
      (if (eqv? 0 (status:exit-val status))
          (begin
            (delete-file srcname)
            libname)
          (throw 'compilation-error
                 (simple-format #f "Cannot exec ~s: exit-val=~s, term-sig=~s stop-sig=~s~%"
                                cmd
                                (status:exit-val status)
                                (status:term-sig status)
                                (status:stop-sig status)))))))

(export stub->so)

; some tools

(define (bool->C b)
  (if b "true" "false"))
(export bool->C)

(define (proto-code->C proto)
  (string-append "PROTO_CODE_" (string-upcase (symbol->string proto))))
(export proto-code->C)

