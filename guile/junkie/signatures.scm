; vim:filetype=scheme expandtab

(define-module (junkie signatures)
               #:use-module ((junkie netmatch netmatch)    :renamer (symbol-prefix-proc 'nm:))
               #:use-module ((junkie netmatch types)       :renamer (symbol-prefix-proc 'type:))
               #:use-module (junkie defs)
               #:use-module (junkie runtime))

(nm:reset-register-types)

(add-proto-signature "SSLv2" 1 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 3)
                                              ((rest @ 2) == 4)
                                              (((rest @ 0) & #xc0) == #x40)
                                              (((((rest @ 0) & #x3f) << 8) + (rest @ 1)) == (nb-bytes rest))))) ; FIXME: we'd rather compare with wire-length!

(add-proto-signature "SSLv3" 2 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 3)
                                              ((rest @ 0) == 23)
                                              ((rest @ 1) == 3)
                                              ((rest @ 2) == 0))))


(add-proto-signature "TLS" 3 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 3)
                                              ((rest @ 0) == 23)
                                              ((rest @ 1) == 3)
                                              ((rest @ 2) == 1))))

