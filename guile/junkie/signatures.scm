; vim:filetype=scheme expandtab

(define-module (junkie signatures)
               #:use-module ((junkie netmatch netmatch)    :renamer (symbol-prefix-proc 'nm:))
               #:use-module ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:))
               #:use-module (junkie defs))

(let* ((stub (nm:function->stub type:bool '(tcp)
                                '(and (rest.cap-length >= 3)
                                      ((rest[2]) == 4)
                                      (((rest[0]) & #xc0) == #x40)
                                      (((((rest[0]) & #x3f) << 8) + (rest[1])) == rest.wire-length))))
       (flt  (ll:stub->so stub)))
  (add-proto-signature "SSLv2" 1 'medium flt)))

(let* ((stub (nm:function->stub type:bool '(tcp)
                                '(and (rest.cap-length >= 3)
                                      ((rest[0]) == 23)
                                      ((rest[1]) == 3)
                                      ((rest[2]) == 0))))
       (flt  (ll:stub->so stub)))
  (add-proto-signature "SSLv3" 2 'medium flt))

(let* ((stub (nm:function->stub type:bool '(tcp)
                                '(and (rest.cap-length >= 3)
                                      ((rest[0]) == 23)
                                      ((rest[1]) == 3)
                                      ((rest[2]) == 1))))
       (flt  (ll:stub->so stub)))
  (add-proto-signature "TLS" 3 'medium flt))

