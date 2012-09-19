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
                                              (or
                                                ((rest @ 0) == 22) ; handshake
                                                ((rest @ 0) == 23)) ; application data
                                              ((rest @ 1) == 3)
                                              ((rest @ 2) == 0))))


(add-proto-signature "TLS" 3 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 3)
                                              (or
                                                ((rest @ 0) == 22) ; handshake
                                                ((rest @ 0) == 23)) ; application data
                                              ((rest @ 1) == 3)
                                              ((rest @ 2) == 1))))

(add-proto-signature "bittorrent" 4 'medium
                     (nm:compile
                       type:bool '(tcp) '(or
                                           (and ((nb-bytes rest) >= 6)
                                                ((firsts 6 rest) == 00,00,00,0d,06,00))
                                           (and ((nb-bytes rest) >= 8)
                                                ((firsts 8 rest) == 00,00,40,09,07,00,00,00))
                                           (str-in-bytes rest "BitTorrent Protocol")
                                           (str-in-bytes rest "/announce"))))

; Adapted from http://protocolinfo.org/

; Small tool to convert string to bytes:
; (define (string->numbers s) (map char->integer (string->list s)))
; (define (string->hexstr s) (string-join (map (lambda (n) (format #f "~2,'0x" n)) (string->numbers s)) ",") )

(add-proto-signature "gnutella" 5 'low ; until proven otherwise
                     (nm:compile
                       type:bool '(tcp) '(or
                                           (and ((nb-bytes rest) >= 4)
                                                ((firsts 3 rest) == 67,6e,64)
                                                (or ((rest @ 3) == 1)
                                                    ((rest @ 3) == 2)))
                                           (and ((nb-bytes rest) >= 22)
                                                ; "gnutella connect/[012]\.[0-9]\x0d\x0a"
                                                ((firsts 17 rest) == 67,6e,75,74,65,6c,6c,61,20,63,6f,6e,6e,65,63,74,2f)
                                                ((rest @ 17) >= 48)
                                                ((rest @ 17) <= 50)
                                                ((rest @ 19) >= 48)
                                                ((rest @ 19) <= 57)
                                                ((rest @ 20) == 13)
                                                ((rest @ 21) == 10))
                                           (and ((nb-bytes rest) >= 26)
                                                ; "get /uri-res/n2r\?urn:sha1:"
                                                ((firsts 26 rest) == 67,65,74,20,2f,75,72,69,2d,72,65,73,2f,6e,32,72,3f,75,72,6e,3a,73,68,61,31,3a))
                                           (and ((nb-bytes rest) >= 44)
                                                ; gnutella.*content-type: application/x-gnutella
                                                ((firsts 8 rest) == 67,6e,75,74,65,6c,6c,61)
                                                (str-in-bytes rest "content-type: application/x-gnutella"))
                                           (and ((nb-bytes rest) >= 5)
                                                ((firsts 5 rest) == 67,65,74,20,2f)
                                                (or (str-in-bytes rest "content-type: application/x-gnutella-packets")
                                                    (str-in-bytes rest "user-agent: gtk-gnutella")
                                                    (str-in-bytes rest "user-agent: bearshare")
                                                    (str-in-bytes rest "user-agent: mactella")
                                                    (str-in-bytes rest "user-agent: gnucleus")
                                                    (str-in-bytes rest "user-agent: gnotella")
                                                    (str-in-bytes rest "user-agent: limewire")
                                                    (str-in-bytes rest "user-agent: imesh"))))))

(add-proto-signature "RTP" 6 'medium
                     (nm:compile
                       type:bool '(udp) '(and ((udp.src-port & 1) == 0)
                                              ((udp.dst-port & 1) == 0)
                                              ; ^\x80[\x01-"`-\x7f\x80-\xa2\xe0-\xff]?..........*\x80
                                              ((nb-bytes rest) >= 11)
                                              ((rest @ 0) == #x80)))) ; the rest does not worth the trouble

; Discovery of HTTP payload
(add-proto-signature "HTTP" 7 'medium
                     (nm:compile
                       type:bool '(tcp) '(or (starts-with rest "HTTP/1")
                                             (starts-with rest "GET ")
                                             (starts-with rest "HEAD ")
                                             (starts-with rest "POST ")
                                             (starts-with rest "CONNECT ")
                                             (starts-with rest "PUT ")
                                             (starts-with rest "OPTIONS ")
                                             (starts-with rest "TRACE ")
                                             (starts-with rest "DELETE "))))

; Discovery of FTP payload
(add-proto-signature "FTP" 8 'medium
                     (nm:compile
                       type:bool '(tcp) '(or (starts-with rest "220-")
                                             (starts-with rest "220 ")
                                             (starts-with rest "USER ")
                                             (starts-with rest "FEAT ")
                                             (starts-with rest "OPTS "))))

