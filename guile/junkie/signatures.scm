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

(add-proto-signature "TLS" 3 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 3)
                                              (or
                                                ((rest @ 0) == 22) ; handshake
                                                ((rest @ 0) == 23)) ; application data
                                              ((rest @ 1) == 3)
                                              (or
                                                ((rest @ 2) == 1) ; TLS v3.1
                                                ((rest @ 2) == 0))))) ; TLS v3.0

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
                                             ;(starts-with rest "USER ") conflicts with IRC
                                             (starts-with rest "FEAT ")
                                             (starts-with rest "OPTS "))))

; Discovery of SIP payload
(add-proto-signature "SIP" 9 'medium
                     (nm:compile
                       type:bool '(udp) '(or (starts-with rest "INVITE ")
                                             (starts-with rest "SIP/2.0")
                                             (starts-with rest "REGISTER ")
                                             (starts-with rest "ACK ")
                                             (starts-with rest "OPTIONS ")
                                             (starts-with rest "CANCEL "))))

; Discovery of MGCP payload
(add-proto-signature "MGCP" 10 'medium
                     (nm:compile
                       type:bool '(udp) '(or (starts-with rest "NTFY ")
                                             (starts-with rest "RQNT ")
                                             (starts-with rest "MDCX ")
                                             (starts-with rest "DLCX ")
                                             (starts-with rest "EPCF ")
                                             (starts-with rest "CRCX ")
                                             (starts-with rest "RSIP "))))

; Chat services
(add-proto-signature "IRC" 11 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 8)
                                              ((firsts 5 rest) == 4e,49,43,4b,20)))) ; "NICK "

(add-proto-signature "jabber" 12 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 14)
                                              ((firsts 14 rest) == 3c,73,74,72,65,61,6d,3a,73,74,72,65,61,6d))))


; Other, mostly windows related
(add-proto-signature "VNC" 13 'high
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 12)
                                              ((firsts 6 rest) == 52,46,42,20,30,30)
                                              ((rest @ 6) >= 49) ; from 1
                                              ((rest @ 6) <= 57) ; to 9
                                              ((rest @ 7) == 46) ; then .00
                                              ((rest @ 8) == 48)
                                              ((rest @ 9) == 48)
                                              ((rest @ 10) >= 48) ; then from 0
                                              ((rest @ 10) <= 57) ; to 9
                                              ((rest @ 11) == 10)))) ; then \n

(add-proto-signature "CIFS" 14 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 13)
                                              ((rest @ 0) == 0) ; NB session msg
                                              ((rest @ 4) == #xff)
                                              ((rest @ 5) == 83) ; S
                                              ((rest @ 6) == 77) ; M
                                              ((rest @ 7) == 66)))) ; B

(add-proto-signature "PCanywhere" 15 'medium
                     (nm:compile
                       type:bool '() '(and ((nb-bytes rest) == 2)
                                           (or ((firsts 2 rest) == 6e,71)
                                               ((firsts 2 rest) == 73,74)))))

(add-proto-signature "citrix" 16 'medium
                     (nm:compile
                       type:bool '() '(str-in-bytes rest "\x32\x26\x85\x92\x58")))

(add-proto-signature "telnet" 17 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 8)
                                              ((rest @ 0) == #xff)
                                              ((rest @ 1) >= #xfb)
                                              ((rest @ 1) <= #xfe)
                                              ((rest @ 3) == #xff)
                                              ((rest @ 4) >= #xfb)
                                              ((rest @ 4) <= #xfe)
                                              ((rest @ 6) == #xff)
                                              ((rest @ 7) >= #xfb)
                                              ((rest @ 7) <= #xfe))))

(add-proto-signature "BGP" 18 'medium
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 21)
                                              (starts-with rest "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff")
                                              (or (and ((rest @ 17) == 1)
                                                       ((rest @ 18) >= 3)
                                                       ((rest @ 18) <= 4))
                                                  (and ((rest @ 18) == 1)
                                                       ((rest @ 19) >= 3)
                                                       ((rest @ 19) <= 4))))))

(add-proto-signature "IMAP" 19 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 4)
                                              (starts-with rest "* OK"))))

(add-proto-signature "POP" 20 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) > 7)
                                              (starts-with rest "+OK POP"))))

(add-proto-signature "NTP" 21 'low
                     (nm:compile
                       type:bool '(udp) '(and ((nb-bytes rest) == 48)
                                              (or ((rest @ 0) == #x13)
                                                  ((rest @ 0) == #x14)
                                                  ((rest @ 0) == #x1b)
                                                  ((rest @ 0) == #x1c)
                                                  ((rest @ 0) == #x23)
                                                  ((rest @ 0) == #xd3)
                                                  ((rest @ 0) == #xdb)
                                                  ((rest @ 0) == #xe3)))))

(add-proto-signature "RDP" 22 'high
                     (nm:compile
                       type:bool '(tcp) '(and (str-in-bytes rest "rdpdr")
                                              (str-in-bytes rest "cliprdr"))))

