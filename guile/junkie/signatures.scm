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

(add-proto-signature "Bittorrent" 4 'medium
                     (nm:compile
                       type:bool '(tcp) '(or
                                           (and ((nb-bytes rest) >= 6)
                                                ((firsts 6 rest) == #(#x00 #x00 #x00 #x0d #x06 #x00)))
                                           (and ((nb-bytes rest) >= 8)
                                                ((firsts 8 rest) == #(#x00 #x00 #x40 #x09 #x07 #x00 #x00 #x00)))
                                           (str-in-bytes rest "BitTorrent Protocol")
                                           (str-in-bytes rest "/announce"))))

; Adapted from http://protocolinfo.org/

; Small tool to convert string to bytes:
; (define (string->numbers s) (map char->integer (string->list s)))
; (define (string->bytes s) (list->vector (string->numbers s)))

(add-proto-signature "Gnutella" 5 'low ; until proven otherwise
                     (nm:compile
                       type:bool '(tcp) '(or
                                           (and ((nb-bytes rest) >= 4)
                                                ((firsts 3 rest) == #(#x67 #x6e #x64))
                                                (or ((rest @ 3) == 1)
                                                    ((rest @ 3) == 2)))
                                           (and ((nb-bytes rest) >= 22)
                                                ; "gnutella connect/[012]\.[0-9]\x0d\x0a"
                                                ((firsts 17 rest) == #(#x67 #x6e #x75 #x74 #x65 #x6c #x6c #x61 #x20 #x63 #x6f #x6e #x6e #x65 #x63 #x74 #x2f))
                                                ((rest @ 17) >= 48)
                                                ((rest @ 17) <= 50)
                                                ((rest @ 19) >= 48)
                                                ((rest @ 19) <= 57)
                                                ((rest @ 20) == 13)
                                                ((rest @ 21) == 10))
                                           (and ((nb-bytes rest) >= 26)
                                                ; "get /uri-res/n2r\?urn:sha1:"
                                                ((firsts 26 rest) == #(#x67 #x65 #x74 #x20 #x2f #x75 #x72 #x69 #x2d #x72 #x65 #x73 #x2f #x6e #x32 #x72 #x3f #x75 #x72 #x6e #x3a #x73 #x68 #x61 #x31 #x3a)))
                                           (and ((nb-bytes rest) >= 44)
                                                ; gnutella.*content-type: application/x-gnutella
                                                ((firsts 8 rest) == #(#x67 #x6e #x75 #x74 #x65 #x6c #x6c #x61))
                                                (str-in-bytes rest "content-type: application/x-gnutella"))
                                           (and ((nb-bytes rest) >= 5)
                                                ((firsts 5 rest) == #(#x67 #x65 #x74 #x20 #x2f))
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
                       type:bool '(tcp) '(or ;(starts-with rest "220-") conflicts with SMTP
                                             ;(starts-with rest "220 ")
                                             ;(starts-with rest "USER ") conflicts with IRC
                                             (starts-with rest "PASV ")
                                             (starts-with rest "RETR ")
                                             (starts-with rest "STOR ")
                                             (starts-with rest "STOU ")
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
                                              ((firsts 5 rest) == #(#x4e #x49 #x43 #x4b #x20))))) ; "NICK "

(add-proto-signature "Jabber" 12 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 14)
                                              ((firsts 14 rest) == #(#x3c #x73 #x74 #x72 #x65 #x61 #x6d #x3a #x73 #x74 #x72 #x65 #x61 #x6d)))))


; Other, mostly windows related
(add-proto-signature "VNC" 13 'high
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 12)
                                              ((firsts 6 rest) == #(#x52 #x46 #x42 #x20 #x30 #x30))
                                              ((rest @ 6) >= 49) ; from 1
                                              ((rest @ 6) <= 57) ; to 9
                                              ((rest @ 7) == 46) ; then .00
                                              ((rest @ 8) == 48)
                                              ((rest @ 9) == 48)
                                              ((rest @ 10) >= 48) ; then from 0
                                              ((rest @ 10) <= 57) ; to 9
                                              ((rest @ 11) == 10)))) ; then \n

; Detection of Netbios session for smb over tcp
(add-proto-signature "Netbios" 14 'low
                     (nm:compile
                       type:bool '(tcp) '(and ((nb-bytes rest) >= 36)
                                              ((rest @ 0) == #x00)
                                              ((rest @ 4) == #xff)
                                              ((rest @ 5) == #x53) ; S
                                              ((rest @ 6) == #x4d) ; M
                                              ((rest @ 7) == #x42)))) ; B

(add-proto-signature "PCanywhere" 15 'medium
                     (nm:compile
                       type:bool '() '(and ((nb-bytes rest) == 2)
                                           (or ((firsts 2 rest) == #(#x6e #x71))
                                               ((firsts 2 rest) == #(#x73 #x74))))))

(add-proto-signature "Citrix" 16 'medium
                     (nm:compile
                       type:bool '() '(str-in-bytes rest "\x32\x26\x85\x92\x58")))

(add-proto-signature "Telnet" 17 'low
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

(add-proto-signature "DNS" 23 'medium
                     (nm:compile
                       type:bool '(udp) '(do
                                           (endname := (index-of-bytes rest #(0 0) 12 250 999)) ; Search for the end of a qname and the begin of the dns type
                                         (and
                                           (endname != 999) ; a bytes #(0 0) has been found
                                           ((rest @ 4) == #x00) ; Check that number of questions is < 255
                                           ((rest @ 6) == #x00) ; Check that number of answers is < 255
                                           ((rest @ 8) == #x00) ; Check that number of authority RR is < 255
                                           ((rest @ 10) == #x00) ; Check that number of additional RR is < 255
                                           ((nb-bytes rest) > (endname + 2)) ; Check that we have place for a dns type after
                                           (or
                                             (and
                                               ((rest @ (endname + 2) ) >= 1)
                                               ((rest @ (endname + 2) ) <= 16))
                                             ((rest @ (endname + 2) ) == #x1c)
                                             ((rest @ (endname + 2) ) == #x20)
                                             ((rest @ (endname + 2) ) == #x21)
                                             ((rest @ (endname + 2) ) == #x26)
                                             ((rest @ (endname + 2) ) == #xfb)
                                             ((rest @ (endname + 2) ) == #xfc)
                                             ((rest @ (endname + 2) ) == #xff))))))

; Discovery of SMTP payload
(add-proto-signature "SMTP" 24 'medium
                     (nm:compile
                       type:bool '(tcp) '(or (and (rel-seq-num == 0)
                                                  (or (starts-with rest "HELO ")
                                                      (starts-with rest "EHLO ")))
                                             (starts-with rest "MAIL FROM:")
                                             (starts-with rest "RCPT TO:")
                                             (starts-with rest "VRFY "))))


; Sql signatures
(add-proto-signature "TNS" 25 'medium
                     (nm:compile
                       type:bool '(tcp) '(and
                                           ((nb-bytes rest) >= 8)
                                           ((rest @16n 0) <= (payload)) ; Check length
                                           ((rest @16n 2) == 0) ; Checksum is generally to 0...
                                           ((rest @ 4) >= #x01) ; Check data type
                                           ((rest @ 4) <= #x0f)
                                           ((rest @ 5) == 0) ; Reserved byte is 0
                                           ((rest @16n 6) == 0)))) ; Another checksum at 0...


(add-proto-signature "PostgreSQL" 26 'medium
                     (nm:compile
                       type:bool '(tcp) '(and
                                           ((nb-bytes rest) >= 8)
                                           (or
                                             ; Check for startup
                                             (and
                                               ((rest @32n 0) == (payload)) ; Check length
                                               ((rest @32n 4) == #x30000)) ; Check protocol version
                                             ; Check for ssl request
                                             (and
                                               ((rest @32n 0) == 8)
                                               ((rest @32n 4) == 80877103)))))) ; Check ssl magic value

; TODO add smp detection
(add-proto-signature "TDS" 27 'medium
                     (nm:compile
                       type:bool '(tcp) '(and
                                           ((nb-bytes rest) >= 8) ; Header length
                                           (or
                                             (and ((rest @ 0) >= 1) ((rest @ 0) <= 4))   ; Batch, Login, Rpc, Result
                                             ((rest @ 0) == 6)                           ; Attention
                                             ((rest @ 0) == 7)                           ; Bulk load
                                             ((rest @ 0) == 14)                          ; Manager Req
                                             (and ((rest @ 0) >= 16) ((rest @ 0) <= 18))); Login, Sspi, Pre login
                                           ((rest @16n 2) == (payload)) ; Check length
                                           ((rest @16n 4) < 100) ; Channel number should not be too high...
                                           ((rest @ 6) < 10)))) ; Packet number should not be too high

