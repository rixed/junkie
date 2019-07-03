#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing runtime capture\n")

(define logfile "writer_check.log");
(false-if-exception (delete-file logfile))
(set-log-file logfile)
(set-log-level 7)
(set-log-level 3 "mutex")

(set-quit-when-done #f)

;; Load the writer plugin and configure a capture
(load-plugin "../plugins/writer/.libs/writer.so")
(define savefile (tmpnam))
(define conf (make-capture-conf savefile 'pcap))
(capture-start conf)

;; Read a pcap
(define (play file)
  (simple-format #t "Playing ~a~%" file)
  ; reset dedup
  (reset-digests)
  ; play
  (open-pcap file)
  ; wait completion
  (while (not (null? (iface-names)))
         (usleep 100)))

(define (num-pkts)
  (assq-ref (proto-stats "Capture") 'num-frames))

(play (string-append (getenv "srcdir") "/pcap/voip/sip_via.pcap"))
(define num-pkts1 (num-pkts))
(simple-format #t "We had ~a packets~%" num-pkts1)

;; Stop recording and replay the save file!
(capture-stop conf)
(play savefile)
(simple-format #t "We now have ~a packets~%" (num-pkts))
(assert (eqv? (num-pkts) (* 2 num-pkts1)))

(delete-file savefile)

;; good enough!
(exit 0)
