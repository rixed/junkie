#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(display "Testing runtime capture\n")

(define logfile "writer_check.log");
(false-if-exception (delete-file logfile))
(set-log-file logfile)
(set-log-level 7)

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
  (set-nb-digests 0)
  (set-nb-digests 100)
  ; play
  (open-pcap file)
  ; wait completion
  (while (not (null? (iface-names)))
         (usleep 100)))

(define (nb-pkts)
  (assq-ref (proto-stats "Capture") 'nb-frames))

(play "pcap/voip/sip_via.pcap")
(define nb-pkts1 (nb-pkts))
(simple-format #t "We had ~a packets~%" nb-pkts1)

;; Stop recording and replay the save file!
(capture-stop conf)
(play savefile)
(simple-format #t "We now have ~a packets~%" (nb-pkts))
(assert (eqv? (nb-pkts) (* 2 nb-pkts1)))

(delete-file savefile)

;; good enough!
(exit 0)
