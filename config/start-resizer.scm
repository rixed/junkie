; vim:syntax=scheme expandtab
;;; Source this file if you want to start a thread that will resize TCP and UDP muxer hashes automatically

(use-modules (ice-9 threads))

(if (not (defined? 'defs-loaded)) (load "defs.scm"))

; First the function that will limit UDP/TCP muxers to some hash size and collision rates
(define (resizer-thread)
  (let* ((min-collision-avg 4)
         (max-collision-avg 16)  ; make this higher if you want to give more CPU time to reclaim RAM
         (min-hash-size     5)
         (max-hash-size     353) ; so between two given hosts we can happily store 353*16*2=11k different sockets
         (limiter           (make-mux-hash-controller
                              min-collision-avg max-collision-avg min-hash-size max-hash-size))
         (period            60)) ; will resize every minute
    (set-thread-name "junkie-resizer")
    (let loop ()
      (sleep period)
      (limiter "TCP")
      (limiter "UDP")
      (loop))))

(make-thread resizer-thread)

