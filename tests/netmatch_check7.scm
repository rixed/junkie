#!../src/junkie -c
; vim:syntax=scheme expandtab
!#

(load "netmatch_check_lib.scm")
(use-modules (check))

; Test timeout function is actually called

(test "Timeout function"
      '([]
        [(node
           ; This test do not prove much, since the timeout is called at the end
           ; like all on-timeout functions are - our pcap is too short to trigger
           ; a timeout (even a 1us timeout as here), and even if it were lasting
           ; longer timeouting is not performed comprehensively, so is never
           ; guaranteed to happen in a short time scale.
           (timeout 1)
           (on-timeout (apply (check) incr-called)))]
        [(root node
           (match (http) ((set? http.error-code) && (http.error-code == 400))) ; we've got only one errcode 400
           spawn)
         ; add an edge from node so that it's kept
         (node node
            (match (http) ((set? http.error-code) && (http.error-code == 666))))]))

(assert (= called 1))

;; good enough!
(exit 0)
