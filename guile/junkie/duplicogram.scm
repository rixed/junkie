; vim:syntax=scheme filetype=scheme expandtab
;;; This module defines some web pages to handle captures online

(define-module (junkie duplicogram))

(use-modules (ice-9 match)
             (junkie defs)
             (junkie runtime)
             (junkie www server))


(define (register)
  (add-dispatcher
    (lambda (path params)
      (slog log-debug "Duplicodispatch for path ~s" path)
      (match path
             [("duplicogram" "home")
              (respond
                '((h1 "Duplicogram! Here I am!")))]
             [_ #f])))
  (add-menus "duplicogram" "/duplicogram/home"))

(export register)

