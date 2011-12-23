; vim:syntax=scheme filetype=scheme expandtab
;; This module display a mere create/read/update/delete from functions manipulating
;; lists of vectors (so easily to mix with sqlite3 lib)

(define-module (junkie www crud))

(use-modules (ice-9 match)
             (sxml simple)
             (rnrs bytevectors)
             (rnrs records syntactic)
             (system vm program) ; for introspecting user functions
             (web uri)
             (rnrs lists)
             (junkie defs) ; for slog
             (junkie www server))

;;
;; Crudable are objects which we can create, read, update and delete.
;;
;; keys: a function returning the list of keys for this type
;; reader: a function that read all field for a key
;; writer: a function taking a key, a field name and a value and change this fieldname (must return the new value due to tablekit API)
;; creator: a function taking some parameters and returning nothing.
;;

(define-record-type crudable (fields name keys reader writer creator actions))
(export make-crudable)
(export crudable-name)

; We have a global registry of crudables so that we can retrieve them by name

(define crudables '())
(define (register-crudable crudable)
  (slog log-debug "new CRUDable ~s" crudable)
  (assert (crudable? crudable))
  (set! crudables (cons crudable crudables)))
(export crudables)

(export register-crudable)

(define (crudable-find name)
  (find (lambda (crudable)
          (string=? name (crudable-name crudable)))
        crudables))

;;
;; Then the editor itself
;;

(define creator-prefix "creator-param-")

(define (val->string v)
  (if (string? v) v (object->string v)))

; values must start with a non-editable key. writer-url should be an url or #f
; TODO: all numeric columns must have a min/max/sum/avg at the end
(define* (show-table vals heads name create-heads actions #:key writer-url creator-url actions-url)
  (slog log-debug "show-table with heads = ~s, vals = ~s, name = ~s and create-heads = ~s" heads vals name create-heads)
  ; later, put the two JS includes in the header, with a way to tell templatize that they are needed?
  `(,@(if heads
          `((script (@ (type . "text/javascript") (src . "http://ajax.googleapis.com/ajax/libs/prototype/1.6.0.2/prototype.js")) "")
            (script (@ (type . "text/javascript") (src . "http://millstream.com.au/upload/code/tablekit/js/tablekit.js")) "")
            (script (@ (type . "text/javascript"))
                    ,(string-append
                       "TableKit.options.editAjaxURI = '" (if writer-url writer-url "/crud/not_writable") "';\n"
                       "readonlyObject = function(name) { this.name = name; }\n"
                       "readonlyObject.prototype.edit = function(cell) { /* nop */ }\n"
                       "TableKit.Editable.addCellEditor(new readonlyObject('readonly'));\n"))
            (table (@ (id . ,(string-append "list_" name))
                      (class . "sortable resizable editable"))
                   (caption ,name)
                   (thead ,(if heads `(tr ,@(map (lambda (h)
                                                   `(th (@ (class . ,(if writer-url "" "readonly"))
                                                           (id . ,h))
                                                        ,h))
                                                 heads)
                                          ,(if (not (null? actions)) `(th "") '()))))
                   (tfoot ,(if heads `(tr ,@(map (lambda (h)
                                                   `(th ,h))
                                                 heads)
                                          ,(if (not (null? actions)) `(th "") '()))))
                   (tbody
                     ,@(map (lambda (l)
                              (let ((key  (car l))
                                    (vals (cdr l)))
                                `(tr (@ (id . ,key))
                                     (th ,(val->string key))
                                     ,@(map (lambda (v h)
                                              `(td ,(val->string v)))
                                            vals (cdr heads))
                                     ,(if (not (null? actions))
                                          `(th ,@(map (lambda (action)
                                                        (let ((label (car action)))
                                                          `(a (@ (href . ,(string-append actions-url "/" label "?key=" (uri-encode key)))
                                                                 (class . "editor_action"))
                                                              ,label)))
                                                      actions))
                                          '()))))
                            vals))))
          `((p (@ (class . "err")) ,(string-append "No " name " yet"))))
    ,(if creator-url
         `(form (@ (method . post)
                   (action . ,creator-url)
                   (id . ,(string-append "new_" name))
                   (class . "creator"))
                (table
                  (caption ,(string-append "New " name))
                  (tbody
                    ,@(map (lambda (h)
                             `(tr (th ,(string-append h ":"))
                                  (td (input (@ (name . ,(string-append creator-prefix h)))))))
                           create-heads)
                    (tr (th (@ (colspan . 2))
                            (input (@ (type . "submit") (value . "OK"))))))))
         '())))

(export show-table)

(define (pop l n)
  (cond
    ((eqv? 0 n) '())
    ((null? l)  '())
    (else       (cons (car l)
                      (pop (cdr l) (- n 1))))))

(define (fun-params fun)
  (let ((bindings (program-bindings fun))
        (arity    (arity:nreq (car (program-arities fun)))))
    (slog log-debug "bindings for this fun: ~s (taking the first ~a)" bindings arity)
    (map (lambda (binding)
           (val->string (binding:name binding)))
         (pop bindings arity))))

(define (show-crudable crudable)
  (let* ((name          (crudable-name crudable))
         (writer        (crudable-writer crudable))
         (creator       (crudable-creator crudable))
         (actions       (crudable-actions crudable))
         (heads         #f)
         (create-heads  (if creator (fun-params creator) '()))
         (alist->keys   (lambda (al) (map car al)))
         (alist->values (lambda (al) (map cdr al)))
         (vals          (map (lambda (key)
                               (let ((vals `((name . ,key) ,@((crudable-reader crudable) key))))
                                 (if (not heads)
                                     (set! heads (alist->keys vals)))
                                 (alist->values vals)))
                             ((crudable-keys crudable)))))
    (show-table vals heads name create-heads actions
                #:writer-url (and writer (string-append "/crud/write/" name))
                #:creator-url (and creator (string-append "/crud/new/" name))
                #:actions-url (string-append "/crud/action/" name))))

(export show-crudable)

(define (string-starts-with? str prefix)
  (string= str prefix 0 (string-length prefix)))

(define (crud-dispatch path params)
  (slog log-debug "CRUD dispatch for path ~s" path)
  (match path
         (("crud" "read" name)
          (let ((crudable (crudable-find name)))
            (if crudable
                (begin
                  (slog log-debug "Found a crudable named ~a" name)
                  (respond (show-crudable crudable)))
                (begin
                  (slog log-debug "No crudable named ~a" name)
                  (respond (error-page (simple-format #f "No such object ~a" name)))))))
          (("crud" "write" name)
           (let ((crudable (crudable-find name)))
             (if crudable
                 (let ((field (assq-ref params 'field))
                       (value (assq-ref params 'value))
                       (key   (assq-ref params 'id)))
                   (slog log-debug "Found a crudable named ~a" name)
                   (catch #t
                          (lambda ()
                            ((crudable-writer crudable) key field value)
                            (respond-raw (string->utf8 value)))
                          (lambda (key . args)
                            (slog log-err "Writting crudable ~s resulted in error ~s ~s" name key args)
                            (respond (error-page (simple-format #f "Error ~s ~s" key args))))))
                 (begin ; TODO: with-crudable-named name (lambda...)
                   (slog log-debug "No crudable named ~a" name)
                   (respond (error-page (simple-format #f "No such object ~a" name)))))))
          (("crud" "new" name)
           (let ((crudable (crudable-find name)))
             (if crudable
                 (let ((creator (crudable-creator crudable)))
                   (slog log-debug "Create new ~a" name)
                   (catch #t
                          (lambda ()
                            ; This works because the form entries are sent in order of apearance in the doc
                            (apply creator (map cdr (filter (lambda (p)
                                                              (string-starts-with? (val->string (car p)) creator-prefix))
                                                            params)))
                            (respond (show-crudable crudable)))
                          (lambda (key . args)
                            (slog log-err "Creating crudable resulted in error ~s ~s" key args)
                            (respond (error-page (simple-format #f "Error ~s ~s" key args))))))
                 (begin
                   (slog log-debug "No crudable named ~a" name)
                   (respond (error-page (simple-format #f "No such object ~a" name)))))))
          (("crud" "action" name action-label)
           (let ((crudable (crudable-find name)))
             (if crudable
                 (let* ((key        (assq-ref params 'key))
                        (actions    (crudable-actions crudable))
                        (action-fun (assoc-ref actions action-label)))
                   (slog log-debug "Perform ~a on ~a which key is ~s" action-label name key)
                   (catch #t
                          (lambda ()
                            ; action-fun is allowed to answer itself
                            (let ((res (action-fun key)))
                              (if (list? res)
                                  res
                                  (respond (show-crudable crudable)))))
                          (lambda (key . args)
                            (slog log-err "Performing ~a on crudable ~a resulted in error ~s ~s" action-label name key args)
                            (respond (error-page (simple-format #f "Error ~s ~s" key args))))))
                 (begin
                   (slog log-debug "No crudable named ~a" name)
                   (respond (error-page (simple-format #f "No such object ~a" name)))))))
          (_ #f)))

(export crud-dispatch)
