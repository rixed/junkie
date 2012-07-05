; vim:syntax=scheme filetype=scheme expandtab

(define-module (junkie netmatch nettrack))

(use-modules (ice-9 match)
             (junkie tools)
             (junkie runtime) ; for make-nettrack
             (junkie defs) ; for slog
             (srfi srfi-1)
             ((junkie netmatch netmatch)    :renamer (symbol-prefix-proc 'netmatch:))
             ((junkie netmatch types)       :renamer (symbol-prefix-proc 'type:)) ; for string->C-ident and friends
             ((junkie netmatch ll-compiler) :renamer (symbol-prefix-proc 'll:)))

;;; This takes a name and a nettrack expression with all tests developped, and returns:
;;; - the required shared object file name,
;;; - the required number of registers,
;;; - the nettrack graph SMOB object.
;;;
;;; For instance, let's consider this nettrack expression:
#;( ; register declarations (optional but recommended)
     [(http-status uint)
      (ip-client ip)
      (ip-server ip)
      (client-port uint)]
     ; vertices (notice that edges are filled with default attributes as required)
     [(http-answer
        (on-entry (pass "printf(\"%\"PRIuPTR\"\\n\", " http-status ");\n"))) ; an action to perform whenever the http-answer node is entered
      (web-syn
        (index-size 1024))]
     ; edges
     [(root web-syn
            (match (ip tcp) (do
                              (ip-client := ip.src)
                              (ip-server := ip.dst)
                              (client-port := tcp.src-port)
                              (tcp.syn && (tcp.dst-port == 80))))
            (dst-index-on () client-port)
            spawn)
      (web-syn http-answer
               (match (ip tcp http) (do
                                      (http-status := http.status)
                                      (and (ip.src == ip-server)
                                           (ip.dst == ip-client)
                                           (tcp.dst-port == client-port)
                                           (set? http.status))))
               (src-index-on (tcp) tcp.dst-port))])
;;; Notice that despite type inference we need to declare (some) registers since type inference is performed
;;; test after test. Even if type inference was done globally, such deep backtracking would lead to slow compilation,
;;; and thus the ability to make some types explicit would come handy nonetheless.
;;; For actions, here we use 'eval' with parameters of various types (eval is a special form which parameters are
;;; evaluated but not type checked, see netmatch.scm).
;;; We could also use 'call' which would call this function with given parameters (it's up to you (and ld) to
;;; ensure this call will eventually succeed). See netmatch.scm for these (and others) interesting special forms...
;;;
;;; We want to gather from this nettrack expression the list of matches:
;;; -> ((("root_2_web_syn" . ((ip with ....) (tcp with ...)))
;;;      ("web_syn_2_http_answer" . (...)))

; returns the stub for a given vertice
(define (vertex->stub vertice preamble defs)
  (match vertice
         [(name . cfgs)
          (let ((entry-func (type:make-stub "" "NULL" '()))
                (index-size 0)
                (timeout    1000000)) ; 1 second by default
            (for-each (lambda (cfg)
                        (match cfg
                               [('on-entry expr) ; FIXME: check we do not set this several times
                                (set! entry-func (netmatch:function->stub type:any '() expr #f))]
                               [('index-size sz) ; FIXME: idem
                                (set! index-size sz)]
                               [('timeout n)
                                (set! timeout n)]
                               [_ (throw 'you-must-be-joking cfg)]))
                      cfgs)
            (set! preamble
              (type:stub-concat
                preamble
                entry-func))
            (set! defs
              (type:stub-concat
                defs
                (type:make-stub
                  (string-append
                    "{\n"
                    "        .name = " (type:symbol->C-string name) ",\n"
                    "        .entry_fn = " (type:stub-result entry-func) ",\n"
                    "        .index_size = " (number->string index-size) ",\n"
                    "        .timeout = " (number->string timeout) "LL,\n"
                    "    }, ")
                  "" '()))))]
         [_ (throw 'you-must-be-joking (simple-format #f "can't understand vertice ~a" vertice))])
  (cons preamble defs))

(define (vertices->stub vertices)
  (slog log-debug "Nettrack compiling vertices ~s" vertices)
  (let ((nb-vertices (length vertices)))
    (match (fold (lambda (v prev)
                   (let ((preamble (car prev))
                         (defs     (cdr prev)))
                     (vertex->stub v preamble defs)))
                 (cons type:empty-stub ; empty preamble
                       (type:make-stub ; start of defs
                         (string-append
                           "struct nt_vertex_def vertice_defs[" (number->string nb-vertices) "] = {\n    ")
                         "" '()))
                 vertices)
           [(preamble . defs)
            (type:stub-concat
              preamble
              defs
              (type:make-stub
                (string-append
                  "\n};\n"
                  "unsigned nb_vertice_defs = " (number->string nb-vertices) ";\n\n")
                "vertice_defs" '()))])))

; returns the stub for a given edge
(define (edge->stub edge preamble defs)
  (match edge
         [(from to . cfgs)
          (let ((spawn          #f)
                (grab           #f)
                (min-age        0) ; minimal age (in usecs) to match this edge
                (proto-code     'cap) ; even when we have no actual match function we need to be called from time to time...
                (src-index-func (type:make-stub "" "NULL" '()))
                (dst-index-func (type:make-stub "" "NULL" '()))
                (match-func     (type:make-stub "" "NULL" '())))
            (for-each (lambda (cfg)
                        (match cfg
                               [('match protos expr)
                                (let ((protos (reverse protos)))
                                  (set! match-func (netmatch:function->stub type:bool protos expr #f))
                                  ; Would fail if no protos are given, since we use this to register a callback
                                  (if (not (null? protos))
                                      (set! proto-code (car protos))))]
                               [('older n)
                                (set! min-age n)]
                               [('src-index-on protos expr)
                                (set! src-index-func (netmatch:function->stub type:uint protos expr #f))]
                               [('dst-index-on protos expr)
                                (set! dst-index-func (netmatch:function->stub type:uint protos expr #f))]
                               ['spawn
                                (set! spawn #t)]
                               ['grab
                                (set! grab #t)]
                               [_ (throw 'you-must-be-joking cfg)]))
                      cfgs)
            (slog log-debug "Done, got proto-code = ~s (~s)" proto-code (ll:proto-code->C proto-code))
            (cons (type:stub-concat
                    preamble
                    src-index-func
                    dst-index-func
                    match-func) ; new preamble
                  (type:stub-concat defs ; new defs
                                    (type:make-stub
                                      (string-append
                                        "{\n"
                                        "        .match_fn = " (type:stub-result match-func) ",\n"
                                        "        .inner_proto = " (ll:proto-code->C proto-code) ",\n"
                                        "        .from_vertex = " (type:symbol->C-string from) ",\n"
                                        "        .to_vertex = " (type:symbol->C-string to) ",\n"
                                        "        .from_index_fn = " (type:stub-result src-index-func) ",\n"
                                        "        .to_index_fn = " (type:stub-result dst-index-func) ",\n"
                                        "        .min_age = " (number->string min-age) "LL,\n"
                                        "        .spawn = " (ll:bool->C spawn) ",\n"
                                        "        .grab = " (ll:bool->C grab) ",\n"
                                        "    }, ")
                                      "" '()))))]
         [_ (throw 'you-must-be-joking (simple-format #f "can't understand edge ~a" edge))]))

(define (edges->stub edges)
  (slog log-debug "Nettrack compiling edges ~s" edges)
  (let ((nb-edges (length edges)))
    (match (fold (lambda (v prev)
                   (let ((preamble (car prev))
                         (defs     (cdr prev)))
                     (edge->stub v preamble defs)))
                 (cons type:empty-stub ; empty preamble
                       (type:make-stub ; start of defs
                         (string-append
                           "struct nt_edge_def edge_defs[" (number->string nb-edges) "] = {\n    ")
                         "" '()))
                 edges)
           [(preamble . defs)
            (type:stub-concat
              preamble
              defs
              (type:make-stub
                (string-append
                  "\n};\n"
                  "unsigned nb_edge_defs = " (number->string nb-edges) ";\n\n")
                "edge_defs" '()))])))

; takes a nettrack expression and returns the nettrack SMOB
(define (compile name expr)
  (slog log-debug "Nettrack compiling expression ~s" expr)
  (netmatch:reset-register-types) ; since we are going to call test->ll-test (FIXME: test->ll-test is too much hassle just for obtaining the proto!)
  (let ((decls     (car expr)) ; some type declarations to preset some register types
        (vertices  (cadr expr))
        (edges     (caddr expr)))
    ; register the given register types
    (for-each
      (lambda (dec)
        (let ((regname  (car dec))
              (typename (cadr dec)))
          (netmatch:set-register-type
            (type:symbol->C-ident regname)
            (module-ref (resolve-module '(junkie netmatch types)) typename))))
      decls)
    (let* ((init (type:make-stub
                   "unsigned default_index_size = 1;\n\n" ; FIXME
                   "" '()))
           (v-stub (vertices->stub vertices))
           (e-stub (edges->stub edges))
           (stub   (type:stub-concat
                     init v-stub e-stub)))
      (make-nettrack name (ll:stub->so stub)))))

(export compile)
