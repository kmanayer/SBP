;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
;; one idea is to router all malicious traffic through client via rogue browser plugin
;; another idea is rogue browser plugin, can they add a root CA?

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (answer cookie sskey login_info data) (c p name) (enc_cookie mesg))
    (trace
      ;; tls handshake with proxy (line 0-10 in diagram) is out of scope
      ;; assume both share a ltk that no other role can guess
      ;; all further communiation passes through SSL connection
      (send (ltk c p))
      (send (enc "login-request" login_info  (ltk c p)))
      (recv (enc "login-success" enc_cookie (ltk c p))) 
      (send enc_cookie) ;; to simulate leaking cookie
      ;;(send (enc "request" "malicious" enc_cookie (ltk c p))) ;; xss script sends this request
      (send (enc "request" enc_cookie (ltk c p))) ;; 
      (recv (enc "answer" answer enc_cookie (ltk c p))) ;; only clients can trigger release of answer
    )
    
  )
  
  (defrole proxy ;; encryption of cookie and communication with server are out of scope
    (vars (answer cookie sskey login_info data) (c p name) )
    (trace
      (recv (enc "login-request" login_info (ltk c p)))
      (send (enc "login-success" (enc cookie (hash (ltk c p) sskey)) (ltk c p)))
      (recv (enc "request" (enc cookie (hash (ltk c p) sskey)) (ltk c p))) ;; but to make this request, you need the tlskey,
      (send (enc "answer" answer (enc cookie (hash (ltk c p) sskey)) (ltk c p))) ;; only clients can trigger release of answer
    )
    (uniq-gen answer);; so network has to try to figure it out each time
    ;;(non-orig sskey);; kc = (hash (ltk c p) sskey)
  )

)



;; from the perspective of the client, with a listener for the answer
;; it probably will need the proxy cuz proxy has the answer
(defskeleton sbp
  (vars (answer data) (c p name))
  (defstrandmax client (answer answer) (c c) (p p))
  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  ;;(deflistener answer)
  ;;(non-orig (ltk c p)) 
  (uniq-gen (ltk c p)) ;; assume different for every client-proxy connection
)


