;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (answer cookie tlskey data))
    (trace
      ;; tls handshake and client authentication with proxy is out of scope
      (recv cookie) ;; cookie is leaked
      (send (enc "request" cookie tlskey)) ;; but no one can use the cookie except client instances
      (recv (enc "response" answer cookie tlskey)) ;; only clients can trigger release of answer
    )
  )
  
  (defrole proxy ;; encryption of cookie and communication with server are out of scope
    (vars (answer cookie tlskey data))
    (trace
      (send cookie)
      (recv (enc "request" cookie tlskey))
      (send (enc "response" answer cookie tlskey))
    )
    (uniq-gen answer)
  )
  
)

;; from the perspective of the client, with a listener for the answer
(defskeleton sbp
  (vars (answer tlskey data))
  (defstrandmax client (tlskey tlskey) (answer answer))
  (deflistener answer)
  (pen-non-orig tlskey)
)
