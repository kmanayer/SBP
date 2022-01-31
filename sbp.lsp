;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (answer cookie tlskey sskey data))
    (trace
      ;; tls handshake and client authentication with proxy is out of scope
  
      (recv (enc "response" (enc cookie sskey) tlskey)) ;; proxy is sharing cookie with client cuz client is nice
      (send (enc cookie sskey)) ;; client is dumb af and cookie is leaked
      (send (enc "request" (enc cookie sskey) tlskey)) ;; but to make this request, you need the tlskey,
      (recv (enc "sensitive" answer (enc cookie sskey) tlskey)) ;; only clients can trigger release of answer
    )
    
  )
  
  (defrole proxy ;; encryption of cookie and communication with server are out of scope
    (vars (answer cookie tlskey sskey data))
    (trace
      (send (enc "response" (enc cookie sskey) tlskey))
      (recv (enc "request" (enc cookie sskey) tlskey)) ;; but to make this request, you need the tlskey,
      (send (enc "sensitive" answer (enc cookie sskey) tlskey)) ;; only clients can trigger release of answer
    )
    (uniq-gen answer cookie) ;; so network has to try to figure it out each time
    (non-orig sskey)
  )
  
)

;; from the perspective of the client, with a listener for the answer
;; it probably will need the proxy cuz proxy has the answer
(defskeleton sbp
  (vars (answer tlskey data))
  (defstrandmax client (tlskey tlskey) (answer answer))
  (defstrandmax proxy  (tlskey tlskey) (answer answer))
  (deflistener answer)
  (pen-non-orig tlskey)
)
