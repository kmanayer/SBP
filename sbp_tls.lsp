;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
;; one idea is to router all malicious traffic through client via rogue browser plugin
;; another idea is rogue browser plugin, can they add a root CA?

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc id s cred request answer data) (p name) (enc_cookie mesg))
    (trace

      (send cc)
      (recv id)
      (send (enc s (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (send (enc "login-request"   cred                  (hash s cc id)))
      (recv (enc "login-success"             enc_cookie  (hash s cc id))) 
      (send (enc "request"        request    enc_cookie  (hash s cc id))) 
      (recv (enc "answer"         answer                 (hash s cc id))) 
    )
    (uniq-gen cc)
    (uniq-gen s)

  )
  
  (defrole proxy ;; encryption of cookie and communication with server are out of scope
    (vars (cc id s cred cookie request answer sskey data) (p name))
    (trace
      (recv cc)
      (send id)
      (recv (enc s (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (recv (enc "login-request" cred                                                  (hash s cc id)))
      (send (enc "login-success"            (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (recv (enc "request"       request    (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (send (enc "answer"        answer     (enc cookie (hash sskey (hash s cc id)))   (hash s cc id))) 
    )
    (uniq-gen id)
    (uniq-gen cookie)
    (non-orig sskey)
    (non-orig (privk p))
    (uniq-orig answer)
  )

)



;; from the perspective of the client, with a listener for the answer
;; it probably will need the proxy cuz proxy has the answer
(defskeleton sbp
  (vars (answer data) (p name))
  (defstrandmax client (answer answer) (p p))
  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  ;;(deflistener answer)
  (non-orig (privk p))
  
)


