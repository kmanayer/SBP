(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc id s cred request answer data) (pk akey) (enc_cookie mesg) (p name))
    (trace
      (send cc)
      (recv (cat id pk))
      (send (enc s  pk))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))
      (send (enc "login-request"   cred                  (hash s cc id)))
      (recv (enc "login-success"             enc_cookie  (hash s cc id))) 
      (send (enc "request"        request    enc_cookie  (hash s cc id))) 
      (recv (enc  (enc "answer" (privk p))   enc_cookie  (hash s cc id)))
    )
  )
  
  (defrole proxy
    (vars (cc id s cred cookie request answer sskey data) (pk akey) (p name))
    (trace
      (recv cc)
      (send (cat id pk))
      (recv (enc s  pk))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (recv (enc "login-request" cred                                                  (hash s cc id)))
      (send (enc "login-success"            (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (recv (enc "request"       request    (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (send (enc (enc "answer" (privk p))   (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
    )
  )

)

(defskeleton sbp
  (vars (cc id s cred cookie request answer data) (pk akey) (p name))
  (defstrandmax client (cc cc) (id id) (s s) (pk pk) (p p))
  (uniq-gen cc)
  (uniq-gen s)
  (non-orig (privk p))
)

  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  ;;(deflistener answer)
  ;;(uniq-gen id)
  ;;(non-orig (invk pk))
  ;;(uniq-gen cookie)
  ;;(non-orig sskey)
  ;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
  ;; one idea is to router all malicious traffic through client via rogue browser plugin
  ;; another idea is rogue browser plugin, can they add a root CA?

