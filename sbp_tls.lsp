(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc id s cred request answer data) (enc_cookie mesg) (pk akey) (c p name))
    (trace
      (send cc)
      (recv (cat id pk))
      (send (enc s  pk))
      (recv (enc id (hash s cc id)))
      (send (enc cc (hash s cc id)))

      (send (enc (enc "login:" cred (privk c))                (hash s cc id)))
      (recv (enc "login-successful"               enc_cookie  (hash s cc id))) 

      (send (enc "request"                        enc_cookie  (hash s cc id))) 
      (recv (enc (enc "answer:" answer (privk p))              (hash s cc id)))
    )
    (uniq-gen cc)
    (uniq-gen s)
  )
  
  (defrole proxy
    (vars (cc id s cred cookie  answer sskey data) (c p name))
    (trace
      (recv cc)
      (send (cat id (pubk p)))
      (recv (enc s  (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (recv (enc (enc "login:" cred (privk c))                                               (hash s cc id)))
      (send (enc "login-successful"               (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))

      (recv (enc "request"                        (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (send (enc (enc "answer:" answer (privk p))                                            (hash s cc id)))
    )
    (uniq-gen id)
  )
)

(defskeleton sbp
  (vars (c p name))
  (defstrandmax client (c c) (p p))
  (non-orig (privk c))
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

