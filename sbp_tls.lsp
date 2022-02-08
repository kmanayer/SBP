(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc id s cred request answer data) (enc_cookie mesg) (p name))
    (trace
      (send cc)
      (recv (cat id (pubk p)))
      (send (enc s  (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (send (enc "login-request" cred                                    (hash s cc id)))
      (recv (enc "login-success"                             enc_cookie  (hash s cc id)))
      (send (enc "embedded link w/ malicious request"        enc_cookie  (hash s cc id))) 
      (send (enc "actual post"                               enc_cookie  (hash s cc id))) 
      (recv (enc (enc "answer" answer (privk p))                         (hash s cc id)))
    )
  )
  
  (defrole proxy
    (vars (cc id s cred cookie request answer sskey data) (p name) (msg mesg))
    (trace
      (recv cc)
      (send (cat id (pubk p)))
      (recv (enc s  (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (recv (enc "login-request" cred                                                        (hash s cc id)))
      (send (enc "login-success"                  (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (recv (enc     msg                          (enc cookie (hash sskey (hash s cc id)))   (hash s cc id)))
      (send (enc (enc "answer" answer (privk p))                                             (hash s cc id)))
    )
    (uniq-gen answer)
  )
)

(defskeleton sbp
  (vars (cc id s cred cookie request answer data) (p name))
  (defstrandmax client (cc cc) (id id) (s s) (cred cred) (answer answer) (p p))
  (uniq-gen cc)
  (uniq-gen s)
  (non-orig (privk p))
)

  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  ;;(deflistener answer)
  ;;(deflistener s)
  ;;(deflistener cred)
  ;;(uniq-gen id)
  ;;(non-orig sskey)
;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
;; one idea is to router all malicious traffic through client via rogue browser plugin
;; another idea is rogue browser plugin, can they add a root CA?
