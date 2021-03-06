(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc id s cred answer data) (enc_cookie mesg) (p name))
    (trace
      (send cc)
      (recv (cat id (pubk p)))
      (send (enc s  (pubk p)))
      (send (enc id (hash s cc id)))
      (recv (enc cc (hash s cc id)))

      (send (enc             "login" cred            (hash s cc id)))
      (recv (enc    "login-successful" enc_cookie    (hash s cc id))) 

      (send (enc       "request" "get" enc_cookie    (hash s cc id))) 
      (recv (enc           "answer" answer           (hash s cc id)))
    )
    (uniq-gen cc)
    (uniq-gen s)
  )
  
  (defrole proxy
    (vars (cc id s cred iv cookie sskey answer data) (request mesg) (p name))
    (trace
      (recv cc)
      (send (cat id (pubk p)))
      (recv (enc s  (pubk p)))
      (recv (enc id (hash s cc id)))
      (send (enc cc (hash s cc id)))

      (recv (enc                "login" cred                  (hash s cc id)))
      (send (enc           "login-successful" (cat iv 
                  (enc cookie (hash sskey (hash s cc id))))   (hash s cc id)))

      (recv (enc            "request" request (cat iv 
                  (enc cookie (hash sskey (hash s cc id))))   (hash s cc id)))
      (send (enc              "answer" answer                 (hash s cc id)))
    )
    (uniq-gen id)
    (uniq-gen iv)
    (non-orig sskey)
  )
)

(defskeleton sbp
  (vars (cred answer data) (p name))
  (defstrandmax client (cred cred) (answer answer) (p p))
  (defstrandmax proxy  (cred cred) (answer answer) (p p))
  (uniq-gen cred)
  (uniq-gen answer)
  (non-orig (privk p))
)



;;(deflistener answer)
;;(deflistener cred)

;; proxy POV
;;(defskeleton sbp
;;  (vars (answer data) (c p name))
;;  (defstrandmax client (c c) (p p))
;;  ;;(defstrandmax proxy (answer answer) (c c) (p p))
;;  (deflistener answer)
;;  (non-orig (privk c))
;;  (non-orig (privk p))
;;)

  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  
  ;;(deflistener s)
  ;;(deflistener cred)
  ;;(uniq-gen id)
  ;;(non-orig sskey)
;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
;; one idea is to router all malicious traffic through client via rogue browser plugin
;; another idea is rogue browser plugin, can they add a root CA?
