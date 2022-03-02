(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (cc cred answer data) (enc_cookie mesg) (c p name))
    (trace
      (send (enc "login:" cred (privk c)))
      (recv (cat "login-successful" enc_cookie)) 

      (send (cat "request" enc_cookie)) 
      (recv (enc "answer:" answer (privk p)))
    )
  )
  
  (defrole proxy
    (vars (cc id s cred iv cookie answer sskey data) (c p name))
    (trace
      (recv cc)
      (send (cat id (pubk p)))
      (recv (enc s  (pubk p)))
      (recv (enc id (hash s cc id)))
      (send (enc cc (hash s cc id)))

      (recv (enc          (enc "login:" cred (privk c))       (hash s cc id)))
      (send (enc           "login-successful" (cat iv 
                  (enc cookie (hash sskey (hash s cc id))))   (hash s cc id)))

      (recv (enc               "request" (cat iv 
                  (enc cookie (hash sskey (hash s cc id))))   (hash s cc id)))
      (send (enc       (enc "answer:" answer (privk p))       (hash s cc id)))
    )
    (uniq-gen id)
    (non-orig sskey)
  )
)

(defskeleton sbp
  (vars (cred answer iv data) (c p name))
  (defstrandmax client (cred cred) (answer answer) (c c) (p p))
  (defstrandmax proxy  (cred cred) (answer answer) (iv iv) (c c) (p p))
  (uniq-gen cred)
  (uniq-gen answer)
  (uniq-gen iv)
  (non-orig (privk c))
  (non-orig (privk p))
)

  ;;(uniq-gen cc)
  ;;(uniq-gen s)
  
  ;;(defstrandmax proxy  (answer answer) (c c) (p p))
  ;;(deflistener answer)
  ;;(deflistener s)
  ;;(deflistener cred)
  ;;(uniq-gen id)
  ;;(non-orig sskey)
;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working
;; one idea is to router all malicious traffic through client via rogue browser plugin
;; another idea is rogue browser plugin, can they add a root CA?
