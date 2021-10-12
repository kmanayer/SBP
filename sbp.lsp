;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (answer cookie tlskey data))
    (trace
      (recv cookie)
      (send (enc "request" cookie tlskey))
      (recv (enc "response2" answer cookie tlskey))
    )
  )
  
  (defrole proxy
    (vars (answer cookie tlskey data))
    (trace
      (send cookie)
      (recv (enc "request" cookie tlskey))
      (send (enc "response2" answer cookie tlskey))
    )
  )
    )


(defskeleton sbp
  (vars (tlskey data))
  (defstrandmax client (tlskey tlskey))
  (pen-non-orig tlskey)
  
)

;;(defskeleton sbp
;;  (vars (syskey tlskey data) )
;;  (defstrandmax client (syskey syskey) (tlskey tlskey) )
;;  (non-orig syskey)
;;  (pen-non-orig tlskey)
;;)


;; at most one proxy per client
;;(defgoal sbp
;;  (forall ((z0 z1 strd) (client proxy name))
;;    (implies
;;      (and (p "proxy" z0 1)
;;           (p "proxy" z1 1)
;;           (p "proxy" "client" z0 client)
;;           (p "proxy" "client" z1 client)
;;           (p "proxy" "proxy"  z0 proxy)
;;           (p "proxy" "proxy"  z1 proxy)
;;      )     
;;      (= z0 z1)
;;    )
;;  )
;;)
         
           
;;(defskeleton sbp
;;  (vars (syskey tlskey data) )
;;  (defstrandmax client (syskey syskey) (tlskey tlskey) )
;;  (non-orig syskey)
;;  (pen-non-orig tlskey)
;;)

