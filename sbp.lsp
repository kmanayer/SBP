;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (request request2 answer answer2 cookie syskey data) (client proxy name))
    (trace
      (send (cat request))
      (recv (cat answer (enc cookie (hash syskey (ltk client proxy)))))
      (send (cat request2 (enc cookie (hash syskey (ltk client proxy)))))
      (recv (cat answer2))
    )
  )
  
  (defrole proxy
    (vars (request request2 answer answer2 cookie syskey data) (client proxy name))
    (trace
      (recv (cat request))
      (init request)
      (obsv (cat answer cookie))
      (send (cat answer (enc cookie (hash syskey (ltk client proxy)))))
      (recv (cat request2 (enc cookie (hash syskey (ltk client proxy)))))
      (init (cat request2 cookie))
      (obsv answer2)
      (send (cat answer2))
    )
  )
  
  (defrole server
    (vars (request request2 answer answer2 cookie data) )
    (trace 
      (tran request (cat answer cookie))
      (tran (cat request2 cookie) answer2)
    )
  )
    
)

;;(defskeleton sbp
;;  (vars (syskey tlskey data) )
;;  (defstrandmax client (syskey syskey) (tlskey tlskey) )
;;  (non-orig syskey)
;;  (pen-non-orig tlskey)
;;)

(defskeleton sbp
  (vars (syskey data) )
  (defstrandmax client (syskey syskey))
  (non-orig syskey)
)


;; at most one proxy per client
(defgoal sbp
  (forall ((z0 z1 strd) (client proxy name))
    (implies
      (and (p "proxy" z0 1)
           (p "proxy" z1 1)
           (p "proxy" "client" z0 client)
           (p "proxy" "client" z1 client)
           (p "proxy" "proxy"  z0 proxy)
           (p "proxy" "proxy"  z1 proxy)
      )     
      (= z0 z1)
    )
  )
)
           
           
           
           
;;(defskeleton sbp
;;  (vars (syskey tlskey data) )
;;  (defstrandmax client (syskey syskey) (tlskey tlskey) )
;;  (non-orig syskey)
;;  (pen-non-orig tlskey)
;;)

