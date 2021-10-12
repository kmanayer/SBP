;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (request request2 answer answer2 cookie data) (client proxy name))
    (trace
      (init request)
      (recv (enc (cat "response1" answer cookie) (privk proxy)))
      (send (enc (cat "request" request2 cookie) (privk client)))
      (recv (enc (cat "response2" answer2 cookie) (privk proxy)))
    )
  )
  
  (defrole proxy
    (vars (request request2 answer answer2 cookie data) (client proxy name))
    (trace
      (obsv (cat answer cookie))
      (send (enc (cat "response1" answer cookie) (privk proxy)))
      (recv (enc (cat "request" request2 cookie) (privk client)))
      (init (cat request2 cookie))
      (obsv (cat answer2 cookie))
      (send (enc (cat "response2" answer2 cookie) (privk proxy)))
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


(defskeleton sbp
  (vars (client proxy name) )
  (defstrandmax client (proxy proxy) (client client))
  (non-orig (privk proxy) (privk client))
  
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

