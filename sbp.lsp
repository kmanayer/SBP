(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (request request2 answer answer2 cookie syskey tlskey data) (client name))
    (trace
      (send (cat client request))
      (recv (cat client answer (enc cookie (hash syskey tlskey))))
      (send (cat client request2 (enc cookie (hash syskey tlskey))))
      (recv (cat client answer2))
    )
  )
  
  (defrole proxy
    (vars (request request2 answer answer2 cookie syskey tlskey data) (client name))
    (trace
      (recv (cat client request))
      (init request)
      (obsv (cat answer cookie))
      (send (cat client answer (enc cookie (hash syskey tlskey))))
      (recv (cat client request2 (enc cookie (hash syskey tlskey))))
      (init (cat request2 cookie))
      (obsv answer2)
      (send (cat client answer2))
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
  (vars (syskey tlskey data) )
  (defstrandmax client (syskey syskey) (tlskey tlskey) )
  (non-orig syskey)
  (pen-non-orig tlskey)
)

;; at most one proxy per client
(defgoal sbp
  (forall ((z0 z1 strd) (client name))
    (implies
      (and (p "proxy" z0 1)
           (p "proxy" z1 1)
           (p "proxy" "client" z0 client)
           (p "proxy" "client" z1 client)
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

