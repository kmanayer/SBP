;;(defconstant tlskey (ltk client proxy)) - try using long term keys after we get it working

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (request request2 answer answer2 cookie syskey tlskey data) (client name))
    (trace
      (init request)
      (recv (cat answer (enc cookie (hash syskey tlskey))))
      (send (cat request2 (enc cookie (hash syskey tlskey))))
      (recv (cat answer2 (enc cookie (hash syskey tlskey))))
    )
  )
  
  (defrole proxy
    (vars (request request2 answer answer2 cookie syskey tlskey data))
    (trace
      (obsv (cat answer cookie))
      (send (cat answer (enc cookie (hash syskey tlskey))))
      (recv (cat request2 (enc cookie (hash syskey tlskey))))
      (init (cat request2 cookie))
      (obsv (cat answer2 cookie))
      (send (cat answer2 (enc cookie (hash syskey tlskey))))
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
  (vars (syskey request answer answer2 tlskey cookie data) )
  (defstrandmax client (syskey syskey) (tlskey tlskey)  
                       (answer answer) (answer2 answer2) (cookie cookie))
  (non-orig cookie)           
  (non-orig syskey)
  (non-orig tlskey)
  (non-orig answer)
  (non-orig answer2)
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

