;; This is a minimal template for a CPSA input file.

;; Replace <TITLE> with the desired title and <PROTONAME>
;; with the desired name of your project.

;; The defrole template below may be copied and used as
;; a starting point for the roles of your protocol.
;; Change the <ROLENAME> field in each copy as desired.
;; Roles must have distinct names.

;; The basic cryptoalgebra is selected by default. If
;; your project requires the diffie-hellman algebra,
;; delete "basic" on the defprotocol line, uncomment
;; "diffie-hellman" on this same line and uncomment
;; the "(algebra diffie-hellman)" statement in the
;; herald.

;; Refer to the CPSA manual for more information
;; about syntax and additional features.

(herald "Session Binding Protocol (SBP)" )

(defprotocol sbp basic

  (defrole client
    (vars (request request2 answer answer2 cookie syskey tlskey data) )
    (trace
      (send request)
      (recv (cat answer (enc cookie (hash syskey tlskey))))
      (send (cat request2 (enc cookie (hash syskey tlskey))))
      (recv answer2)
    )
  )
  
  (defrole proxy
    (vars (request request2 answer answer2 cookie syskey tlskey data) )
    (trace
      (recv request)
      (init request)
      (obsv (cat answer cookie))
      (send (cat answer (enc cookie (hash syskey tlskey))))
      (recv (cat request2 (enc cookie (hash syskey tlskey))))
      (init (cat request2 cookie))
      (obsv answer2)
      (send answer2)
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
  (defstrandmax proxy (syskey syskey) (tlskey tlskey) )
  (defstrandmax client (syskey syskey) (tlskey tlskey) )
  (non-orig syskey)
  (pen-non-orig tlskey)
)

;;(defskeleton sbp
;;  (vars (syskey tlskey data) )
;;  (defstrandmax client (syskey syskey) (tlskey tlskey) )
;;  (non-orig syskey)
;;  (pen-non-orig tlskey)
;;)

