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
    (vars (challenge id secret request request2 answer answer2 cookie syskey data) (proxy name) )
    (trace
      (send challenge)
      (recv id)
      (send (enc secret (pubk proxy)))
      (send (enc id (hash secret challenge id)))
      (recv (enc challenge (hash secret challenge id)))
      (send request)
      (recv (cat answer (enc cookie (hash syskey (hash secret challenge id)))))
      (send (cat request2 (enc cookie (hash syskey (hash secret challenge id)))))
      (recv answer2)
    )
  )
  
  (defrole proxy
    (vars (challenge id secret request request2 answer answer2 cookie syskey data) (proxy name) )
    (trace
      (recv challenge)
      (send id)
      (recv (enc secret (pubk proxy)))
      (recv (enc id (hash secret challenge id)))
      (send (enc challenge (hash secret challenge id)))
      (recv request)
      (init request)
      (obsv (cat answer cookie))
      (send (cat answer (enc cookie (hash syskey (hash secret challenge id)))))
      (recv (cat request2 (enc cookie (hash syskey (hash secret challenge id)))))
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
  (vars (challenge secret id syskey data) (proxy name) )
  (defstrandmax client (challenge challenge) (secret secret) (proxy proxy) (id id) (syskey syskey) )
  ;;(deflistener (hash secret challenge id))
  (uniq-orig challenge)
  (uniq-orig secret)
  (non-orig (privk proxy))
  (non-orig syskey)
  (pen-non-orig (pubk proxy))
)
