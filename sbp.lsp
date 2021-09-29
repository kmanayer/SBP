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
    (vars (challenge id secret request iv answer cookie syskey data) (proxy ca name) )
    (trace
      (send challenge)
      (recv (cat id (pubk proxy) (enc proxy (pubk proxy) (privk ca))))
      (send (enc secret (pubk proxy)))
      (send (enc id (hash secret challenge id)))
      (recv (enc challenge (hash secret challenge id)))
      (send request)
      (recv (cat answer iv (enc cookie (hash syskey (hash secret challenge id)))))
    )
  )
  
  (defrole proxy
    (vars (challenge id secret request iv answer cookie syskey data) (proxy ca name) )
    (trace
      (obsv (enc proxy (pubk proxy) (privk ca)))
      (recv challenge)
      (send (cat id (pubk proxy) (enc proxy (pubk proxy) (privk ca))))
      (recv (enc secret (pubk proxy)))
      (recv (enc id (hash secret challenge id)))
      (send (enc challenge (hash secret challenge id)))
      (recv request)
      (init request)
      (obsv (cat answer cookie))
      (send (cat answer iv (enc cookie (hash syskey (hash secret challenge id)))))
    )
  )
  
  (defrole certauth
    (vars (proxy ca name) )
    (trace
      (init (enc proxy (pubk proxy) (privk ca)))
    )
  )
  
  (defrole server
    (vars (request answer cookie data) )
    (trace 
      (tran request (cat answer cookie))
    )
  )
    
)

(defskeleton sbp
  (vars (challenge secret id syskey data) (proxy ca name) )
  (defstrandmax client (challenge challenge) (secret secret) (proxy proxy) (ca ca) (id id) (syskey syskey) )
  ;;(deflistener (hash secret challenge id))
  (uniq-orig challenge)
  (uniq-orig secret)
  (non-orig (privk proxy))
  (non-orig (privk ca))
  (non-orig syskey)
)
