package middleware

/*
mTLS middleware for Security-Switch request validation.
Verifies client certificates and ensures only authenticated
Entry-Hub instances can communicate with the Security-Switch.
*/

import (
	"fmt"
	"log"
	"net/http"
	"security_switch/utils"
)

// VerifyMTLS is a middleware that verifies the client certificate
func VerifyMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set JSON response header
		w.Header().Set("Content-Type", "application/json")

		// Check if the request has TLS connection info
		if r.TLS == nil {
			log.Printf("Request without TLS from %s", r.RemoteAddr)
			utils.SendErrorResponse(w, http.StatusUnauthorized, "TLS required")
			return
		}

		// Verify that client certificate was provided
		if len(r.TLS.PeerCertificates) == 0 {
			log.Printf("Request without client certificate from %s", r.RemoteAddr)
			utils.SendErrorResponse(w, http.StatusUnauthorized, "Client certificate required")
			return
		}

		// Get the client certificate
		clientCert := r.TLS.PeerCertificates[0]

		// Log successful mTLS authentication
		log.Printf("mTLS authenticated request from %s (CN=%s, O=%s)",
			r.RemoteAddr,
			clientCert.Subject.CommonName,
			clientCert.Subject.Organization)

		// Additional validation: check if it's from Entry-Hub
		if len(clientCert.Subject.Organization) == 0 || clientCert.Subject.Organization[0] != "EntryHub" {
			log.Printf("Unauthorized client organization: %v", clientCert.Subject.Organization)
			utils.SendErrorResponse(w, http.StatusForbidden, "Unauthorized client")
			return
		}

		// Log the request details
		fmt.Printf("Authenticated request: \n\tfrom:\t%s \n\tmethod:\t%s\n\tpath:\t%s\n",
			r.RemoteAddr, r.Method, r.URL.Path)

		// Call the next handler
		next(w, r)
	}
}
