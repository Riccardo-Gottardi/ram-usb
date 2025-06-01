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

// VerifyMTLS is a MIDDLEWARE FUNCTION that verifies the client certificate
//
// This specific middleware ensures that:
// 1) The connection uses TLS
// 2) A valid client certificate was provided
// 3) The certificate comes from an authorized Entry-Hub
//
// # The parameter "next" is the original handler function to call after verification
//
// Returns a new handler that includes mTLS verification
func VerifyMTLS(next http.HandlerFunc) http.HandlerFunc {
	// VerifyMTLS returns an anonymous function that takes care of performing all the necessary checks
	// before calling next
	return func(w http.ResponseWriter, r *http.Request) {
		// Set JSON response header
		w.Header().Set("Content-Type", "application/json")

		// Check if the request has TLS connection info
		// r.TLS contains TLS connection state information
		// If r.TLS is nil, it means the connection is not using TLS
		if r.TLS == nil {
			// Log the security violation
			// r.RemoteAddr contains the client's IP address and port
			log.Printf("Request without TLS from %s", r.RemoteAddr)

			// Send HTTP 401 Unauthorized response and stop processing
			// We don't call next() because this request is not authorized
			utils.SendErrorResponse(w, http.StatusUnauthorized, "TLS required")
			return
		}

		// Verify that client certificate was provided
		// r.TLS.PeerCertificates is a slice containing the client's certificate
		// len() returns 0 if no certificates were provided
		if len(r.TLS.PeerCertificates) == 0 {
			log.Printf("Request without client certificate from %s", r.RemoteAddr)
			utils.SendErrorResponse(w, http.StatusUnauthorized, "Client certificate required")
			return
		}

		// Extract and examine the client certificate
		// PeerCertificates[0] is the client's certificate
		// The certificate contains information about who issued it and to whom
		clientCert := r.TLS.PeerCertificates[0]

		// Log successful mTLS authentication
		log.Printf("mTLS authenticated request from %s (CN=%s, O=%s)",
			// clientCert.Subject contains the certificate's subject information:
			// - CommonName (CN): the service/host name
			// - Organization (O): the company/department name
			r.RemoteAddr,
			clientCert.Subject.CommonName,
			clientCert.Subject.Organization)

		// Check that the certificate was issued to "EntryHub" organization
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
