package utils

/*
HTTP utility functions for request handling and validation.
Provides common HTTP operations like method enforcement
for the Security-Switch API endpoints.
*/

import (
	"net/http"
)

// EnforcePOST ensures the request method is POST
func EnforcePOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		LogAndSendError(w, http.StatusMethodNotAllowed,
			"invalid method: "+r.Method+"; only POST is allowed",
			"Method not allowed. Use POST.")
		return false
	}
	return true
}
