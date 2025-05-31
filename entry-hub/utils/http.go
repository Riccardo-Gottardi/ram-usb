/*
HTTP utility functions for request handling and validation.
Provides common HTTP operations like method enforcement and
request validation to ensure proper API usage.
*/

package utils

import (
	"net/http"
)

func EnforcePOST(w http.ResponseWriter, r *http.Request) bool {
	// Accepts POST requests only.
	if r.Method != http.MethodPost {
		LogAndSendError(w, http.StatusMethodNotAllowed, // Return HTTP 405 Method Not Allowed
			"invalid method: "+r.Method+"; only POST is allowed",
			"Method not allowed. Use POST.")
		return false
	}
	return true
}
