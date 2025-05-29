package utils

import (
	"encoding/json"
	"https_server/types"
	"net/http"
)

// Ensures only POST requests are accepted.
// If the request method is not POST, it responds with HTTP 405 (Method Not Allowed).
func EnforcePOST(w http.ResponseWriter, r *http.Request) bool {
	// Accepts POST requests only.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed) // Return HTTP 405 Method Not Allowed
		json.NewEncoder(w).Encode(types.Response{  // Send a JSON response with an error message
			Success: false,
			Message: "Method not allowed. Use POST.",
		})
		return false
	}
	return true
}
