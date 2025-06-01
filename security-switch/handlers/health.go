package handlers

/*
Health check handler for the Security-Switch.
Provides a simple endpoint to verify the Security-Switch status and connectivity.
Returns a JSON response indicating the Security-Switch is operational.
*/

import (
	"encoding/json"
	"net/http"
	"security_switch/types"
)

// HealthHandler verifies Security-Switch status
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: "Security-Switch operational!",
	})
}
