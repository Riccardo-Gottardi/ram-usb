package handlers

import (
	"encoding/json"
	"https_server/types"
	"net/http"
)

// Handler to verify that the server is working
func HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json") // Tells the client that the response will be a json
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: "HTTPS server working!",
	})
}
