package main

import (
	"encoding/json"
	"net/http"
)

// Handler to verify that the server is working
func healthHandler(w http.ResponseWriter, r *http.Request) { //
	w.Header().Set("Content-Type", "application/json") // Tells the client that the response will be a json
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "HTTPS server working!",
	})
}
