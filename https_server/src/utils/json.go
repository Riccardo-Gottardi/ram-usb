package utils

import (
	"encoding/json"
	"https_server/types"
	"io"
	"net/http"
)

// Reads and validates the request body
func ReadRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body) // Save the content of the request in the body variable
	if err != nil {                 // If reading fails
		w.WriteHeader(http.StatusBadRequest)      // Responds to client with HTTP code 400
		json.NewEncoder(w).Encode(types.Response{ // Create a json response to send to the server
			Success: false,
			Message: "Error reading request.",
		})
		return nil, false
	}
	return body, true
}

// Parse the request body into the given struct
func ParseJSONBody(body []byte, target interface{}, w http.ResponseWriter) bool {
	// Attempt to unmarshal the JSON into the target struct
	if err := json.Unmarshal(body, target); err != nil {
		// Responds to client with HTTP code 400 if JSON is badly formatted
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Invalid JSON.",
		})
		return false
	}
	return true
}
