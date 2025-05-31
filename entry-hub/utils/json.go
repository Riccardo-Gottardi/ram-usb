/*
JSON processing utilities for API request/response handling.
Contains functions for reading request bodies, parsing JSON data,
and handling JSON-related errors.
*/

package utils

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReadRequestBody reads and validates the request body.
// Returns the request body as a byte slice, or sends an error response and returns nil on failure.
func ReadRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		LogAndSendError(w, http.StatusBadRequest, "failed to read request body", "Error reading request.")
		return nil, false
	}
	return body, true
}

// ParseJSONBody parses the request body into the given struct.
// Returns false and sends an HTTP code 400 error response if parsing fails.
func ParseJSONBody(body []byte, target interface{}, w http.ResponseWriter) bool {
	// Attempt to unmarshal the JSON into the target struct
	if err := json.Unmarshal(body, target); err != nil {
		LogAndSendError(w, http.StatusBadRequest,
			"failed to parse JSON body: "+err.Error(),
			"Invalid JSON format.")
		return false
	}
	return true
}
