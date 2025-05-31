package utils

/*
JSON processing utilities for API request/response handling.
Contains functions for reading request bodies, parsing JSON data,
and handling JSON-related errors.
*/

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReadRequestBody reads and validates the request body
func ReadRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		LogAndSendError(w, http.StatusBadRequest,
			"failed to read request body",
			"Error reading request.")
		return nil, false
	}
	return body, true
}

// ParseJSONBody parses the request body into the given struct
func ParseJSONBody(body []byte, target interface{}, w http.ResponseWriter) bool {
	if err := json.Unmarshal(body, target); err != nil {
		LogAndSendError(w, http.StatusBadRequest,
			"failed to parse JSON body: "+err.Error(),
			"Invalid JSON format.")
		return false
	}
	return true
}
