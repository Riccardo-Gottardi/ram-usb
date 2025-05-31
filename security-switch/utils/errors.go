package utils

/*
Error handling utilities for consistent error responses.
Provides standardized error handling and logging functions
for the Security-Switch API endpoints.
*/

import (
	"encoding/json"
	"log"
	"net/http"
	"security_switch/types"
)

// SendErrorResponse sends a standardized error response
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(types.Response{
		Success: false,
		Message: message,
	})
}

// SendSuccessResponse sends a standardized success response
func SendSuccessResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: message,
	})
}

// LogAndSendError logs an error and sends an error response
func LogAndSendError(w http.ResponseWriter, statusCode int, logMessage, clientMessage string) {
	log.Printf("Error: %s", logMessage)
	SendErrorResponse(w, statusCode, clientMessage)
}
