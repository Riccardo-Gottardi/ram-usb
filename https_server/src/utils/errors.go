package utils

/*
Error handling utilities for consistent error responses.
Provides standardized error handling and logging functions
for the backup service API endpoints.
*/

import (
	"encoding/json"
	"https_server/types"
	"log"
	"net/http"
)

// SendErrorResponse sends a standardized error response to the client
func SendErrorResponse(w http.ResponseWriter, statusCode int, message string) {
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(types.Response{
		Success: false,
		Message: message,
	})
}

// SendSuccessResponse sends a standardized success response to the client
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
