/*
User registration handler for the backup service REST API.
Handles POST requests to /api/register endpoint.
Parse the JSON
Validates user input.
Check if the email and the password are valid.
Check if the SSH public key is valid.
Initialize EntryHub_to_SecuritySwitch interface.
Forward the request to the Security-Switch.
Check the Security-Switch response
*/

package handlers

import (
	"fmt"
	"https_server/config"
	"https_server/interfaces"
	"https_server/types"
	"https_server/utils"
	"log"
	"net/http"
	"strings"
)

// User registration handler
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request: \n\tfrom:\t%s \n\tmethod:\t%s\n", r.RemoteAddr, r.Method)

	// Set Content-Type to JSON
	w.Header().Set("Content-Type", "application/json") // Tells the client that the response will be a json

	if !utils.EnforcePOST(w, r) { // Accepts POST requests only.
		return
	}

	// Read request body
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return
	}

	// Parsing JSON and exit if the JSON is invalid
	var req types.RegisterRequest // Create a variable as a struct RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return
	}

	// Input Validation
	if req.Email == "" || req.Password == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// Check if the email is valid by calling the isValidEmail function. If it's not, it returns error 400
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// Check for suspicious patterns in email
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// Check if the password is valid.
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// Check for common weak passwords
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// Check password complexity
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// Check if the SSH public key is valid. If it's not, it returns error 400
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// Verify SSH key has proper format
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// Initialize EntryHub interface
	config := config.GetConfig()
	securityClient, err := interfaces.NewEntryHubClient(
		config.SecuritySwitchIP,
		config.ClientCertFile,
		config.ClientKeyFile,
		config.CACertFile,
	)
	if err != nil {
		// More specific error for client initialization problems
		errorMsg := fmt.Sprintf("Failed to initialize Security-Switch client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// Determine the type of error to give a more specific answer
		if strings.Contains(err.Error(), "certificate") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate configuration error. Please contact administrator.")
		} else if strings.Contains(err.Error(), "file") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate files not found. Please contact administrator.")
		} else {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Security-Switch client initialization failed. Please contact administrator.")
		}
		return
	}

	// Try contacting Security-Switch
	log.Printf("Attempting to forward registration request for user: %s", req.Email)

	switchResponse, err := securityClient.ForwardRegistration(req)
	if err != nil {
		// Error due to connection problems
		errorMsg := fmt.Sprintf("Failed to contact Security-Switch for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// Determine the type of connection error
		if strings.Contains(err.Error(), "connection refused") {
			utils.SendErrorResponse(w, http.StatusServiceUnavailable,
				"Security-Switch service is unavailable. Please try again later.")
		} else if strings.Contains(err.Error(), "timeout") {
			utils.SendErrorResponse(w, http.StatusGatewayTimeout,
				"Security-Switch service timeout. Please try again later.")
		} else if strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Security certificate validation failed. Please contact administrator.")
		} else {
			utils.SendErrorResponse(w, http.StatusBadGateway,
				"Unable to reach Security-Switch service. Please try again later.")
		}
		return
	}

	// Check the Security-Switch response
	if !switchResponse.Success {
		log.Printf("Security-Switch rejected registration for %s: %s", req.Email, switchResponse.Message)
		utils.SendErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("Registration failed: %s", switchResponse.Message))
		return
	}

	// Success
	log.Printf("User successfully registered via Security-Switch: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
