package handlers

/*
Registration request handler for the Security-Switch.
Receives registration requests from Entry-Hub via mTLS,
performs additional validation, and forwards them to Database-Vault
for secure storage of user credentials.
*/

import (
	"fmt"
	"log"
	"net/http"
	"security_switch/config"
	"security_switch/interfaces"
	"security_switch/types"
	"security_switch/utils"
	"strings"
)

// RegisterHandler processes registration requests from Entry-Hub
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Accepts POST requests only.
	if !utils.EnforcePOST(w, r) {
		return
	}

	// Read request body
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return
	}

	// Parse JSON request
	var req types.RegisterRequest
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

	// Initialize Database-Vault interface
	cfg := config.GetConfig()
	dbClient, err := interfaces.NewDatabaseVaultClient(
		cfg.DatabaseVaultIP,
		cfg.ClientCertFile,
		cfg.ClientKeyFile,
		cfg.CACertFile,
	)
	if err != nil {
		// More specific error for client initialization problems
		errorMsg := fmt.Sprintf("Failed to initialize Database-Vault client: %v", err)
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

	// Forward registration to Database-Vault
	log.Printf("Forwarding registration request for user: %s", req.Email)

	dbResponse, err := dbClient.StoreUserCredentials(req)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to store user credentials for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// Handle different error scenarios
		if strings.Contains(err.Error(), "connection refused") {
			utils.SendErrorResponse(w, http.StatusServiceUnavailable,
				"Database-Vault service is unavailable. Please try again later.")
		} else if strings.Contains(err.Error(), "timeout") {
			utils.SendErrorResponse(w, http.StatusGatewayTimeout,
				"Database-Vault service timeout. Please try again later.")
		} else {
			utils.SendErrorResponse(w, http.StatusBadGateway,
				"Unable to store user credentials. Please try again later.")
		}
		return
	}

	// Check Database-Vault response
	if !dbResponse.Success {
		log.Printf("Database-Vault rejected registration for %s: %s", req.Email, dbResponse.Message)
		// Pass through the specific error from Database-Vault
		utils.SendErrorResponse(w, http.StatusBadRequest, dbResponse.Message)
		return
	}

	// Success - user credentials stored
	log.Printf("User successfully registered: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
