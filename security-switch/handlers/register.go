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
	// Verify HTTP method
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

	// Additional validation at Security-Switch level
	if err := validateRegistrationRequest(req); err != nil {
		utils.SendErrorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Initialize Database-Vault client
	cfg := config.GetConfig()
	dbClient, err := interfaces.NewDatabaseVaultClient(
		cfg.DatabaseVaultIP,
		cfg.ClientCertFile,
		cfg.ClientKeyFile,
		cfg.CACertFile,
	)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to initialize Database-Vault client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// Determine error type for specific response
		if strings.Contains(err.Error(), "certificate") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Database-Vault certificate configuration error. Please contact administrator.")
		} else {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Failed to connect to Database-Vault service.")
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

// validateRegistrationRequest performs additional security checks
func validateRegistrationRequest(req types.RegisterRequest) error {
	// Check for suspicious patterns in email
	if strings.Count(req.Email, "@") != 1 {
		return fmt.Errorf("invalid email format")
	}

	// Check password strength (basic check, enhance as needed)
	if len(req.Password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	// Verify SSH key has proper format
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		return fmt.Errorf("invalid SSH public key format")
	}

	// Check for common weak passwords
	if utils.IsWeakPassword(req.Password) {
		return fmt.Errorf("password is too common, please choose a stronger password")
	}

	// Check password complexity
	if !utils.HasPasswordComplexity(req.Password) {
		return fmt.Errorf("password must contain at least 3 of: uppercase, lowercase, numbers, special characters")
	}

	return nil
}
