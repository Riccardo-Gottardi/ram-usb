/*
Registration request handler for the Security-Switch mTLS gateway service.

This handler implements the second layer of the R.A.M.-U.S.B. distributed authentication system.
It receives mTLS-authenticated registration requests from Entry-Hub instances, performs additional
validation layers, and securely forwards valid requests to the Database-Vault using mutual TLS.

The registration flow through Security-Switch follows this sequence:
1. Entry-Hub -> Security-Switch (mTLS)
2. Security-Switch -> Database-Vault (mTLS)

The Security-Switch adds an additional security layer by re-performing all validations,
ensuring that even if an Entry-Hub is compromised, invalid data cannot reach the Database-Vault.
*/

package handlers

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

// RegisterHandler is the PRIMARY ENDPOINT HANDLER for user registration in the Security-Switch service.
//
// This function implements the complete registration request processing pipeline for the Security-Switch:
// 1. HTTP method enforcement (POST-only for security)
// 2. Request body parsing and JSON deserialization
// 3. Defense-in-depth input validation (email format, password strength, SSH key structure)
// 4. Database-Vault client initialization with mTLS configuration
// 5. Secure request forwarding to Database-Vault
// 6. Response processing and appropriate HTTP status code mapping
//
// The handler follows the same validation logic as Entry-Hub for defense-in-depth security.
// This ensures that even if an Entry-Hub instance is compromised, invalid or malicious
// data cannot reach the Database-Vault layer.
//
// Security considerations:
// - All user input undergoes strict re-validation despite Entry-Hub validation
// - mTLS ensures only authorized Database-Vault instances can be contacted
// - Acts as a security checkpoint between public-facing and data storage layers
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// NOTE: mTLS authentication is handled by the VerifyMTLS middleware before this handler is called
	// The middleware ensures that only authenticated Entry-Hub instances can reach this endpoint

	// HTTP METHOD ENFORCEMENT
	// Only accept POST requests for registration operations
	if !utils.EnforcePOST(w, r) {
		return // Sends HTTP 405 Method Not Allowed and logs the violation
	}

	// REQUEST BODY PARSING
	// Read the entire HTTP request body into memory for JSON processing
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return // Sends HTTP 400 Bad Request if body reading fails
	}

	// JSON CONVERTION
	// Convert the raw JSON bytes into a structured RegisterRequest object
	// This validates that the JSON is well-formed and contains the expected fields
	var req types.RegisterRequest // Create a variable to hold the parsed registration data
	if !utils.ParseJSONBody(body, &req, w) {
		return // Sends HTTP 400 Bad Request if JSON parsing fails
	}

	// BASIC REQUIRED FIELDS VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure that essential fields are not empty or missing
	// This re-validates data that should have been checked by Entry-Hub
	// Defense-in-depth principle: never trust data from upstream services
	if req.Email == "" || req.Password == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// EMAIL FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Validate email address format using RFC 5322 compliant regular expression
	// This prevents malformed email addresses from entering the system and ensures
	// compatibility with standard email processing systems
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// EMAIL SECURITY VALIDATION (DEFENSE-IN-DEPTH)
	// Additional security check: ensure the email contains exactly one @ symbol
	// This prevents email header injection attacks and catches obviously malformed addresses
	// that might bypass the regex validation
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// PASSWORD LENGTH VALIDATION (DEFENSE-IN-DEPTH)
	// Enforce minimum password length of 8 characters
	// This is a basic security requirement that prevents trivially weak passwords
	// while remaining user-friendly (not overly restrictive)
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// WEAK PASSWORD DETECTION (DEFENSE-IN-DEPTH)
	// Check against a database of commonly used weak passwords
	// This prevents users from using passwords that are frequently targeted
	// in dictionary attacks and credential stuffing attacks
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// PASSWORD COMPLEXITY VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure the password contains at least 3 out of 4 character categories:
	// uppercase letters, lowercase letters, numbers, and special characters
	// This approach balances security with usability
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// SSH PUBLIC KEY FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Perform comprehensive validation of the SSH public key including:
	// - Algorithm verification (RSA, Ed25519, ECDSA, etc.)
	// - Base64 encoding validation
	// - Key length appropriate for the algorithm
	// - Internal key structure verification
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SSH KEY PREFIX VALIDATION (DEFENSE-IN-DEPTH)
	// Additional security check: ensure the SSH key starts with a recognized algorithm prefix
	// This catches keys that might have been corrupted or manually edited incorrectly
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// DATABASE-VAULT CLIENT INITIALIZATION
	// Create and configure an mTLS client to communicate securely with the Database-Vault
	// This involves loading certificates, configuring TLS, and creating an HTTP client
	cfg := config.GetConfig() // Load application configuration including certificate paths and IP addresses
	dbClient, err := interfaces.NewDatabaseVaultClient(
		cfg.DatabaseVaultIP, // Target Database-Vault server address
		cfg.ClientCertFile,  // Security-Switch's client certificate for mTLS authentication
		cfg.ClientKeyFile,   // Security-Switch's private key for mTLS authentication
		cfg.CACertFile,      // Certificate Authority certificate for server verification
	)
	if err != nil {
		// Handle client initialization errors with specific error categorization
		errorMsg := fmt.Sprintf("Failed to initialize Database-Vault client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// Provide specific error messages based on the type of failure
		// This helps with troubleshooting
		if strings.Contains(err.Error(), "certificate") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate configuration error. Please contact administrator.")
		} else if strings.Contains(err.Error(), "file") {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Certificate files not found. Please contact administrator.")
		} else {
			utils.SendErrorResponse(w, http.StatusInternalServerError,
				"Database-Vault client initialization failed. Please contact administrator.")
		}
		return
	}

	// SECURE REQUEST FORWARDING TO DATABASE-VAULT
	// Log the forwarding attempt for audit purposes
	log.Printf("Forwarding registration request for user: %s", req.Email)

	// Forward the validated registration request to Database-Vault using mTLS
	// The StoreUserCredentials method handles JSON serialization, HTTPS request creation,
	// certificate-based authentication, and response parsing
	dbResponse, err := dbClient.StoreUserCredentials(req)
	if err != nil {
		// Handle communication errors with the Database-Vault
		// Different error types require different HTTP status codes and client messages
		errorMsg := fmt.Sprintf("Failed to store user credentials for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// Categorize the error and provide appropriate HTTP status codes:
		// - Connection refused: Service is down or unreachable
		// - Timeout: Service is overloaded or network issues
		// - Other: Generic network or protocol issues
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

	// DATABASE-VAULT RESPONSE VALIDATION
	// Check if the Database-Vault successfully processed the registration request
	// The Database-Vault may reject requests for various reasons (duplicate users, storage errors, etc.)
	if !dbResponse.Success {
		log.Printf("Database-Vault rejected registration for %s: %s", req.Email, dbResponse.Message)
		// Pass through the specific error message from Database-Vault to maintain error context
		// while ensuring no sensitive information is disclosed
		utils.SendErrorResponse(w, http.StatusBadRequest, dbResponse.Message)
		return
	}

	// SUCCESS RESPONSE
	// Log successful registration for audit purposes and send success response to Entry-Hub
	// This completes the Security-Switch portion of the distributed registration process
	log.Printf("User successfully registered: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
