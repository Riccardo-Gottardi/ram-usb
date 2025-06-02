/*
User registration handler for the Entry-Hub REST API service.

This handler implements the first layer of the R.A.M.-U.S.B. distributed authentication system.
It processes incoming HTTPS registration requests from client applications, performs input validation,
and securely forwards valid requests to the Security-Switch using mutual TLS.

The registration flow follows this sequence:
1. Client -> Entry-Hub (HTTPS with server certificates)
2. Entry-Hub -> Security-Switch (mTLS with mutual certificate verification)
3. Security-Switch -> Database-Vault (mTLS with mutual certificate verification)
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

// RegisterHandler is the PRIMARY ENDPOINT HANDLER for user registration in the Entry-Hub service.
//
// This function implements the complete registration request processing pipeline:
// 1. HTTP method enforcement (POST-only for security)
// 2. Request body parsing and JSON deserialization
// 3. Multi-layer input validation (email format, password strength, SSH key structure)
// 4. Security-Switch client initialization with mTLS configuration
// 5. Secure request forwarding to Security-Switch
// 6. Response processing and appropriate HTTP status code mapping
//
// The handler follows defensive programming principles with error handling at each step.
// All validation failures and system errors are logged for security monitoring.
//
// Security considerations:
// - All user input undergoes strict validation before processing
// - mTLS ensures only authorized Security-Switch instances can be contacted
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	// Log the incoming request for security monitoring and debugging
	// r.RemoteAddr contains the client's IP address and port for audit trails
	fmt.Printf("Request: \n\tfrom:\t%s \n\tmethod:\t%s\n", r.RemoteAddr, r.Method)

	// SET RESPONSE CONTENT TYPE
	// Set the HTTP Content-Type header to inform the client that all responses will be JSON
	// This ensures proper parsing by client applications and API compatibility
	w.Header().Set("Content-Type", "application/json")

	// HTTP METHOD ENFORCEMENT
	// Only accept POST requests for registration operations
	if !utils.EnforcePOST(w, r) {
		return // EnforcePOST sends HTTP 405 Method Not Allowed and logs the violation
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
	var req types.RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return // Sends HTTP 400 Bad Request if JSON parsing fails
	}

	// BASIC REQUIRED FIELDS VALIDATION
	// Ensure that essential fields are not empty or missing
	// This is the first line of defense against incomplete requests
	if req.Email == "" || req.Password == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email and password are required.")
		return
	}

	// EMAIL FORMAT VALIDATION
	// Validate email address format using RFC 5322 compliant regular expression
	// This prevents malformed email addresses from entering the system and ensures
	// compatibility with standard email processing systems
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// EMAIL SECURITY VALIDATION
	// Additional security check: ensure the email contains exactly one @ symbol
	// This prevents email header injection attacks and catches obviously malformed addresses
	// that might bypass the regex validation
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// PASSWORD LENGTH VALIDATION
	// Enforce minimum password length of 8 characters
	// This is a basic security requirement that prevents trivially weak passwords
	// while remaining user-friendly (not overly restrictive)
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// WEAK PASSWORD DETECTION
	// Check against a database of commonly used weak passwords
	// This prevents users from using passwords that are frequently targeted
	// in dictionary attacks and credential stuffing attacks
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// PASSWORD COMPLEXITY VALIDATION
	// Ensure the password contains at least 3 out of 4 character categories:
	// uppercase letters, lowercase letters, numbers, and special characters
	// This approach balances security with usability
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// SSH PUBLIC KEY FORMAT VALIDATION
	// Perform comprehensive validation of the SSH public key including:
	// - Algorithm verification (RSA, Ed25519, ECDSA, etc.)
	// - Base64 encoding validation
	// - Key length appropriate for the algorithm
	// - Internal key structure verification
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SSH KEY PREFIX VALIDATION
	// Additional security check: ensure the SSH key starts with a recognized algorithm prefix
	// This catches keys that might have been corrupted or manually edited incorrectly
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SECURITY-SWITCH CLIENT INITIALIZATION
	// Create and configure an mTLS client to communicate securely with the Security-Switch
	// This involves loading certificates, configuring TLS, and creating an HTTP client
	config := config.GetConfig() // Load application configuration including certificate paths and IP addresses
	securityClient, err := interfaces.NewEntryHubClient(
		config.SecuritySwitchIP, // Target Security-Switch server address
		config.ClientCertFile,   // Entry-Hub's client certificate for mTLS authentication
		config.ClientKeyFile,    // Entry-Hub's private key for mTLS authentication
		config.CACertFile,       // Certificate Authority certificate for server verification
	)
	if err != nil {
		// Handle client initialization errors with specific error categorization
		errorMsg := fmt.Sprintf("Failed to initialize Security-Switch client: %v", err)
		log.Printf("Error: %s", errorMsg)

		// Provide specific error messages based on the type of failure
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

	// SECURE REQUEST FORWARDING
	// Log the forwarding attempt for audit purposes
	// This creates a trail that can be used for security monitoring and debugging
	log.Printf("Attempting to forward registration request for user: %s", req.Email)

	// Forward the validated registration request to Security-Switch using mTLS
	// The ForwardRegistration method handles JSON serialization, HTTPS request creation,
	// certificate-based authentication, and response parsing
	switchResponse, err := securityClient.ForwardRegistration(req)
	if err != nil {
		// Handle communication errors with the Security-Switch
		// Different error types require different HTTP status codes and client messages
		errorMsg := fmt.Sprintf("Failed to contact Security-Switch for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)

		// Categorize the error and provide appropriate HTTP status codes:
		// - Connection refused: Service is down or unreachable
		// - Timeout: Service is overloaded or network issues
		// - Certificate/TLS: Security configuration problems
		// - Other: Generic network or protocol issues
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

	// SECURITY-SWITCH RESPONSE VALIDATION
	// Check if the Security-Switch successfully processed the registration request
	// The Security-Switch may reject requests for various reasons
	if !switchResponse.Success {
		log.Printf("Security-Switch rejected registration for %s: %s", req.Email, switchResponse.Message)
		utils.SendErrorResponse(w, http.StatusBadRequest,
			fmt.Sprintf("Registration failed: %s", switchResponse.Message))
		return
	}

	// SUCCESS RESPONSE
	// Log successful registration for audit purposes and send success response to client
	// This completes the Entry-Hub portion of the distributed registration process
	log.Printf("User successfully registered via Security-Switch: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User successfully registered!")
}
