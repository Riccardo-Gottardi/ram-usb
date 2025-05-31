/*
Type definitions for the backup service application.
Contains struct definitions for API requests, responses, and data models
used throughout the application for consistent data handling.
*/

package types

// RegisterRequest represents the JSON that the Entry-Hub sends to the Security-Switch during the user registration phase.
// This type is serialized in JSON and sent via an HTTPS POST request with mTLS authentication.
// The Security-Switch uses this information to register the user in the system:
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	SSHPubKey string `json:"ssh_public_key"`
}

// Login request structure. WARNING: The login is not implemented yet.
/*
type LoginRequest struct {
	Email    string `json:"email"` // email hashed by the client using Argon2id
	Password string `json:"password"`
}
*/

// WARNING:This User structure is not used anymore. It was used ad a test.
// It's here because I don't want to throw away some code for now.
type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	SSHPubKey    string `json:"ssh_public_key"`
}

// Response represents the standard response structure sent by the Entry-Hub to the Client and by the Security-Switch to the Entry-Hub
// following a registration or authentication request.
// This structure is serialized in JSON and sent as an HTTP response.
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
