package types

/*
Type definitions for the Security-Switch service.
Contains struct definitions for API requests, responses, and data models
used for communication between Entry-Hub and Database-Vault.
*/

// RegisterRequest represents the registration data received from Entry-Hub
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	SSHPubKey string `json:"ssh_public_key"`
}

// Response represents the standard API response structure
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// HealthResponse provides detailed health check information
type HealthResponse struct {
	Success      bool              `json:"success"`
	Message      string            `json:"message"`
	Service      string            `json:"service"`
	Status       string            `json:"status"`
	Dependencies map[string]string `json:"dependencies,omitempty"`
}

// UserCredentials represents user data stored in Database-Vault
type UserCredentials struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	SSHPubKey    string `json:"ssh_public_key"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

// LoginRequest for future implementation
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// SessionToken for future implementation
type SessionToken struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	UserEmail string `json:"user_email"`
}
