/*
Type definitions for the backup service application.
Contains struct definitions for API requests, responses, and data models
used throughout the application for consistent data handling.
*/

package types

// Registration request structure
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	SSHPubKey string `json:"ssh_public_key"`
}

// Login request structure.
//type LoginRequest struct {
//	Email    string `json:"email"` // email hashed by the client using Argon2id
//	Password string `json:"password"`
//}

// Structure to represent a user
type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
	SSHPubKey    string `json:"ssh_public_key"`
}

// Response structure
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
