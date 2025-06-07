/*
Password hashing utilities for secure user authentication.

Implements Argon2id password hashing with cryptographically secure salt
generation to defend against rainbow table attacks and GPU-based brute force.
Uses memory-hard algorithm parameters to resist specialized hardware attacks.

TO-DO in package: Move this file to Database-Vault for proper architecture separation
*/
package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// GenerateSalt creates cryptographically secure random salt for password hashing.
//
// Security features:
// - Uses crypto/rand for unpredictable entropy source
// - 16-byte length provides sufficient uniqueness against collisions
// - Hexadecimal encoding prevents binary storage issues
//
// Returns hex-encoded salt string and error if entropy source fails.
func GenerateSalt() (string, error) {
	// SALT GENERATION
	// Create 16-byte buffer for cryptographically secure randomness
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		// Entropy source failure - critical security error
		return "", err
	}

	// ENCODING
	// Convert to hexadecimal for safe database storage and transmission
	return fmt.Sprintf("%x", salt), nil
}

// HashPassword generates Argon2id hash with provided salt for secure storage.
//
// Security features:
// - Argon2id algorithm resists both time-memory and side-channel attacks
// - Memory-hard parameters (32MB) defend against GPU acceleration
// - Single iteration with medium-high memory usage balances security and performance
//
// Returns hex-encoded hash suitable for database storage.
func HashPassword(password, salt string) string {
	// PARAMETER CONVERSION
	// Convert salt to bytes for Argon2id algorithm requirements
	saltBytes := []byte(salt)

	// ARGON2ID HASHING
	// Parameters: 1 iteration, 32MB memory, 4 threads, 32-byte output
	// Chosen to resist GPU attacks while maintaining reasonable server performance
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 32*1024, 4, 32)

	// ENCODING
	// Convert hash to hexadecimal for consistent storage format
	return fmt.Sprintf("%x", hash)
}
