/*
Input validation utilities for user data verification.

This package provides comprehensive validation for:
- Email format validation using regex patterns
- SSH public key format and structure validation
- Password strength and complexity checking
- Protection against common weak passwords
*/

package utils

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// IsValidEmail validates email addresses using a regular expression pattern.
// This function ensures that the email follows RFC-compliant format standards.
//
// The validation pattern checks for:
// - Valid characters before @
// - Proper @ symbol placement
// - Valid domain structure with at least one dot
// - Top-level domain of at least 2 characters
//
// This is the first line of defense against malformed email addresses.
func IsValidEmail(email string) bool {
	// RFC 5322 compliant email validation pattern
	// ^[a-zA-Z0-9._%+-]+ : Local part can contain letters, numbers, and specific special characters
	// @ : Required single @ symbol
	// [a-zA-Z0-9.-]+ : Domain part with letters, numbers, dots, and hyphens
	// \.[a-zA-Z]{2,}$ : Must end with a dot followed by at least 2 letters (TLD)
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	// regexp.MustCompile() creates a compiled regular expression for efficient matching
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

// IsValidSSHKey performs validation of SSH public key format and structure.
// This function implements multi-layer validation to ensure the SSH key is:
// 1. Properly formatted according to OpenSSH standards
// 2. Uses supported cryptographic algorithms
// 3. Has appropriate key length for security
// 4. Contains valid base64-encoded key data
// 5. Has correct internal structure
//
// Supported key types: RSA, Ed25519, ECDSA (various curves), and hardware security keys.
// Returns true if the SSH key passes all validation checks, false otherwise.
func IsValidSSHKey(sshKey string) bool {
	// Remove any leading or trailing whitespace that might interfere with parsing
	sshKey = strings.TrimSpace(sshKey)

	// Check minimum length: a valid SSH key should be at least 80 characters
	// This catches obviously malformed or incomplete keys early
	if len(sshKey) < 80 {
		return false
	}

	// SSH public keys follow the format: "algorithm base64-key-data [optional-comment]"
	// strings.Fields() splits on whitespace and handles multiple spaces correctly
	parts := strings.Fields(sshKey)
	if len(parts) < 2 {
		return false
	}

	algorithm := parts[0] // The cryptographic algorithm (e.g., "ssh-rsa", "ssh-ed25519")
	keyData := parts[1]   // The base64-encoded key material

	// Define supported algorithms with their expected base64 length ranges
	// These ranges account for different key sizes and encoding overhead
	supportedAlgorithms := map[string]struct {
		minLength int // Minimum expected base64 length
		maxLength int // Maximum expected base64 length
	}{
		"ssh-rsa":                            {300, 800}, // RSA keys (2048-4096 bits typical)
		"ssh-ed25519":                        {60, 80},   // Ed25519 keys (fixed 256-bit)
		"ecdsa-sha2-nistp256":                {100, 150}, // ECDSA P-256
		"ecdsa-sha2-nistp384":                {120, 170}, // ECDSA P-384
		"ecdsa-sha2-nistp521":                {140, 200}, // ECDSA P-521
		"sk-ssh-ed25519@openssh.com":         {80, 120},  // Security key Ed25519
		"sk-ecdsa-sha2-nistp256@openssh.com": {120, 180}, // Security key ECDSA
	}

	// Check if the algorithm is in our whitelist of supported types
	algorithmSpec, isSupported := supportedAlgorithms[algorithm]
	if !isSupported {
		return false
	}

	// Verify that the base64 key data length is within expected range for this algorithm
	// This catches keys that are too short (incomplete) or too long (malformed)
	if len(keyData) < algorithmSpec.minLength || len(keyData) > algorithmSpec.maxLength {
		return false
	}

	// Ensure the key data portion contains only valid base64 characters
	if !isValidBase64(keyData) {
		return false
	}

	// Try to decode the base64 to ensure it's valid and check internal structure
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return false // If decoding fails, the base64 is malformed
	}

	// Basic sanity check on decoded length
	if len(decoded) < 20 {
		return false
	}

	// Validate the internal binary structure of the SSH key
	// This ensures the key data is properly formatted according to SSH wire format
	return validateKeyStructure(algorithm, decoded)
}

// isValidBase64 validates that a string contains only valid base64 characters.
// Base64 encoding uses A-Z, a-z, 0-9, +, / for data, and = for padding.
//
// This function uses a compiled regex for efficient validation of base64 format.
// Returns true if the string is valid base64, false otherwise.
func isValidBase64(s string) bool {
	// Base64 character set validation pattern:
	// ^[A-Za-z0-9+/]* : Any number of base64 data characters
	// ={0,2}$ : Followed by 0, 1, or 2 padding characters at the end
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

// validateKeyStructure performs deep validation of the SSH key's internal binary structure.
// SSH public keys follow a specific wire format where the algorithm name is embedded
// within the key data itself, providing an additional layer of validation.
//
// The SSH wire format structure:
// - First 4 bytes: Length of algorithm name (big-endian uint32)
// - Next N bytes: Algorithm name as ASCII string
// - Remaining bytes: Algorithm-specific key material
//
// This function verifies that:
// 1. The decoded data has sufficient length for the header
// 2. The embedded algorithm name length is reasonable
// 3. The embedded algorithm matches the prefix algorithm
func validateKeyStructure(algorithm string, decoded []byte) bool {
	// SSH keys must have at least 4 bytes for the algorithm name length field
	if len(decoded) < 4 {
		return false
	}

	// SSH wire format uses big-endian encoding for the length field
	// Read 4 bytes and convert to integer: [0]<<24 | [1]<<16 | [2]<<8 | [3]
	algNameLen := int(decoded[0])<<24 | int(decoded[1])<<16 | int(decoded[2])<<8 | int(decoded[3])

	// Sanity checks to prevent buffer overflows and catch malformed data:
	// - Algorithm name should be at least 7 characters
	// - Should not exceed 50 characters
	// - Total length must not exceed the decoded data length
	if algNameLen < 7 || algNameLen > 50 || algNameLen+4 > len(decoded) {
		return false
	}

	// Extract the algorithm name from the decoded binary data
	// Skip the first 4 bytes (length field) and read algNameLen bytes
	embeddedAlgorithm := string(decoded[4 : 4+algNameLen])

	// The algorithm name embedded in the key data must exactly match
	// the algorithm specified in the key prefix. This prevents:
	// - Algorithm substitution attacks
	// - Malformed keys with inconsistent headers
	// - Accidentally corrupted key data
	return embeddedAlgorithm == algorithm
}

// IsWeakPassword checks if a password appears in a list of commonly used weak passwords.
// This function provides protection against the most obvious password choices that are
// frequently targeted in dictionary attacks and credential stuffing attacks.
//
// The weak password list includes:
// - Common dictionary words with numbers
// - Default administrative passwords
// - Predictable patterns and sequences
// - Previously compromised passwords from major data breaches
//
// Returns true if the password is considered weak, false if it passes this check.
// Note: This is just one layer of password validation; complexity checks are separate.
func IsWeakPassword(password string) bool {
	weakPasswords := []string{
		"password", "12345678", "qwerty12", "admin123", "12345678",
		"password123", "admin123", "letmein12", "welcome1",
		"monkey12", "dragon12", "1234567890", "qwertyuiop",
	}

	// Convert input to lowercase to catch variations like "Password123", "PASSWORD", etc.
	// Attackers often try case variations of common passwords
	lowerPass := strings.ToLower(password)
	// Check if the lowercased password matches any entry in our weak password database
	for _, weak := range weakPasswords {
		if lowerPass == weak {
			return true
		}
	}
	return false // Password not found in weak list (passes this check)
}

// HasPasswordComplexity evaluates password complexity by checking for character diversity.
// This function implements a balanced approach to password complexity that encourages
// strong passwords without being overly restrictive.
//
// Character categories checked:
// - Uppercase letters (A-Z):
// - Lowercase letters (a-z):
// - Digits (0-9):
// - Special characters:
//
// Requirements: Password must contain at least 3 out of 4 character categories.
// This approach is more user-friendly than requiring all 4 categories while still
// ensuring sufficient complexity for security.
//
// Returns true if the password meets complexity requirements, false otherwise.
func HasPasswordComplexity(password string) bool {
	// Track which types of characters are present in the password
	var hasUpper, hasLower, hasDigit, hasSpecial bool

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", char):
			hasSpecial = true
		}
		// Note: We don't use 'else' because we want to continue checking
		// even after finding characters from all categories
	}

	// Count how many different character categories are present
	complexity := 0
	if hasUpper {
		complexity++
	}
	if hasLower {
		complexity++
	}
	if hasDigit {
		complexity++
	}
	if hasSpecial {
		complexity++
	}

	return complexity >= 3
}
