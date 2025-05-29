package utils

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// Function to validate the email using a regular expression.
func IsValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

// Function to validate SSH public key format with comprehensive checks
func IsValidSSHKey(sshKey string) bool {
	// Remove leading/trailing whitespace
	sshKey = strings.TrimSpace(sshKey)

	// Check if the key is not empty and has a reasonable minimum length
	if len(sshKey) < 80 {
		return false
	}

	// Split the key into parts (format: "algorithm base64-key [comment]")
	parts := strings.Fields(sshKey)
	if len(parts) < 2 {
		return false
	}

	algorithm := parts[0]
	keyData := parts[1]

	// Validate supported algorithms and their expected key lengths
	supportedAlgorithms := map[string]struct {
		minLength int
		maxLength int
	}{
		"ssh-rsa":                            {300, 800}, // RSA keys (2048-4096 bits typical)
		"ssh-ed25519":                        {60, 80},   // Ed25519 keys (fixed 256-bit)
		"ecdsa-sha2-nistp256":                {100, 150}, // ECDSA P-256
		"ecdsa-sha2-nistp384":                {120, 170}, // ECDSA P-384
		"ecdsa-sha2-nistp521":                {140, 200}, // ECDSA P-521
		"sk-ssh-ed25519@openssh.com":         {80, 120},  // Security key Ed25519
		"sk-ecdsa-sha2-nistp256@openssh.com": {120, 180}, // Security key ECDSA
	}

	algorithmSpec, isSupported := supportedAlgorithms[algorithm]
	if !isSupported {
		return false
	}

	// Check if key data length is within expected range for the algorithm
	if len(keyData) < algorithmSpec.minLength || len(keyData) > algorithmSpec.maxLength {
		return false
	}

	// Validate that the key data is valid base64
	if !isValidBase64(keyData) {
		return false
	}

	// Additional validation: try to decode the base64 to ensure it's valid
	decoded, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return false
	}

	// Basic sanity check on decoded length
	if len(decoded) < 20 {
		return false
	}

	// For extra security, validate the internal structure for common key types
	return validateKeyStructure(algorithm, decoded)
}

// Function to validate base64 format
func isValidBase64(s string) bool {
	// Base64 should only contain A-Z, a-z, 0-9, +, /, and = for padding
	base64Pattern := regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
	return base64Pattern.MatchString(s)
}

// Function to validate internal key structure
func validateKeyStructure(algorithm string, decoded []byte) bool {
	// For SSH keys, the decoded data starts with the algorithm name length and name
	if len(decoded) < 4 {
		return false
	}

	// Read the length of the algorithm name (first 4 bytes, big endian)
	algNameLen := int(decoded[0])<<24 | int(decoded[1])<<16 | int(decoded[2])<<8 | int(decoded[3])

	// Sanity check: algorithm name length should be reasonable
	if algNameLen < 7 || algNameLen > 50 || algNameLen+4 > len(decoded) {
		return false
	}

	// Extract the algorithm name from the decoded data
	embeddedAlgorithm := string(decoded[4 : 4+algNameLen])

	// The embedded algorithm should match the one in the key prefix
	return embeddedAlgorithm == algorithm
}
