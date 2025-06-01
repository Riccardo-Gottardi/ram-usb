package utils

/*
Input validation utilities specific to Security-Switch.
Implements additional security validation functions beyond
what Entry-Hub provides.
*/

import (
	"strings"
)

// IsWeakPassword checks if a password is in the list of common weak passwords
func IsWeakPassword(password string) bool {
	weakPasswords := []string{
		"password", "12345678", "qwerty12", "admin123", "12345678",
		"password123", "admin123", "letmein12", "welcome1",
		"monkey12", "dragon12", "1234567890", "qwertyuiop",
	}

	lowerPass := strings.ToLower(password)
	for _, weak := range weakPasswords {
		if lowerPass == weak {
			return true
		}
	}
	return false
}

// HasPasswordComplexity checks if password meets complexity requirements
func HasPasswordComplexity(password string) bool {
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
	}

	// Require at least 3 out of 4 character types
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
