package crypto

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Function to generate a random salt.
// NOTE: _ is used to ignore the first parameter returned by the rand.Read function.
func GenerateSalt() (string, error) {
	salt := make([]byte, 16)  // Create a 16byte empty slice
	_, err := rand.Read(salt) // fills the passed slice with cryptographically secure random bytes.
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", salt), nil //Converts the 16 random bytes to a hexadecimal string to represent binary data in a readable way
}

// Function to hash password with Argon2
func HashPassword(password, salt string) string {
	saltBytes := []byte(salt)                                            // Converts the salt to a byte array because argon2.IDKey requires it
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 32*1024, 4, 32) //hash password with Argon2id using 1 iteration, 32bytes of RAM, 4 CPU threads. Produces a 32byte hash.
	return fmt.Sprintf("%x", hash)                                       // Converts the hash byte array into a readable hexadecimal string
}
