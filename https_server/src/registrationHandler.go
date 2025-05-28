package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
)

// User registration handler
func registerHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request: \n\tfrom:\t%s \n\tmethod:\t%s\n", r.RemoteAddr, r.Method)

	const usersFile = "users.json"

	// Set Content-Type to JSON
	w.Header().Set("Content-Type", "application/json") // Tells the client that the response will be a json

	if !enforcePOST(w, r) { // Accepts POST requests only.
		return
	}

	// Read request body
	body, ok := readRequestBody(w, r)
	if !ok {
		return
	}

	// Parsing JSON and exit if the JSON is invalid
	var req RegisterRequest // Create a variable as a struct RegisterRequest
	if !parseJSONBody(body, &req, w) {
		return
	}

	// Input Validation. If the email or the password is empty, it returns an error
	if req.Email == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Email and password are required.",
		})
		return
	}

	// Check if the email is valid by calling the isValidEmail function. If it's not, it returns error 400
	if !isValidEmail(req.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid email format.",
		})
		return
	}

	// Check if the password is valid. If it's not, it returns error 400
	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Password must be at least 6 characters.",
		})
		return
	}

	// Check if the SSH public key is valid. If it's not, it returns error 400
	if !isValidSSHKey(req.SSHPubKey) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid SSH public key format.",
		})
		return
	}

	// Load existing users. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	users, err := loadUsers(usersFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error loading users.",
		})
		return
	}

	// Check if the user already exists. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	if userExists(users, req.Email) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "User already registered with this email.",
		})
		return
	}

	// Generate a random salt
	salt, err := generateSalt() // Call the generateSalt function and assign the value to the salt variable
	if err != nil {             // If there was an error it returns error 500
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error generating salt.",
		})
		return
	}

	// Generate password hash with Argon2id
	passwordHash := hashPassword(req.Password, salt)

	// Create new user. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	newUser := User{
		Email:        req.Email,
		PasswordHash: passwordHash,
		Salt:         salt,
		SSHPubKey:    req.SSHPubKey,
	}

	// Add the user to the list and save. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	users = append(users, newUser)
	err = saveUsers(users, usersFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Error saving user.",
		})
		return
	}

	// Successful response.
	w.WriteHeader(http.StatusCreated) // Responds with 201. User created
	json.NewEncoder(w).Encode(Response{
		Success: true,
		Message: "User successfully registered!",
	})

	log.Printf("New registered user: %s", req.Email) // Writes to the server terminal
}

// Function to validate the email using a regular expression.
func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(pattern)
	return regex.MatchString(email)
}

// Function to validate SSH public key format with comprehensive checks
func isValidSSHKey(sshKey string) bool {
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

// Function to generate a random salt.
// NOTE: _ is used to ignore the first parameter returned by the rand.Read function.
func generateSalt() (string, error) {
	salt := make([]byte, 16)  // Create a 16byte empty slice
	_, err := rand.Read(salt) // fills the passed slice with cryptographically secure random bytes.
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", salt), nil //Converts the 16 random bytes to a hexadecimal string to represent binary data in a readable way
}

// Function to hash password with Argon2
func hashPassword(password, salt string) string {
	saltBytes := []byte(salt)                                            // Converts the salt to a byte array because argon2.IDKey requires it
	hash := argon2.IDKey([]byte(password), saltBytes, 1, 32*1024, 4, 32) //hash password with Argon2id using 1 iteration, 32bytes of RAM, 4 CPU threads. Produces a 32byte hash.
	return fmt.Sprintf("%x", hash)                                       // Converts the hash byte array into a readable hexadecimal string
}

// Function to load users from JSON file. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func loadUsers(usersFile string) ([]User, error) {
	var users []User

	// If the file does not exist, create an empty one with a JSON slice "[]"
	if _, err := os.Stat(usersFile); os.IsNotExist(err) {
		err := os.WriteFile(usersFile, []byte("[]"), 0644)
		if err != nil {
			return nil, err
		}
		return users, nil
	}

	file, err := os.Open(usersFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&users)
	return users, err
}

// Function to save users in JSON file. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func saveUsers(users []User, usersFile string) error {
	file, err := os.Create(usersFile)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(users)
}

// Function to check if a user already exists. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
func userExists(users []User, email string) bool {
	for _, user := range users {
		if user.Email == email {
			return true
		}
	}
	return false
}

// Ensures only POST requests are accepted.
// If the request method is not POST, it responds with HTTP 405 (Method Not Allowed).
func enforcePOST(w http.ResponseWriter, r *http.Request) bool {
	// Accepts POST requests only.
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed) // Return HTTP 405 Method Not Allowed
		json.NewEncoder(w).Encode(Response{        // Send a JSON response with an error message
			Success: false,
			Message: "Method not allowed. Use POST.",
		})
		return false
	}
	return true
}

// Reads and validates the request body
func readRequestBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(r.Body) // Save the content of the request in the body variable
	if err != nil {                 // If reading fails
		w.WriteHeader(http.StatusBadRequest) // Responds to client with HTTP code 400
		json.NewEncoder(w).Encode(Response{  // Create a json response to send to the server
			Success: false,
			Message: "Error reading request.",
		})
		return nil, false
	}
	return body, true
}

// Parse the request body into the given struct
func parseJSONBody(body []byte, target interface{}, w http.ResponseWriter) bool {
	// Attempt to unmarshal the JSON into the target struct
	if err := json.Unmarshal(body, target); err != nil {
		// Responds to client with HTTP code 400 if JSON is badly formatted
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(Response{
			Success: false,
			Message: "Invalid JSON.",
		})
		return false
	}
	return true
}
