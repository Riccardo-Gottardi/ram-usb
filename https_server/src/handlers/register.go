package handlers

import (
	"encoding/json"
	"fmt"
	"https_server/crypto"
	"https_server/storage"
	"https_server/types"
	"https_server/utils"
	"log"
	"net/http"
)

// User registration handler
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Request: \n\tfrom:\t%s \n\tmethod:\t%s\n", r.RemoteAddr, r.Method)

	const usersFile = "users.json"

	// Set Content-Type to JSON
	w.Header().Set("Content-Type", "application/json") // Tells the client that the response will be a json

	if !utils.EnforcePOST(w, r) { // Accepts POST requests only.
		return
	}

	// Read request body
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return
	}

	// Parsing JSON and exit if the JSON is invalid
	var req types.RegisterRequest // Create a variable as a struct RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return
	}

	// Input Validation. If the email or the password is empty, it returns an error
	if req.Email == "" || req.Password == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Email and password are required.",
		})
		return
	}

	// Check if the email is valid by calling the isValidEmail function. If it's not, it returns error 400
	if !utils.IsValidEmail(req.Email) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Invalid email format.",
		})
		return
	}

	// Check if the password is valid. If it's not, it returns error 400
	// THIS SHOULD BE MODIFIED TO IMPROVE THE SCALABILITY OF THE CODE. IT SHOULD CALL A FUNCTION THAT CHECKS IF THE PASSWORD IS SUITABLE
	if len(req.Password) < 6 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Password must be at least 6 characters.",
		})
		return
	}

	// Check if the SSH public key is valid. If it's not, it returns error 400
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Invalid SSH public key format.",
		})
		return
	}

	// Load existing users. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	users, err := storage.LoadUsers(usersFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Error loading users.",
		})
		return
	}

	// Check if the user already exists. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	if storage.UserExists(users, req.Email) {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "User already registered with this email.",
		})
		return
	}

	// Generate a random salt
	salt, err := crypto.GenerateSalt() // Call the generateSalt function and assign the value to the salt variable
	if err != nil {                    // If there was an error it returns error 500
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Error generating salt.",
		})
		return
	}

	// Generate password hash with Argon2id
	passwordHash := crypto.HashPassword(req.Password, salt)

	// Create new user. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	newUser := types.User{
		Email:        req.Email,
		PasswordHash: passwordHash,
		Salt:         salt,
		SSHPubKey:    req.SSHPubKey,
	}

	// Add the user to the json and save. THIS FUNCTION WILL BE REPLACED INTRODUCING POSTGRESQL
	users = append(users, newUser)
	err = storage.SaveUsers(users, usersFile)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(types.Response{
			Success: false,
			Message: "Error saving user.",
		})
		return
	}

	// Successful response.
	w.WriteHeader(http.StatusCreated) // Responds with 201. User created
	json.NewEncoder(w).Encode(types.Response{
		Success: true,
		Message: "User successfully registered!",
	})

	log.Printf("New registered user: %s", req.Email) // Writes to the server terminal
}
