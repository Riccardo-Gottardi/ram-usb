package main

import (
	"fmt"
	"log"
	"net/http"
)

// Registration request structure
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	SSHPubKey string `json:"ssh_public_key"` // SSH public key field
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
	SSHPubKey    string `json:"ssh_public_key"` // SSH public key field
}

// Response structure
type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func main() {
	// Configure the routes
	http.HandleFunc("/api/register", registerHandler) // Tells the default handler to map the address /api/register to the registerHandler function
	http.HandleFunc("/api/health", healthHandler)     //Tells the default handler to map the address /api/health to the healthHandler function

	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/register (User registration)")
	fmt.Println("\tGET  /api/health (Check server status)")
	fmt.Println("Use the command below to register a new user:")
	fmt.Println("\tcurl https://IP TAILSCALE DEL CONTAINER:8443/api/register --insecure --header \"Content-Type: application/json\" --request \"POST\" --data '{\"email\":\"your.email@example.com\",\"password\":\"password123\",\"ssh_public_key\":\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... your-ssh-key\"}'")
	fmt.Println("To stop the server press Ctrl+C")

	// Start HTTPS server.
	// log.fatal, if http.ListenAndServeTLS returns an error, print the error to the terminal and stop the server.
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", "../priv/server.crt", "../priv/server.key", nil)) // The nil parameter indicates that the default handler will handle the request. The handler will handle it as told above.
}
