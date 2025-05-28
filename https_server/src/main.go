package main

import (
	"fmt"
	"log"
	"net/http"
)

// Registration request structure used for the json parsing
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Structure to represent a user
type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	Salt         string `json:"salt"`
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
	fmt.Println("\tcurl https://IP TAILSCALE DEL CONTAINER:8443/api/register --insecure --header \"Content-Type: application/json\" --request \"POST\" --data '{\"email\":\"your.email@example.com\",\"password\":\"password123\"}'")
	fmt.Println("To stop the server press Ctrl+C")

	// Start HTTPS server.
	// log.fatal, if http.ListenAndServeTLS returns an error, print the error to the terminal and stop the server.
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", "../priv/server.crt", "../priv/server.key", nil)) // The nil parameter indicates that the default handler will handle the request. The handler will handle it as told above.
}
