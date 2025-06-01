/*
Main application entry point for the HTTPS backup service server.
Sets up HTTP routes, configures handlers, and starts the HTTPS server
with TLS certificates for secure communication.
*/

package main

import (
	"fmt"
	"https_server/config"
	"https_server/handlers"
	"log"
	"net/http"
)

// main sets up the server configuration and starts listening for HTTPS requests
func main() {
	// LOAD APPLICATION CONFIGURATION
	// config.GetConfig() returns a configuration object with all server settings
	// This includes IP addresses, ports, and certificate paths
	cfg := config.GetConfig()

	// LOG CONFIGURATION INFORMATION
	fmt.Printf("Security-Switch IP: %s\n", cfg.SecuritySwitchIP)
	fmt.Println("mTLS certificates configured")

	// STEP 3: SET UP HTTP ROUTES
	// http.HandleFunc() maps URL patterns to handler functions
	// When a client makes a request to these URLs, the corresponding function is called
	// Route for user registration handles POST requests to create new user accounts
	// handlers.RegisterHandler processes the registration logic
	http.HandleFunc("/api/register", handlers.RegisterHandler)
	http.HandleFunc("/api/health", handlers.HealthHandler)

	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/register (User registration)")
	fmt.Println("\tGET  /api/health (Check server status)")
	fmt.Println("Use the command below to register a new user:")
	// WARNING: --insecure is used here because we're using self-signed certificates
	fmt.Println("\tcurl https://IP TAILSCALE DEL CONTAINER:8443/api/register --insecure --header \"Content-Type: application/json\" --request \"POST\" --data '{\"email\":\"your.email@example.com\",\"password\":\"password123\",\"ssh_public_key\":\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... your-ssh-key\"}'")
	fmt.Println("To stop the server press Ctrl+C")

	// START THE HTTPS SERVER
	// http.ListenAndServeTLS() starts an HTTPS server with TLS encryption
	// It listen on all network interfaces on port 8443
	// Actually, since only one Tailscale IP in the private network can reach
	// other Tailscale IPs, this server can only be reached by clients registered
	// to the private network.
	// the parameter nil = use the default HTTP request multiplexer (router)
	//   - This means use the routes registered with http.HandleFunc()
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", "../certificates/entry-hub/server.crt", "../certificates/entry-hub/server.key", nil))
}
