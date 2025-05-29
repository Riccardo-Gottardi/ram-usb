/*
Main application entry point for the HTTPS backup service server.
Sets up HTTP routes, configures handlers, and starts the HTTPS server
with TLS certificates for secure communication.
*/

package main

import (
	"fmt"
	"https_server/handlers"
	"log"
	"net/http"
)

func main() {
	// Configure the routes
	http.HandleFunc("/api/register", handlers.RegisterHandler)
	http.HandleFunc("/api/health", handlers.HealthHandler)

	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/register (User registration)")
	fmt.Println("\tGET  /api/health (Check server status)")
	fmt.Println("Use the command below to register a new user:")
	fmt.Println("\tcurl https://IP TAILSCALE DEL CONTAINER:8443/api/register --insecure --header \"Content-Type: application/json\" --request \"POST\" --data '{\"email\":\"your.email@example.com\",\"password\":\"password123\",\"ssh_public_key\":\"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... your-ssh-key\"}'")
	fmt.Println("To stop the server press Ctrl+C")

	// Start the https server. nil indicates to use http.DefaultServeMux (Go's default multiplexer) as the HTTP request handler. This will follow the directions given above
	log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", "../priv/server.crt", "../priv/server.key", nil))
}
