/*
Main application entry point for the Security-Switch mTLS server.
Configures mTLS authentication, sets up routes, and starts the secure
server that acts as a gateway between Entry-Hub and Database-Vault.
*/

package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"security_switch/config"
	"security_switch/handlers"
	"security_switch/middleware"
)

func main() {
	// LOAD CONFIGURATION
	// GetConfig() returns an object containing all server settings
	// cfg is a variable that holds this configuration
	cfg := config.GetConfig()

	// Log configuration (without sensitive data)
	fmt.Printf("Security-Switch starting on port %s\n", cfg.ServerPort)
	fmt.Printf("Database-Vault endpoint: %s\n", cfg.DatabaseVaultIP)
	fmt.Println("mTLS authentication enabled")

	// LOAD THE CA CERTIFICATE
	// The CA is the authority that signed all certificates in our system
	// os.ReadFile() reads the entire file and returns its content as a byte array
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	// CREATE THE CA CERTIFICATE POOL
	// A pool is a collection of certificates considered trusted
	// x509.NewCertPool() creates a new empty pool
	caCertPool := x509.NewCertPool()
	// AppendCertsFromPEM() adds the CA certificate to the pool
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	// LOAD THE SERVER'S CERTIFICATE AND PRIVATE KEY
	// tls.LoadX509KeyPair() loads both and combines them into a usable structure
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// Configure TLS with mutual authentication
	// &tls.Config{} creates a pointer to a new TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},  // List of certificates the server presents to clients
		ClientAuth:   tls.RequireAndVerifyClientCert, // ClientAuth: specifies that we require and verify the client's certificate
		ClientCAs:    caCertPool,                     // // Only clients with certificates signed by this CA will be accepted
		MinVersion:   tls.VersionTLS13,               // Enforce TLS 1.3 for better security
	}

	// CREATE THE HTTP ROUTER
	// A router (multiplexer) maps URLs to functions that handle requests
	mux := http.NewServeMux()

	// REGISTER ROUTES WITH mTLS MIDDLEWARE
	// HandleFunc() associates a URL path with a handler function
	// middleware.VerifyMTLS() is a function that "wraps" the original handler
	// It first verifies the client's certificate, then calls the handler if everything is ok

	// Apply mTLS verification middleware to all routes
	mux.HandleFunc("/api/register", middleware.VerifyMTLS(handlers.RegisterHandler))
	mux.HandleFunc("/api/health", middleware.VerifyMTLS(handlers.HealthHandler))

	// Create HTTPS server with mTLS configuration
	// WARNING: Now we listen on all network.
	// WARNING: Then we will change it to listen only from those IPs:
	// WARNING: Entry-Hub, Database-Vault, Storage-Service and OPA
	server := &http.Server{
		Addr:      "0.0.0.0:" + cfg.ServerPort, // Listen on all network interfaces.
		Handler:   mux,                         // The router that will handle requests
		TLSConfig: tlsConfig,
	}

	fmt.Println("Available endpoints:")
	fmt.Println("\tPOST /api/register (Forward user registration to Database-Vault)")
	fmt.Println("\tGET  /api/health (Check Security-Switch status)")
	fmt.Println("Security-Switch ready to accept mTLS connections")
	fmt.Println("To stop the server press Ctrl+C")

	// Start the mTLS server
	log.Fatal(server.ListenAndServeTLS("", "")) // Empty strings because certificates are already loaded in TLSConfig
}
