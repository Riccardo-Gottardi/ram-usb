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
	// Load configuration
	cfg := config.GetConfig()

	// Log configuration (without sensitive data)
	fmt.Printf("Security-Switch starting on port %s\n", cfg.ServerPort)
	fmt.Printf("Database-Vault endpoint: %s\n", cfg.DatabaseVaultIP)
	fmt.Println("mTLS authentication enabled")

	// Load CA certificate for client verification
	caCert, err := os.ReadFile(cfg.CACertFile)
	if err != nil {
		log.Fatalf("Failed to read CA certificate: %v", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		log.Fatal("Failed to parse CA certificate")
	}

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		log.Fatalf("Failed to load server certificate: %v", err)
	}

	// Configure TLS with mutual authentication
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require and verify client certificate
		ClientCAs:    caCertPool,
		MinVersion:   tls.VersionTLS13, // Enforce TLS 1.3 for better security
	}

	// Create router with mTLS middleware
	mux := http.NewServeMux()

	// Apply mTLS verification middleware to all routes
	mux.HandleFunc("/api/register", middleware.VerifyMTLS(handlers.RegisterHandler))
	mux.HandleFunc("/api/health", middleware.VerifyMTLS(handlers.HealthHandler))

	// Create HTTPS server with mTLS configuration
	server := &http.Server{
		Addr:      "0.0.0.0:" + cfg.ServerPort,
		Handler:   mux,
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
