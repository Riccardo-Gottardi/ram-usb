package interfaces

/*
Security-Switch -> Database-Vault
mTLS client for communicating with the Database-Vault service.
Handles secure communication with the Database-Vault service
for storing user credentials using mutual TLS authentication.
*/

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"security_switch/types"
	"time"
)

// DatabaseVaultClient handles communication with the Database-Vault server (Security-Switch -> Database-Vault)
type DatabaseVaultClient struct {
	baseURL    string       // Database-Vault URL
	httpClient *http.Client // pointer to the struct of the GO standard library http
}

// NewDatabaseVaultClient is a CONSTRUCTOR FUNCTION that creates and configures a new DatabaseVaultClient
// This function implements mutual TLS (mTLS) authentication, where both Security-Switch and Database-Vault verify each other's certificates.
// It follows the same pattern as NewEntryHubClient but configures the client to connect to Database-Vault instead of Security-Switch.
func NewDatabaseVaultClient(databaseVaultIP string, clientCertFile, clientKeyFile, caCertFile string) (*DatabaseVaultClient, error) {
	// Load the client's certificate and private key for mTLS authentication
	// tls.LoadX509KeyPair() reads both the certificate (.crt) and private key (.key) files
	// and combines them into a single tls.Certificate structure that Go can use for authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Load the Certificate Authority (CA) certificate
	// The CA certificate is used to verify that the Database-Vault's certificate is legitimate
	// os.ReadFile() reads the entire CA certificate file into memory as a byte slice
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Create a certificate pool and add the CA certificate to it
	// A certificate pool is Go's way of managing trusted certificates
	// x509.NewCertPool() creates an empty pool of trusted certificates
	caCertPool := x509.NewCertPool()

	// AppendCertsFromPEM() parses the CA certificate (in PEM format) and adds it to the pool
	// This tells our client "trust any certificate signed by this CA"
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Configure TLS with mutual authentication
	// &tls.Config{} creates a POINTER to a new tls.Config struct
	// This configuration ensures that both client and server authenticate each other
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert}, // Our client certificate (Security-Switch's certificate)
		RootCAs:            caCertPool,                    // CA pool to verify the Database-Vault server
		ServerName:         "database-vault",              // Must match the CN of the Database-Vault certificate
		InsecureSkipVerify: false,                         // Always verify certificates in production
		MinVersion:         tls.VersionTLS13,              // Enforce TLS 1.3 for maximum security
	}

	// Create a custom HTTP client with the TLS configuration
	// This client will use mTLS for all requests to Database-Vault
	client := &http.Client{
		Transport: &http.Transport{ // Customize http.client to use TLS
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second, // After 30 seconds, the connection ends.
	}

	// Create and return the DatabaseVaultClient instance
	return &DatabaseVaultClient{
		baseURL:    fmt.Sprintf("https://%s", databaseVaultIP),
		httpClient: client, // Use the http client created earlier, which uses mTLS
	}, nil
}

// StoreUserCredentials is a method of the DatabaseVaultClient struct
// It sends a registration request to the Database-Vault server using HTTPS with mTLS.
//
// This method performs the following operations:
// 1. Converts the request (struct RegisterRequest) to JSON format
// 2. Creates an HTTP POST request to the Database-Vault /api/store-user endpoint
// 3. Sends the request via an HTTP client configured with TLS mutual authentication
// 4. Reads the JSON response received from the Database-Vault and decodes it into a struct Response
// If any of these steps fail, returns an error.
func (c *DatabaseVaultClient) StoreUserCredentials(req types.RegisterRequest) (*types.Response, error) {
	// Convert the struct types.RegisterRequest to JSON format
	// c is the name we give to the instance inside the method (like "this" in Java)
	// json.Marshal() serializes the Go struct into a JSON byte array
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP POST request to send to Database-Vault using the GO standard function http.NewRequest
	// c.baseURL + "/api/store-user" concatenates strings to form the complete URL
	// bytes.NewBuffer(jsonData) creates a buffer containing the JSON data to send in the request body
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/store-user", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Inform the Database-Vault that the request content format is JSON
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request to Database-Vault
	// The Do() method takes the request httpReq and sends it to the Database-Vault server
	// Do() returns resp: a pointer to http.Response, which is the response received from the server
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Database-Vault: %v", err)
	}
	defer resp.Body.Close() // Ensures that the HTTP response body is closed at the end of the function

	// Decode the JSON response from Database-Vault
	// json.NewDecoder(resp.Body).Decode() reads the JSON from the response body
	// and converts it into the dbResponse struct
	// &dbResponse passes the address of the variable (necessary to modify it)
	var dbResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&dbResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Database-Vault response: %v", err)
	}

	// Return the response received from Database-Vault
	return &dbResponse, nil
}

// CheckHealth is a METHOD that verifies Database-Vault connectivity and availability
// This method sends a simple GET request to the Database-Vault health endpoint
// and returns true if the service is reachable and responding correctly.
//
// This is useful for:
// - Service discovery and health monitoring
// - Verifying mTLS connectivity before sending actual requests
// - Load balancer health checks
func (c *DatabaseVaultClient) CheckHealth() bool {
	// Create a simple GET request to the Database-Vault health endpoint
	// http.NewRequest() creates the request, but unlike StoreUserCredentials,
	// this request has no body (nil as the third parameter)
	httpReq, err := http.NewRequest("GET", c.baseURL+"/api/health", nil)
	if err != nil {
		// If we can't even create the request, the client is misconfigured
		return false
	}

	// Send the health check request using our mTLS-configured client
	// This will verify both network connectivity and certificate validation
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		// Network error, certificate error, or Database-Vault is unreachable
		return false
	}
	defer resp.Body.Close() // Always close the response body

	// Check if Database-Vault responded with HTTP 200 OK
	// A successful health check should return status code 200
	// Any other status code indicates a problem with the Database-Vault service
	return resp.StatusCode == http.StatusOK
}
