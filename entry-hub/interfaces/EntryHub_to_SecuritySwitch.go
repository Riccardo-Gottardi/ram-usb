package interfaces

/*
Entry-Hub -> Security-Switch
mTLS client for communicating with the Security-Switch server.
Handles secure communication with the remote registration service
using mutual TLS authentication.
*/

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"https_server/types"
	"net/http"
	"os"
	"time"
)

// EntryHubClient handles communication with the Security-Switch server (Entry-Hub -> Security-Switch)
type EntryHubClient struct {
	baseURL    string       //Security-Switch URL
	httpClient *http.Client // pointer to the struct of the GO standard library http
}

// NewEntryHubClient is a CONSTRUCTOR FUNCTION that creates and configures a new EntryHubClient
// This function implements mutual TLS (mTLS) authentication, where both client and server verify each other's certificates.
func NewEntryHubClient(securitySwitchIP string, clientCertFile, clientKeyFile, caCertFile string) (*EntryHubClient, error) {
	// Load the client's certificate and private key for mTLS authentication
	// tls.LoadX509KeyPair() reads both the certificate (.crt) and private key (.key) files
	// and combines them into a single tls.Certificate structure that Go can use for authentication
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Load the Certificate Authority (CA) certificate
	// The CA certificate is used to verify that the Security-Switch's certificate is legitimate
	// os.ReadFile() reads the entire CA certificate file into memory as a byte slice
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Create a certificate pool and add the CA certificate to it
	// A certificate pool is Go's way of managing trusted certificates
	// x509.NewCertPool() creates an empty pool of trusted certificates
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// AppendCertsFromPEM() parses the CA certificate (in PEM format) and adds it to the pool
	// This tells our client "trust any certificate signed by this CA"
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	// Configure TLS with mutual authentication
	// &tls.Config{} creates a POINTER to a new tls.Config struct
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert}, // Our client certificate
		RootCAs:            caCertPool,                    // CA pool to verify the server
		ServerName:         "security-switch",             // Must match the CN of the certificate
		InsecureSkipVerify: false,                         // Set to false in production with proper CA
		MinVersion:         tls.VersionTLS13,
	}

	// Create a custom HTTP client with the TLS configuration
	client := &http.Client{
		Transport: &http.Transport{ // Customize http.client to use TLS
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second, // After 30 seconds, the connection ends.
	}

	// Create and return the EntryHubClient instance
	return &EntryHubClient{
		baseURL:    fmt.Sprintf("https://%s", securitySwitchIP),
		httpClient: client, // Use the http client created earlier, which uses TLS
	}, nil
}

// ForwardRegistration is a METHOD of the EntryHubClient struct
// It sends a registration request to the Security-Switch server using HTTPS with mTLS.
//
// Converts the request (struct RegisterRequest) to JSON format.
// Creates an HTTP POST request to the Security-Switch /api/register endpoint.
// Sends the request via an HTTP client configured with TLS mutual authentication.
// Reads the JSON response received from the Security-Switch and decodes it into a struct Response.
// If any of these steps fail, returns an error.
func (c *EntryHubClient) ForwardRegistration(req types.RegisterRequest) (*types.Response, error) {
	// Converts the struct type.RegisterRequest to a json
	// c is the name we give to the instance inside the method (like "this" in Java)
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP POST request to send to Security-Switch using the GO standard function http.NewRequest
	// c.baseURL + "/api/register" concatenates strings to form the complete URL
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/register", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Inform the server that the request format is a json
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request to Security-Switch
	// The Do() method takes the request httpReq and sends it to the Security-Switch.
	// Do() returns resp: a pointer to http.Response, which is the response received from the server.
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Security-Switch: %v", err)
	}
	defer resp.Body.Close() // Ensures that the HTTP response is closed at the end of the function

	// Decode the JSON response
	// Decode() reads the JSON and puts it into the switchResponse struct
	// &switchResponse passes the address of the variable (necessary to modify it)
	var switchResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&switchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Security-Switch response: %v", err)
	}

	return &switchResponse, nil
}
