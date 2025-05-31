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
	"encoding/json"
	"fmt"
	"https_server/types"
	"net/http"
	"time"
)

// EntryHubClient handles communication with the Security-Switch server (Entry-Hub -> Security-Switch)
type EntryHubClient struct {
	baseURL    string       //Security-Switch URL
	httpClient *http.Client // pointer to the struct of the GO standard library http
}

// NewEntryHubClient initializes a new HTTP client configured for secure (mTLS) communication with the Security-Switch.
// Loads the client's certificate and private key from the specified files, and inserts them into the TLS configuration.
// Creates a TLS configuration that enables mutual authentication between client and server.
// Instantiates an http.Client that uses this TLS configuration to establish secure connections.
// Constructs and returns an EntryHubClient object, which includes the Security-Switch URL and the mTLS HTTP client.
func NewEntryHubClient(securitySwitchIP string, clientCertFile, clientKeyFile, caCertFile string) (*EntryHubClient, error) {
	// Load client certificate and key for mTLS and store it in clientCert
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Create a new configuration TLS with client certificate using the GO struct tls.config
	tlsConfig := &tls.Config{ // Return a pointer to the struct created
		Certificates: []tls.Certificate{clientCert},
		// Note: We might need to add CA certificate validation here.
		InsecureSkipVerify: false, // Set to false in production with proper CA
	}

	// Create HTTP client with mTLS configuration
	client := &http.Client{ // client contains a pointer to a struct of type *http.Client
		Transport: &http.Transport{ // Customize http.client to use TLS
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second, // After 30 seconds, the connection ends.
	}

	// Creates an instance of the EntryHubClient struct
	return &EntryHubClient{ // Creates a new EntryHubClient object and returns its pointer
		baseURL:    fmt.Sprintf("https://%s", securitySwitchIP),
		httpClient: client, // Use the http client created earlier, which uses TLS
	}, nil // No errors to return here
}

// ForwardRegistration sends a registration request to the Security-Switch server using HTTPS with mTLS.
// Converts the request (struct RegisterRequest) to JSON format.
// Creates an HTTP POST request to the Security-Switch /api/register endpoint.
// Sends the request via an HTTP client configured with TLS mutual authentication.
// Reads the JSON response received from the Security-Switch and decodes it into a struct Response.
// If any of these steps fail, returns an error.
func (c *EntryHubClient) ForwardRegistration(req types.RegisterRequest) (*types.Response, error) {
	// Converts the struct type.RegisterRequest to a json
	// c is the EntryHubClient instance.
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP POST request to send to Security-Switch using the GO standard function http.NewRequest
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/register", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Inform that the request format is a json
	httpReq.Header.Set("Content-Type", "application/json")

	// Send request to Security-Switch
	// The Do() method takes the request httpReq and sends it to the Security-Switch.
	// Do() returns resp: a pointer to http.Response, which is the response received from the server.
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Security-Switch: %v", err)
	}
	defer resp.Body.Close() // Ensures that the HTTP response is closed at the end of the function, even if there are errors or early returns later.

	// Parse response from Security-Switch
	var switchResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&switchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Security-Switch response: %v", err)
	}

	return &switchResponse, nil
}
