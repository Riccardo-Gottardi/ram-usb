package clients

/*
mTLS client for communicating with the Security-Switch server.
Handles secure communication with the remote registration service
using mutual TLS authentication for enhanced security.
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

// SecuritySwitchClient handles communication with the Security-Switch server
type SecuritySwitchClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewSecuritySwitchClient creates a new client for Security-Switch communication
func NewSecuritySwitchClient(securitySwitchIP string, clientCertFile, clientKeyFile, caCertFile string) (*SecuritySwitchClient, error) {
	// Load client certificate and key for mTLS
	clientCert, err := tls.LoadX509KeyPair(clientCertFile, clientKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %v", err)
	}

	// Configure TLS with client certificate
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		// Note: You might need to add CA certificate validation here depending on your setup
		InsecureSkipVerify: false, // Set to false in production with proper CA
	}

	// Create HTTP client with mTLS configuration
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
		Timeout: 30 * time.Second,
	}

	return &SecuritySwitchClient{
		baseURL:    fmt.Sprintf("https://%s", securitySwitchIP),
		httpClient: client,
	}, nil
}

// ForwardRegistration forwards the registration request to Security-Switch
func (c *SecuritySwitchClient) ForwardRegistration(req types.RegisterRequest) (*types.Response, error) {
	// Convert request to JSON
	jsonData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP request to Security-Switch
	httpReq, err := http.NewRequest("POST", c.baseURL+"/api/register", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	// Send request to Security-Switch
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send request to Security-Switch: %v", err)
	}
	defer resp.Body.Close()

	// Parse response from Security-Switch
	var switchResponse types.Response
	if err := json.NewDecoder(resp.Body).Decode(&switchResponse); err != nil {
		return nil, fmt.Errorf("failed to decode Security-Switch response: %v", err)
	}

	return &switchResponse, nil
}
